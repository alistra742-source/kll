/* nr_executor.c -- the executor core, running inside the Roblox client.
 *
 * This is the piece that actually runs a script. Everything before it (the
 * kernel driver, the handle-less loader) exists only to get this file into the
 * client's address space; once here, it owns the Luau state and executes.
 *
 * How it gets the state -- the method that works without guessing a global:
 *
 *   1. Several hot Luau C functions receive the lua_State* as their first
 *      argument. We detour one of them (the address comes from config, because
 *      it moves every build). Our detour runs before the original, captures the
 *      state pointer, and returns the original's result.
 *   2. From that state we make our own thread with LUA_NEWTHREAD and pop it back
 *      off, so the client's running stack is untouched.
 *   3. Scripts arrive as *compiled bytecode* over a named pipe (the app compiles
 *      with luau-compile). We call the client's own luau_load + lua_pcall on our
 *      private thread against the globals table.
 *
 * Why bytecode, not source: the client has no `loadstring` and its compiler is
 * not exposed. Compiling outside and shipping the chunk is what the surviving
 * executors do.
 *
 * Config is read from a file the app writes next to the DLL (nr_executor.cfg),
 * so offsets can be updated without rebuilding. Every address that is not
 * resolved is a clean refusal at startup, never a guess -- calling a wrong
 * address in someone's client is a crash, and crashes get reported.
 *
 * Build: payload\build_executor.bat (MSVC, x64, /MT).
 */

#include <windows.h>
#include <stdio.h>

#define NR_PIPE_PREFIX   "\\\\.\\pipe\\nr_"
#define NR_CFG_NAME      "nr_executor.cfg"
#define NR_LOG           "nr_executor.log"
#define MAX_SCRIPT       (4 * 1024 * 1024)

/* ---- Luau entry points we call through. All resolved from config. ---------- */
typedef void*   (__cdecl *fn_lua_newthread)(void* L);
typedef int     (__cdecl *fn_lua_settop)(void* L, int idx);
typedef int     (__cdecl *fn_lua_gettop)(void* L);
typedef int     (__cdecl *fn_luau_load)(void* L, const char* chunk, const char* data,
                                        size_t size, int env);
typedef int     (__cdecl *fn_lua_pcall)(void* L, int nargs, int nresults, int errfunc);

typedef struct {
    /* Absolute addresses in the loaded client. 0 means "not configured". */
    unsigned long long hook_target;   /* a hot Luau function taking L first  */
    unsigned long long lua_newthread;
    unsigned long long lua_settop;
    unsigned long long luau_load;
    unsigned long long lua_pcall;
    int hook_len;                     /* bytes to steal for the detour (>=5) */
    int settle_ms;                    /* quiet period before we touch anything */
} nr_config;

static nr_config g_cfg;
static void*     g_state = NULL;      /* captured lua_State* */
static void*     g_thread = NULL;     /* our private coroutine */
static HMODULE   g_self = NULL;
static volatile LONG g_stop = 0;

/* ---- tiny logging, since a DLL has no console ------------------------------ */
static void nr_log(const char* fmt, ...)
{
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(g_self, path, MAX_PATH);
    if (n == 0) return;
    char* slash = strrchr(path, '\\');
    if (slash) *(slash + 1) = 0;
    strncat_s(path, MAX_PATH, NR_LOG, _TRUNCATE);

    FILE* f = NULL;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

/* ---- config ---------------------------------------------------------------- */
static void nr_load_config(void)
{
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(g_self, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *(slash + 1) = 0;
    strncat_s(path, MAX_PATH, NR_CFG_NAME, _TRUNCATE);

    FILE* f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) {
        nr_log("config not found at %s -- refusing to run blind", path);
        return;
    }
    /* One key=value per line, hex for addresses. Deliberately dumb: no parser to
     * get wrong, and anything missing stays zero, which we refuse. */
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long v = 0;
        if (sscanf_s(line, "hook_target=%llx", &v) == 1)      g_cfg.hook_target = v;
        else if (sscanf_s(line, "lua_newthread=%llx", &v) == 1) g_cfg.lua_newthread = v;
        else if (sscanf_s(line, "lua_settop=%llx", &v) == 1)    g_cfg.lua_settop = v;
        else if (sscanf_s(line, "luau_load=%llx", &v) == 1)     g_cfg.luau_load = v;
        else if (sscanf_s(line, "lua_pcall=%llx", &v) == 1)     g_cfg.lua_pcall = v;
        else if (sscanf_s(line, "hook_len=%d", &g_cfg.hook_len) == 1) { }
        else if (sscanf_s(line, "settle_ms=%d", &g_cfg.settle_ms) == 1) { }
    }
    fclose(f);

    if (g_cfg.hook_len < 5) g_cfg.hook_len = 14;   /* a full detour fits */
    if (g_cfg.settle_ms <= 0) g_cfg.settle_ms = 8000;
}

/* ---- detour ---------------------------------------------------------------- */
/* A 14-byte absolute jump: ff 25 00000000 <addr64>. Overwriting 14 bytes needs
 * the target's first instructions to not be a jump destination inside the range,
 * which is why hook_len is configurable -- a branchy prologue needs a longer
 * steal. The original bytes are kept and replayed by the trampoline. */
static unsigned char g_original[32];
static void*         g_trampoline = NULL;
static void*         g_hook_addr  = NULL;

static int __cdecl nr_hook_gettop(void* L)
{
    /* Capture once. Re-hooking is pointless after we have the state, so we do
     * not -- and the client sees exactly one detour, briefly. */
    if (!g_state && L) g_state = L;
    /* Fall through to the original. */
    fn_lua_gettop original = (fn_lua_gettop)g_trampoline;
    return original ? original(L) : 0;
}

static int nr_install_hook(void)
{
    if (!g_cfg.hook_target) {
        nr_log("hook_target not configured");
        return 0;
    }
    g_hook_addr = (void*)g_cfg.hook_target;

    DWORD old = 0;
    if (!VirtualProtect(g_hook_addr, g_cfg.hook_len, PAGE_EXECUTE_READWRITE, &old)) {
        nr_log("VirtualProtect failed on hook target (%lu)", GetLastError());
        return 0;
    }
    memcpy(g_original, g_hook_addr, g_cfg.hook_len);

    /* Trampoline: original bytes, then a jump back to hook+len. */
    g_trampoline = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!g_trampoline) {
        VirtualProtect(g_hook_addr, g_cfg.hook_len, old, &old);
        return 0;
    }
    memcpy(g_trampoline, g_original, g_cfg.hook_len);
    unsigned char* t = (unsigned char*)g_trampoline + g_cfg.hook_len;
    t[0] = 0xFF; t[1] = 0x25; *(DWORD*)(t + 2) = 0;
    *(unsigned long long*)(t + 6) = (unsigned long long)g_hook_addr + g_cfg.hook_len;

    /* Hook: ff 25 00000000 <nr_hook_gettop> */
    unsigned char* h = (unsigned char*)g_hook_addr;
    h[0] = 0xFF; h[1] = 0x25; *(DWORD*)(h + 2) = 0;
    *(unsigned long long*)(h + 6) = (unsigned long long)&nr_hook_gettop;

    VirtualProtect(g_hook_addr, g_cfg.hook_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_hook_addr, g_cfg.hook_len);
    nr_log("hook installed at 0x%llx (steal %d bytes)", g_cfg.hook_target, g_cfg.hook_len);
    return 1;
}

static void nr_remove_hook(void)
{
    if (!g_hook_addr) return;
    DWORD old = 0;
    VirtualProtect(g_hook_addr, g_cfg.hook_len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_hook_addr, g_original, g_cfg.hook_len);
    VirtualProtect(g_hook_addr, g_cfg.hook_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_hook_addr, g_cfg.hook_len);
    nr_log("hook removed");
}

/* ---- execution ------------------------------------------------------------- */
static int nr_execute(const char* bytecode, size_t size, char* out, size_t out_size)
{
    if (!g_state) { snprintf(out, out_size, "no lua state captured yet"); return 0; }
    if (!g_cfg.luau_load || !g_cfg.lua_pcall) {
        snprintf(out, out_size, "luau_load/lua_pcall not configured");
        return 0;
    }

    fn_lua_newthread newthread = (fn_lua_newthread)g_cfg.lua_newthread;
    fn_lua_settop    settop    = (fn_lua_settop)g_cfg.lua_settop;
    fn_luau_load     load      = (fn_luau_load)g_cfg.luau_load;
    fn_lua_pcall     pcall     = (fn_lua_pcall)g_cfg.lua_pcall;

    /* Our own coroutine, so the client's running stack is never touched. */
    void* L = newthread ? newthread(g_state) : g_state;
    if (!L) { snprintf(out, out_size, "lua_newthread failed"); return 0; }
    g_thread = L;

    /* The chunk's environment is the main thread's globals (-1 == global table
     * index on the new thread stack after ntr pops). */
    int loaded = load(L, "@nightrelay", bytecode, size, -1);
    if (loaded != 0) {
        if (settop) settop(L, -2);
        snprintf(out, out_size, "luau_load rejected the chunk");
        return 0;
    }

    int rc = pcall(L, 0, 0, 0);
    /* Pop our thread back off the parent state so nothing is left behind. */
    if (settop && L != g_state) settop(g_state, -2);
    if (rc != 0) {
        snprintf(out, out_size, "script raised an error (pcall=%d)", rc);
        return 0;
    }
    snprintf(out, out_size, "ok");
    return 1;
}

/* ---- pipe server ----------------------------------------------------------- */
/* Length-prefixed framing: [u32 len][bytes]. A 'len' of 0 is an exit request.
 * Bounded reads -- a corrupted length must end the connection, never hang. */
static unsigned char* nr_recv(HANDLE pipe, unsigned long* out_len)
{
    unsigned long len = 0, got = 0;
    if (!ReadFile(pipe, &len, 4, &got, NULL) || got != 4) return NULL;
    if (len == 0) { *out_len = 0; return NULL; }       /* clean shutdown */
    if (len > MAX_SCRIPT) { nr_log("refused oversized payload %lu", len); return NULL; }

    unsigned char* buf = (unsigned char*)malloc(len);
    if (!buf) return NULL;
    unsigned long read = 0;
    while (read < len) {
        DWORD chunk = 0;
        if (!ReadFile(pipe, buf + read, len - read, &chunk, NULL) || chunk == 0) {
            free(buf);
            return NULL;
        }
        read += chunk;
    }
    *out_len = len;
    return buf;
}

static void nr_serve(HANDLE pipe)
{
    for (;;) {
        if (g_stop) break;
        unsigned long len = 0;
        unsigned char* payload = nr_recv(pipe, &len);
        if (!payload) {
            if (len == 0 && !g_stop) { /* client asked to stop */ }
            break;
        }

        char out[256] = {0};
        int ok = nr_execute((const char*)payload, len, out, sizeof(out));
        free(payload);

        DWORD wrote = 0;
        short status = ok ? 1 : 0;
        WriteFile(pipe, &status, sizeof(status), &wrote, NULL);
        DWORD out_len = (DWORD)strlen(out);
        WriteFile(pipe, &out_len, sizeof(out_len), &wrote, NULL);
        WriteFile(pipe, out, out_len, &wrote, NULL);
    }
}

static DWORD WINAPI nr_main(LPVOID param)
{
    (void)param;
    nr_load_config();

    /* Humanization: the client is CPU-sensitive at startup and its load is
     * watched in the first seconds. Wait for it to settle before touching
     * anything. */
    Sleep(g_cfg.settle_ms);

    if (!nr_install_hook()) {
        nr_log("could not install hook -- exiting without touching the client");
        return 0;
    }

    /* Wait for the state to be captured by the detour. */
    for (int i = 0; i < 6000 && !g_state; i++) Sleep(10);
    if (!g_state) {
        nr_log("no lua state captured; removing hook");
        nr_remove_hook();
        return 0;
    }
    nr_log("state captured: 0x%p", g_state);
    nr_remove_hook();   /* one detour was enough -- leave the client clean */

    /* Pipe name carries the pid so multiple clients do not collide. */
    char name[128];
    snprintf(name, sizeof(name), "%s%lu", NR_PIPE_PREFIX, GetCurrentProcessId());

    for (;;) {
        if (g_stop) break;
        HANDLE pipe = CreateNamedPipeA(
            name, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, MAX_SCRIPT + 64, MAX_SCRIPT + 64, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            nr_serve(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = inst;
        DisableThreadLibraryCalls(inst);
        /* Work on our own thread: DllMain must not block or call the loader. */
        HANDLE t = CreateThread(NULL, 0, nr_main, NULL, 0, NULL);
        if (t) CloseHandle(t);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_stop = 1;
    }
    return TRUE;
}
