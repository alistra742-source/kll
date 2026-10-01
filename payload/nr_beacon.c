/* nr_beacon.c -- proof-of-load payload.
 *
 * Loaded into a target process by NightRelay's injector. It does exactly one
 * thing: on attach, it writes a beacon file naming the process it landed in and
 * the address it was mapped at, then returns. No hooks, no patches, nothing that
 * can destabilise the client -- this exists to prove which injection path works
 * on a given machine before anything real is layered on top.
 *
 * Two ways in, and it has to handle both:
 *   - LoadLibraryW: lpvReserved is NULL and the image is in the loader list, so
 *     it can find its own file name.
 *   - manual map:    lpvReserved carries the output path, because a reflected
 *     image is deliberately absent from the loader list and cannot locate itself.
 *
 * Build: payload\build_payload.bat  (MSVC x64, statically linked CRT)
 */

#include <windows.h>

#define NR_SUFFIX ".beacon.txt"

static char g_path[MAX_PATH + 16];
static HMODULE g_module;

/* Runs on its own thread so DllMain never blocks the loader lock. */
static DWORD WINAPI nr_beacon(LPVOID unused)
{
    char line[256];
    DWORD written = 0;
    DWORD len;
    HANDLE file;

    (void)unused;
    if (g_path[0] == '\0') {
        return 1;
    }

    file = CreateFileA(g_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }

    len = wsprintfA(line,
                    "loaded=1\r\npid=%lu\r\nmodule_base=0x%p\r\n"
                    "method=%s\r\nlua_runtime=0\r\narch=%s\r\n",
                    (unsigned long)GetCurrentProcessId(),
                    (void *)g_module,
                    GetModuleHandleA(NULL) ? "loaded-or-mapped" : "unknown",
#if defined(_WIN64)
                    "x64");
#else
                    "x86");
#endif

    WriteFile(file, line, len, &written, NULL);
    CloseHandle(file);
    return 0;
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    const char *given = (const char *)reserved;
    HANDLE thread;

    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    /* We never rely on per-thread notifications; skipping them removes a
       deadlock path inside the loader lock. */
    DisableThreadLibraryCalls(module);
    g_module = module;

    /* Copy the caller's path immediately: the mapper may free that buffer as
       soon as DllMain returns, and our writer runs on another thread. */
    g_path[0] = '\0';
    if (given != NULL && given[0] != '\0') {
        lstrcpynA(g_path, given, MAX_PATH + 15);
    } else if (GetModuleFileNameA(module, g_path, MAX_PATH)) {
        lstrcatA(g_path, NR_SUFFIX);
    } else {
        return TRUE;  /* nothing to report against */
    }

    thread = CreateThread(NULL, 0, nr_beacon, NULL, 0, NULL);
    if (thread != NULL) {
        CloseHandle(thread);
    }
    return TRUE;
}
