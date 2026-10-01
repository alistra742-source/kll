# NightRelay

A Windows 10/11 desktop app for Roblox: attach to the client you are signed into,
author and run Luau through a loader bridge, search the public script hubs, and
lift the frame cap.

Ships as a single `NightRelay.exe`. No Python, no installer, no dependencies on
the target machine.

---

## Build the .exe

```bat
build_exe.bat
```

or by hand:

```bat
python -m pip install pyinstaller flask requests pillow
python assets\make_icon.py
python -m PyInstaller --noconfirm --clean --onefile --noconsole ^
  --name NightRelay --paths . --add-data "ui;ui" ^
  --hidden-import nr.server --icon assets\nightrelay.ico nightrelay.py
```

Output: `dist\NightRelay.exe` (~14 MB).

Run from source instead:

```bat
python nightrelay.py                 REM opens the app window
python nightrelay.py --no-window     REM serve only, on http://127.0.0.1:8791
python nightrelay.py --browser       REM open in your normal browser
```

## What it does

### Attach
NightRelay links to a running `RobloxPlayerBeta.exe` and reads **who is signed
in** from Roblox's own `LocalStorage\appStorage.json` — the same file the client
writes. You get the display name, username, user id, the last place joined and
the amount of process access the client actually granted.

That distinction matters. Attach reports two different things separately:

* **the link** — a handle on the client, plus its identity. This succeeds.
* **memory write access** — whether a module could be loaded. NightRelay shows
  this as granted or refused rather than pretending either way.

### Execution — the loader bridge
Scripts actually run through a **loader bridge**. This is the path that works,
and it needs no bypass: the user's own executor is what executes.

1. NightRelay hosts a tiny loopback HTTP server (default `127.0.0.1:8792`).
2. Press **get loader** in the Execution engine panel — it drops the loader into
the editor with the bridge address already baked in. Put it in your executor's
`autoexec` folder (or run it once per session).
3. The loader registers, polls for work, runs each script inside the live client,
captures the printed output and reports it back.

That is the mechanism the working executors and VSExecutor-style tools use, and
it is the reverse of the usual shape: instead of NightRelay reaching in, the
loader reaches out. A connected loader shows up as an `engine: loader` candidate,
and `/api/execute` routes to it automatically. Nothing is injected; the loader is
the only part that touches the client, and it runs on your executor.

### Delivery
Scripts have to land somewhere. The backends, best first:

| Backend | What it is | Works? |
|---|---|---|
| `loader` | Runs through the Lua loader attached to the bridge. | Yes — this is the real path |
| `external` | POSTs `{"script": …}` to an executor bridge you already run, over HTTP or a named pipe. | If you have one |
| `folder` | Writes the script into an executor's `autoexec` watch folder. | Yes, on the engine's own schedule |
| `dll` | Remote-thread `LoadLibraryW`: allocate the path in the target, spawn the thread, then scrub and free the remote buffer. | Only if the client permits it |

**Discovery does not guess ports.** It enumerates every loopback TCP listener via
`GetExtendedTcpTable`, resolves the owning process, checks the named-pipe
namespace, and looks for `autoexec` watch folders. An engine on any port is found
with no configuration.

A listener owned by NightRelay's own process is never a candidate, and every
NightRelay reply carries an `X-NightRelay-Self` header so a second copy of the app
can never be mistaken for an engine — the failure mode where the app discovered
itself and reported a success while nothing ran.

### The Lua hook, in progress
Running Luau through the client means finding the client's own Lua state and its
`luau_load` / `lua_pcall`, then getting a call into it. `nr/luavm.py` is the data
half of that, done from outside the process using the read access the client
grants:

* it walks the address space with `VirtualQueryEx`,
* locates interned strings by their bytes and validates them against the
  `TString` header (length field and type tag must both agree),
* finds whatever references those pointers, which is how the global table is
  reached without a disassembler.

No code signatures are used, deliberately: a signature has to be re-derived per
build and a stale one calls into the middle of a function. Structure changes far
less often, and every hit is checked before it is reported.

`tools/lua_probe.py` runs it against a live client. Run it with a place actually
loaded -- with the client sitting at the menu there may be no game Lua state to
find yet, and the tool says so rather than reporting an empty result as a
failure.

### Module loading, measured
The `dll` backend was taken apart and measured rather than assumed, because
"probably blocked" is not a finding. `tools/inject_bench.py` runs three delivery
paths against a process the loader owns, then against the live client:

| Path | What it does | Control | Roblox client |
|---|---|---|---|
| `load` | remote-thread `LoadLibraryW` | runs | refused |
| `manual` | reflective map, entry on a fresh thread | runs | refused |
| `apc` | reflective map, code reached via `QueueUserAPC` | runs | refused |

What the client allows and what it refuses, concretely:

* `OpenProcess` with `VM_READ`, `VM_WRITE`, `VM_OPERATION` and `CREATE_THREAD` is
  **granted**. So is `VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC`, and
  thread handles with `THREAD_SET_CONTEXT`.
* The image really is written into the client's address space — mapping reports a
  base and a size.
* Nothing ever executes. The remote thread comes back with `0xC000071C` where the
  same code returns `0x1` in a process NightRelay owns, and a queued APC writes
  nothing where the identical stub sets a flag in the control.

So the refusal is at **execution**, not at loading. Memory is writable and
threads are reachable; running code in the client is not. That is the actual
boundary, and it is why every surviving executor ships a kernel driver rather
than a user-mode injector — and why the open-source ones on GitHub are uniformly
dead or detected. Nothing that can be copied from a repository crosses this line.

`nr/manualmap.py` and `payload/` are kept because they are correct and measured,
not because they get past the client. `load` and `manual` work on any process
that does not defend itself, which is what makes them useful for testing and for
Studio.

The probe is strict on purpose: a local service that merely *answers* is not an
engine. A 401 from an auth gate or a 200 carrying a dev server's index page is
rejected, because calling those engines would make the app claim a capability it
does not have. The Engine panel shows every port it looked at plus the exact
reason it was passed over.

Scans stay interactive. A listener that accepts the connection and then says
nothing is the one case that could stall a scan (a timeout per candidate path),
so it is cut off after ~1s and named in the report. Results are cached for a few
seconds, and an explicit rescan asks for live data. `tools/scan_bench.py` proves
both behaviours against a deliberately silent listener.

NightRelay ships **no anti-cheat bypass**. Modern Roblox clients are protected at
kernel level; loading an unsigned module into one is refused, and the app reports
the refusal with the actual Win32 error instead of a fake success.

### Frame cap
Roblox now keeps a **denylist** for local fast-flag overrides. The client logs
every refusal:

```
Warning [FLog::FlagFetchingStarterModule] Denied local configuration for: DFIntTaskSchedulerTargetFps
```

So writing `ClientAppSettings.json` does nothing for the FPS flag on current
builds — NightRelay reads that log, shows you the exact list of refused flags,
and stops pretending.

The lever that *does* work is Roblox's own setting:

```
%LOCALAPPDATA%\Roblox\GlobalBasicSettings_13.xml
    <int name="FramerateCap">240</int>
```

That is the value the in-game slider writes, it is read at startup, and it is not
denylisted. NightRelay writes it to any value you pick (presets up to `999`,
which is effectively uncapped).

**Order matters.** Roblox rewrites that file from its in-memory copy when the
client exits, so the cap has to be set with Roblox closed. NightRelay arms the
change and runs a background watcher, so the raise lands by itself the moment the
client quits — you do not have to close Roblox in the right order.

**The switch never overstates itself.** While the change is still pending, the
big number shows the cap that is genuinely in place (`240`) with the label
`armed`, and a separate row says `will run at 999` / `applied: waiting on
Roblox`. It only reads `uncapped` once the new value is really in the file.

To verify it stuck: set the cap, launch Roblox, play, close it, then reopen the
tab. If the value survived, Roblox accepted it. If it snapped back to `240`,
this build clamps it and NightRelay will say so.

### Script library
Searches the public hubs concurrently and merges the results:

* **ScriptBlox** — `scriptblox.com/api/script/search`
* **Rscripts** — `rscripts.net/api/v2/scripts`
* **custom** — register any JSON endpoint with `{q}` and `{p}` placeholders

Every adapter is defensive: it probes several plausible key paths, falls back to
a generic reader, and finally to an HTML link scraper. One hub changing shape or
going down never breaks the others — each source reports its own result count or
its own error.

Results carry the body inline when the hub provides it; otherwise NightRelay
fetches the raw URL (pastebin `/raw/`, gists, any raw endpoint). Save anything to
the local library, which lives in `%LOCALAPPDATA%\NightRelay\scripts`.

### Repo trust check
Searching GitHub for an executor returns over a thousand repositories and almost
none of them are software. On 2026-09-29 the top hits were repos created within
the previous ten days whose entire contents were a `README.md`, an `index.html`,
a `button.svg` and a `preview.svg` — language: HTML. The highest-starred one,
`Delta-Executor-PC` with 52 stars, shipped a single 53-byte Python file that
printed a test string. The download button points off-site, because that is where
the payload lives and GitHub's scanners only ever see the clean half.

`GET /api/trust?repo=owner/name` reads a repository before anything from it is
run, and reports a verdict plus the specific reasons behind it:

* **metadata** — age, last push, stars, forks, archived state
* **language bytes** — GitHub's own analysis, so a large project with its source
  in subdirectories is not mistaken for one with no source
* **root manifest** — landing-page assets, docs outweighing code, and whether the
  shipped bytes could plausibly do the job at all
* **file contents** — decoder-loop obfuscation (`atob`, `eval`, base64 blobs,
  encoded PowerShell) and links that leave GitHub

Staleness and malice are scored separately: `nwvh/neverwhere` is real C# source
that has been archived since 2023, so it reports `looks-genuine` with
`maintenance: archived` rather than being flagged as malicious. Read-only — it
reads metadata and file bytes over GitHub's public API and never downloads,
saves, or executes what it finds.

```
curl "http://127.0.0.1:8791/api/trust?repo=LavenderChancellor/Delta-Executor-PC"
```

`tools/trust_bench.py` checks it against four real repositories with their state
recorded: two distribution pages that must come back `dangerous`, the archived
genuine one, and a control that must not be flagged.

### DeepSeek
Session-token first. Sign in to `chat.deepseek.com`, grab `userToken` from DevTools
→ Application → Local Storage, and paste it into the DeepSeek tab. NightRelay
verifies it against DeepSeek's own API before storing it, solves the
proof-of-work challenge when the web endpoint asks for one, and streams replies
back into the chat. An official `sk-` API key works too, as a secondary option.

Any fenced code block in a reply gets a **send to relay** button that drops it
straight into the editor.

### Traces
* Credentials are sealed with the Windows Data Protection API (`CryptProtectData`),
  keyed to your Windows account — never written as readable text.
* Injected buffers are overwritten and freed after a load.
* Runtime scratch lives in a randomly-named directory and is shredded on exit.
* `wipe traces` overwrites and removes scratch files and backups on demand.
* No telemetry, no crash reporting, no background network traffic of its own.
* Scripts are never written to disk unless you press save.

## Layout

```
nightrelay.py          entry point: bind server, open the app window
nr/config.py           paths, settings, DPAPI secret vault, shredder
nr/roblox.py           process discovery, identity, versions, lifecycle
nr/fflags.py           frame cap + flag-denial detection
nr/library.py          hub adapters and the local script store
nr/trust.py            GitHub repo trust check: metadata, manifest, obfuscation
nr/deepseek.py         API-key and session-token client, streaming, PoW
nr/executor.py         delivery backends, attach lifecycle, run history
nr/manualmap.py        reflective PE mapper (headers, relocs, imports, entry call)
nr/luavm.py            external Luau scanner: regions, strings, references
nr/bridge.py           the loader bridge: loopback server a Lua loader talks to
nr/loader_lua.py       the Lua loader template, served to paste into an executor
nr/discovery.py        loopback listener scan and engine probing
nr/selftest_engine.py  inert stub that proves the relay path
nr/server.py           local HTTP API
ui/index.html          the whole interface, one file
assets/make_icon.py    generates the .ico
build_exe.bat          one-command PyInstaller build
tools/loader_bench.py  end-to-end proof of the loader bridge
tools/scan_bench.py    proves scans stay interactive
tools/inject_bench.py  measures which injection paths run and which are refused
tools/lua_probe.py     finds Luau structures in a live client, from outside
tools/trust_bench.py   repo trust check against known-answer repositories
tools/pow_bench.py     proof-of-work solver checks
payload/nr_beacon.c    injectable payload, built by payload/build_payload.bat
payload/build_payload.bat  MSVC x64 build, toolchain found via vswhere
```

State lives in `%LOCALAPPDATA%\NightRelay` (`settings.json`, `vault.bin`,
`history.json`, `scripts\`, `backups\`). Set `NIGHTRELAY_HOME` for a portable copy.

## Requirements

Windows 10/11 64-bit. The app window uses an installed Chromium browser in
`--app` mode (Edge is present on every Windows 10 box); without one it falls back
to your default browser. Nothing else is needed at runtime.
