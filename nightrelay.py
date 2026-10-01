"""NightRelay entry point.

Boots the local core server, then renders the interface in a real native window
(WebView2 through pywebview). Nothing is written to a console: the window *is*
the app, with no browser chrome and no address bar.

A browser window in app mode is kept only as a fallback for machines where the
WebView2 runtime or pywebview is unavailable.

    python nightrelay.py             # normal run
    python nightrelay.py --portable  # keep every file next to the exe
    python nightrelay.py --browser   # force the browser fallback
    python nightrelay.py --no-window # serve only (headless / debugging)
"""

from __future__ import annotations

import argparse
import atexit
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nr import APP_NAME, APP_VERSION, config, fflags, server  # noqa: E402

BROWSER_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]


def find_app_browser() -> str:
    env = os.environ.get("NIGHTRELAY_BROWSER")
    if env and Path(env).is_file():
        return env
    for candidate in BROWSER_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    for name in ("msedge.exe", "chrome.exe", "brave.exe"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def run_native_window(url: str, title: str) -> bool:
    """Render the UI in a native WebView2 window. False if pywebview is absent."""
    try:
        import webview  # noqa: PLC0415
    except Exception:
        return False

    storage = config.data_dir() / "runtime" / "webview"
    storage.mkdir(parents=True, exist_ok=True)

    try:
        webview.create_window(
            title,
            url,
            width=1360,
            height=880,
            min_size=(940, 620),
            background_color="#06060b",
            text_select=False,
        )
        webview.start(storage_path=str(storage), debug=False)
        return True
    except Exception as exc:  # noqa: BLE001 - fall back to a browser window
        server.log(f"native window unavailable ({exc}); using the browser", "warn")
        return False


def open_window(url: str) -> subprocess.Popen | None:
    """Fallback: a chromeless browser window with its own profile directory."""
    browser = find_app_browser()
    if not browser:
        webbrowser.open(url)
        return None
    profile = config.data_dir() / "runtime" / "window"
    profile.mkdir(parents=True, exist_ok=True)
    args = [
        browser,
        f"--app={url}",
        f"--user-data-dir={profile}",
        "--window-size=1320,860",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-features=Translate,MediaRouter,OptimizationHints",
        "--disable-sync",
        "--mute-audio",
    ]
    try:
        return subprocess.Popen(args, close_fds=True)
    except OSError:
        webbrowser.open(url)
        return None


def wait_for_server(url: str, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/api/health", timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    return False


def cleanup() -> None:
    settings = config.settings()
    if settings.get("executor.shred_on_exit", True):
        server.log("shredding runtime scratch on exit")
        config.shred_tree(config.runtime_dir())
    config.vault().flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME, description="script relay for windows")
    parser.add_argument("--port", type=int, default=0, help="local UI port (0 = auto)")
    parser.add_argument("--no-window", action="store_true", help="serve only, do not open a window")
    parser.add_argument("--browser", action="store_true", help="force the browser fallback")
    parser.add_argument("--portable", action="store_true", help="store everything beside the exe")
    parser.add_argument("--host", default="", help="override bind address")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    args = parser.parse_args(argv)
    if args.portable:
        os.environ.setdefault(
            "NIGHTRELAY_HOME", str(Path(sys.executable if config.frozen() else __file__).resolve().parent / "data")
        )

    settings = config.settings()
    host = args.host or settings.get("server.bind", "127.0.0.1")
    preferred = args.port or int(settings.get("server.port", 8791))
    port = server.free_port(preferred, host)
    url = f"http://{host}:{port}"

    server.log(f"{APP_NAME} {APP_VERSION} starting on {url}")
    server.log(f"data directory: {config.data_dir()}")
    if port != preferred:
        server.log(f"port {preferred} was busy -- using {port}", "warn")

    app = server.create_app()
    server.serve_background(app, host, port)

    if not wait_for_server(url):
        print(f"{APP_NAME}: server failed to come up on {url}", file=sys.stderr)
        return 1

    atexit.register(cleanup)
    fflags.start_watcher()

    # First-run check: if the machine is not yet provisioned for the driver, say
    # so plainly -- and once test signing is on but a reboot has not happened
    # yet, that is the one line the user needs to see.
    try:
        from nr import setup as setup_mod  # noqa: PLC0415

        setup_mod.finalize_if_rebooted()
        setup_status = setup_mod.status()
        if setup_status.get("restart_pending"):
            server.log("restart your PC to finish setup", "warn")
        elif not setup_status.get("ready"):
            server.log("first-run setup has not been completed", "warn")
    except Exception as exc:  # noqa: BLE001 - setup must never stop the app booting
        server.log(f"setup check skipped: {exc}", "warn")

    if args.no_window:
        print(f"{APP_NAME} serving at {url} -- press Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return 0

    settings_ui = config.settings().get("ui.randomize_title", False)
    title = APP_NAME
    if settings_ui:
        title = f"{APP_NAME} {secrets.token_hex(2)}"

    proc = None
    try:
        if not args.browser and run_native_window(url, title):
            return 0
        if args.browser:
            webbrowser.open(url)
        else:
            proc = open_window(url)
            if proc is None:
                server.log("no app-mode browser found -- opened the default browser", "warn")
        while True:
            time.sleep(1)
            if proc is not None and proc.poll() is not None:
                time.sleep(1.5)
                break
    except KeyboardInterrupt:
        pass
    finally:
        fflags.stop_watcher()
        if proc is not None and proc.poll() is None:
            proc.terminate()
        cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
