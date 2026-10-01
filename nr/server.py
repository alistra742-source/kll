"""Local HTTP surface: the UI talks to the core through this module only."""

from __future__ import annotations

import json
import socket
import threading
import time

from flask import Flask, Response, jsonify, request, send_from_directory

from . import APP_NAME, APP_TAGLINE, APP_VERSION
from . import (  # noqa: F401
    bridge as bridge_mod,
    config,
    deepseek,
    discovery,
    executor as executor_mod,
    extc,
    fflags,
    library as library_mod,
    license as license_mod,
    loader_lua,
    roblox,
    selftest_engine,
    trust as trust_mod,
)

state = {
    "started": time.time(),
    "log": [],
}
_log_lock = threading.Lock()


def log(message: str, level: str = "info") -> None:
    entry = {"time": config.uptime_stamp(), "level": level, "message": message}
    with _log_lock:
        state["log"].insert(0, entry)
        del state["log"][400:]


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    ui_dir = config.resource_dir() / "ui"

    @app.after_request
    def _stamp(response):
        """Mark every answer as coming from NightRelay itself.

        Discovery probes loopback POSTs and reads a JSON reply as an engine's
        ack. Our own /api/execute answers exactly like that, so without a marker
        NightRelay (or a second copy of it) would happily discover itself and
        report execution success while nothing ran. The header lets the probe
        refuse that answer with certainty.
        """
        response.headers["X-NightRelay-Self"] = "1"
        return response

    # ------------------------------------------------------------------ UI
    @app.get("/")
    def index():
        return send_from_directory(ui_dir, "index.html")

    @app.get("/<path:asset>")
    def assets(asset: str):
        return send_from_directory(ui_dir, asset)

    # ---------------------------------------------------------------- state
    @app.get("/api/state")
    def api_state():
        settings = config.settings()
        return jsonify(
            {
                "app": APP_NAME,
                "tagline": APP_TAGLINE,
                "version": APP_VERSION,
                "uptime_s": int(time.time() - state["started"]),
                "roblox": roblox.Manager().status(),
                "fflags": fflags.status(),
                "ai": deepseek.status(),                "executor": executor_mod.executor().status(),
        "loader": bridge_mod.bridge().status(),
        "selftest": selftest_engine.engine().status(),
        "settings": settings.all(),
                "log": state["log"][:60],
                "data_dir": str(config.data_dir()),
            }
        )

    @app.get("/api/log")
    def api_log():
        return jsonify({"log": state["log"][:120]})

    # --------------------------------------------------------------- roblox
    @app.get("/api/roblox")
    def api_roblox():
        return jsonify(roblox.Manager().status())

    @app.get("/api/roblox/identity")
    def api_identity():
        return jsonify({"identity": roblox.identity(), "place": roblox.place_from_log()})

    @app.post("/api/roblox/launch")
    def api_launch():
        body = request.get_json(silent=True) or {}
        result = roblox.launch(
            place_url=body.get("place_url", ""),
            multi_instance=bool(body.get("multi_instance", False)),
            extra_args=body.get("args") or None,
        )
        log(result["message"], "ok" if result["ok"] else "error")
        return jsonify(result)

    @app.post("/api/roblox/kill")
    def api_kill():
        result = roblox.kill_all()
        executor_mod.executor().injector.detach_all()
        log(result["message"], "warn")
        return jsonify(result)

    @app.post("/api/roblox/multi-instance")
    def api_multi():
        result = roblox.break_singleton()
        log(result["message"], "ok" if result["ok"] else "warn")
        return jsonify(result)

    # ---------------------------------------------------------------- flags
    @app.get("/api/fflags")
    def api_fflags():
        return jsonify(fflags.status())

    @app.post("/api/fps/toggle")
    def api_fps_toggle():
        body = request.get_json(silent=True) or {}
        result = fflags.set_unlock(bool(body.get("enabled", False)))
        log(result["message"], "ok" if result.get("ok") else "warn")
        return jsonify({**result, "status": fflags.status()})

    @app.post("/api/fflags/apply")
    def api_fflags_apply():
        body = request.get_json(silent=True) or {}
        target = int(body.get("target_fps", fflags.UNLOCK_FPS))
        result = fflags.apply_fps(target)
        config.settings().set("fps.target", target)
        log(result["message"], "ok" if result["ok"] else "warn")
        return jsonify(result)

    @app.post("/api/fflags/telemetry")
    def api_fflags_telemetry():
        body = request.get_json(silent=True) or {}
        off = bool(body.get("off", True))
        result = fflags.apply_telemetry(off)
        config.settings().set("fps.telemetry_off", off)
        log(result["message"], "ok" if result["ok"] else "warn")
        return jsonify(result)

    @app.post("/api/fflags/restore")
    def api_fflags_restore():
        result = fflags.restore_cap()
        fflags.clear_flag_file()
        log(result["message"], "warn")
        return jsonify(result)

    # -------------------------------------------------------------- library
    @app.get("/api/library/sources")
    def api_sources():
        settings = config.settings()
        builtin = [src.to_dict() for src in library_mod.SOURCES.values()]
        custom = settings.get("library.custom_sources", []) or []
        return jsonify({"builtin": builtin, "custom": custom})

    @app.post("/api/library/sources")
    def api_sources_add():
        body = request.get_json(silent=True) or {}
        label = (body.get("label") or "").strip()
        url = (body.get("url") or "").strip()
        if not label or not url:
            return jsonify({"ok": False, "message": "label and url are required"}), 400
        settings = config.settings()
        custom = list(settings.get("library.custom_sources", []) or [])
        custom = [c for c in custom if c.get("label") != label]
        custom.append({"label": label, "url": url, "enabled": True})
        settings.set("library.custom_sources", custom)
        log(f"registered script source {label}", "ok")
        return jsonify({"ok": True, "custom": custom})

    @app.delete("/api/library/sources")
    def api_sources_remove():
        label = request.args.get("label", "")
        settings = config.settings()
        custom = [c for c in (settings.get("library.custom_sources", []) or []) if c.get("label") != label]
        settings.set("library.custom_sources", custom)
        return jsonify({"ok": True, "custom": custom})

    @app.get("/api/library/search")
    def api_search():
        query = request.args.get("q", "").strip()
        page = int(request.args.get("page", 1) or 1)
        limit = int(request.args.get("limit", 24) or 24)
        sources = [s for s in (request.args.get("sources", "").split(",")) if s]
        settings = config.settings()
        result = library_mod.search(
            query,
            source_ids=sources or None,
            page=page,
            limit=limit,
            custom=settings.get("library.custom_sources", []) or [],
        )
        log(f'searched "{query or "*"}" -> {result["count"]} hit(s) in {result["elapsed_ms"]}ms')
        return jsonify(result)

    @app.post("/api/library/fetch")
    def api_fetch():
        body = request.get_json(silent=True) or {}
        code = library_mod.resolve_code(body.get("result") or {})
        if not code:
            return jsonify({"ok": False, "message": "no script body found for that result"})
        return jsonify({"ok": True, "code": code, "bytes": len(code)})

    @app.get("/api/library/url")
    def api_url_fetch():
        url = request.args.get("url", "")
        code = library_mod.fetch_raw(url)
        if not code:
            return jsonify({"ok": False, "message": "could not read a script from that URL"})
        return jsonify({"ok": True, "code": code, "bytes": len(code)})

    # ------------------------------------------------------------ repo trust
    @app.get("/api/trust")
    def api_trust():
        """Audit a GitHub repo before anything from it is run.

        Read-only: this reads metadata and file contents from GitHub's public
        API and never downloads, saves or executes what it finds.
        """
        ref = (request.args.get("repo") or request.args.get("url") or "").strip()
        if not ref:
            return jsonify({"ok": False, "error": "pass ?repo=owner/name"}), 400
        result = trust_mod.audit(ref)
        if not result["ok"]:
            log(f"repo check failed for {ref}: {result['error']}", "warn")
            return jsonify(result), 400
        meta = result.get("meta") or {}
        log(
            f"checked {meta.get('full_name') or ref}: {result['verdict']} "
            f"(score {result['score']})",
            "error" if result["verdict"] == "dangerous" else "info",
        )
        return jsonify(result)

    @app.get("/api/library/local")
    def api_local_list():
        return jsonify({"scripts": library_mod.LocalLibrary().list()})

    @app.get("/api/library/local/<path:name>")
    def api_local_read(name: str):
        return jsonify({"ok": True, "code": library_mod.LocalLibrary().read(name)})

    @app.post("/api/library/local")
    def api_local_save():
        body = request.get_json(silent=True) or {}
        result = library_mod.LocalLibrary().save(
            body.get("name") or "untitled", body.get("code") or "", body.get("meta") or {}
        )
        log(f"saved {result.get('name')}", "ok")
        return jsonify(result)

    @app.delete("/api/library/local")
    def api_local_delete():
        name = request.args.get("name", "")
        return jsonify(library_mod.LocalLibrary().delete(name))

    # ------------------------------------------------------------------- ai
    @app.post("/api/chat")
    def api_chat():
        body = request.get_json(silent=True) or {}
        messages = body.get("messages") or []
        settings = config.settings()
        system = body.get("system") or settings.get("ai.system_prompt", "")
        model = body.get("model") or settings.get("ai.model", "deepseek-chat")
        temperature = float(body.get("temperature", settings.get("ai.temperature", 0.35)))
        if system and not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": system}] + messages

        def generate():
            try:
                for event in deepseek.stream(
                    messages, model=model, temperature=temperature
                ):
                    yield f"data: {json.dumps(event)}\n\n"
            except Exception as exc:  # noqa: BLE001 - surface anything to the UI
                yield f"data: {json.dumps({'type': 'error', 'text': str(exc)})}\n\n"
            yield "data: {\"type\":\"close\"}\n\n"

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/chat/reset")
    def api_chat_reset():
        deepseek.reset_session()
        return jsonify({"ok": True})

    @app.post("/api/ai/connect")
    def api_ai_connect():
        body = request.get_json(silent=True) or {}
        kind = body.get("kind", "token")
        secret = (body.get("secret") or "").strip()
        if not secret:
            return jsonify({"ok": False, "message": "enter a value first"})
        result = deepseek.verify(secret, kind)
        if result["ok"]:
            key = "deepseek_user_token" if kind == "token" else "deepseek_api_key"
            config.vault().set(key, secret)
            deepseek.reset_session()
            log(f"DeepSeek connected ({kind})", "ok")
        else:
            log(f"DeepSeek rejected the {kind}: {result['message']}", "error")
        return jsonify({**result, "secrets": config.vault().masked(), "mode": deepseek.mode()})

    @app.post("/api/ai/disconnect")
    def api_ai_disconnect():
        vault = config.vault()
        for key in ("deepseek_user_token", "deepseek_api_key"):
            vault.clear(key)
        deepseek.reset_session()
        log("DeepSeek credentials cleared", "warn")
        return jsonify({"ok": True, "secrets": vault.masked(), "mode": deepseek.mode()})

    # ------------------------------------------------------------- executor
    @app.get("/api/executor")
    def api_executor():
        return jsonify(executor_mod.executor().status())

    @app.post("/api/executor/attach")
    def api_attach():
        body = request.get_json(silent=True) or {}
        result = executor_mod.executor().attach(body.get("pid"))
        log(result.message, "ok" if result.ok else "error")
        return jsonify(result.to_dict())

    @app.post("/api/executor/probe")
    def api_probe():
        result = executor_mod.executor().bridge.probe(force_scan=True)
        log(result.message, "ok" if result.ok else "warn")
        payload = result.to_dict()
        payload.pop("scan", None)
        return jsonify(payload)

    @app.post("/api/executor/scan")
    def api_scan():
        """Full discovery report: every candidate and why it was accepted.

        Repeat scans inside a few seconds reuse a cached result so the UI stays
        responsive; an explicit rescan asks for a live one.
        """
        body = request.get_json(silent=True) or {}
        refresh = bool(body.get("refresh"))
        report = executor_mod.executor().bridge.scan(refresh=refresh)
        summary = report["summary"]
        if report.get("cached"):
            summary = f"{summary} (cached)"
        log(summary, "ok" if report["ok"] else "warn")
        return jsonify(report)

    @app.post("/api/executor/selftest")
    def api_selftest():
        """Start or stop the inert stub used to prove the relay path."""
        body = request.get_json(silent=True) or {}
        engine = selftest_engine.engine()
        if body.get("stop"):
            result = engine.stop()
            executor_mod.executor().bridge.url = ""
        else:
            result = engine.start()
        log(result["message"], "ok" if result.get("ok") else "error")
        return jsonify({**result, "status": engine.status()})

    @app.post("/api/execute")
    def api_execute():
        body = request.get_json(silent=True) or {}
        code = body.get("code") or ""
        if not code.strip():
            return jsonify({"ok": False, "message": "nothing to run", "backend": "none"})
        result = executor_mod.executor().execute(
            code,
            pid=body.get("pid"),
            backend=body.get("backend"),
            dll_path=body.get("dll_path"),
        )
        log(
            f"execute -> {result['backend']}: {result['message']}",
            "ok" if result["ok"] else "error",
        )
        return jsonify(result)

    @app.post("/api/executor/history/clear")
    def api_history_clear():
        executor_mod.executor().clear_history()
        return jsonify({"ok": True})

    # -------------------------------------------------- external executor core
    @app.get("/api/executor/external")
    def api_external_status():
        """State of the from-outside executor: driver, attach, compiler, offsets."""
        return jsonify(extc.external().status())

    @app.post("/api/executor/external/attach")
    def api_external_attach():
        body = request.get_json(silent=True) or {}
        result = extc.external().attach(body.get("pid"))
        log(result.message, "ok" if result.ok else "error")
        return jsonify(result.to_dict())

    @app.post("/api/executor/external/execute")
    def api_external_execute():
        body = request.get_json(silent=True) or {}
        code = body.get("code") or ""
        if not code.strip():
            return jsonify({"ok": False, "message": "nothing to run", "backend": "external_core"})
        page = extc.external()
        if not page.pid:
            attached = page.attach(body.get("pid"))
            if not attached.ok:
                return jsonify(attached.to_dict())
        result = page.execute(code)
        log(f"external -> {result.message}", "ok" if result.ok else "error")
        return jsonify(result.to_dict())

    # ------------------------------------------------------------------ license
    @app.get("/api/license")
    def api_license():
        lic = license_mod.cached()
        return jsonify(
            {
                "required": license_mod.required(),
                "hwid": license_mod.hwid(),
                "license": lic.to_dict(),
            }
        )

    @app.post("/api/license/activate")
    def api_license_activate():
        body = request.get_json(silent=True) or {}
        url = str(body.get("url") or config.settings().get("license.url", "") or "")
        lic = license_mod.activate(str(body.get("key") or ""), online_url=url)
        log(f"license: {lic.reason}", "ok" if lic.valid else "error")
        return jsonify({"license": lic.to_dict()})

    # ------------------------------------------------------------ loader bridge
    @app.get("/api/bridge")
    def api_bridge():
        return jsonify(bridge_mod.bridge().status())

    @app.post("/api/bridge/start")
    def api_bridge_start():
        body = request.get_json(silent=True) or {}
        port = int(body.get("port") or config.settings().get("executor.bridge_port", 8792))
        result = bridge_mod.bridge().start(port)
        log(result["message"], "ok" if result.get("ok") else "error")
        return jsonify({**result, "status": bridge_mod.bridge().status()})

    @app.post("/api/bridge/stop")
    def api_bridge_stop():
        result = bridge_mod.bridge().stop()
        log(result["message"], "warn")
        return jsonify({**result, "status": bridge_mod.bridge().status()})

    @app.get("/api/bridge/loader")
    def api_bridge_loader():
        """The Lua loader, with this bridge's address already baked in."""
        b = bridge_mod.bridge()
        port = b.port if b.running else int(config.settings().get("executor.bridge_port", 8792))
        source = loader_lua.render("127.0.0.1", port)
        return jsonify({"ok": True, "port": port, "source": source, "bytes": len(source)})

    # ------------------------------------------------------------- settings
    @app.get("/api/settings")
    def api_settings():
        settings = config.settings()
        return jsonify({"settings": settings.all(), "secrets": config.vault().masked()})

    @app.post("/api/settings")
    def api_settings_save():
        body = request.get_json(silent=True) or {}
        patch = body.get("settings") or {}
        secrets = body.get("secrets") or {}
        settings = config.settings()
        if patch:
            settings.update(patch)
            if "executor" in patch:
                executor_mod.executor().bridge.url = patch["executor"].get("external_url", "")
                executor_mod.executor().bridge.pipe = patch["executor"].get("pipe_name", "")
        vault = config.vault()
        for key in config.SECRET_KEYS:
            if key in secrets and secrets[key] != "":
                vault.set(key, str(secrets[key]).strip())
        if secrets.get("_clear"):
            for key in secrets["_clear"]:
                vault.clear(str(key))
        deepseek.reset_session()
        log("settings saved", "ok")
        return jsonify({"ok": True, "settings": settings.all(), "secrets": vault.masked()})

    @app.post("/api/panic")
    def api_panic():
        log("panic requested -- shredding runtime scratch", "warn")
        config.shred_tree(config.runtime_dir())
        return jsonify({"ok": True})

    @app.get("/api/maintenance/backups")
    def api_backups():
        files = sorted(str(p) for p in config.backup_dir().glob("*.json"))
        return jsonify({"backups": files})

    @app.post("/api/maintenance/shred")
    def api_shred():
        result = fflags.delete_all_backups()
        log(result["message"], "warn")
        return jsonify(result)

    @app.get("/api/health")
    def api_health():
        return jsonify({"ok": True, "app": APP_NAME, "version": APP_VERSION})

    return app


# --------------------------------------------------------------------------- #
# Serving
# --------------------------------------------------------------------------- #
def free_port(preferred: int, host: str = "127.0.0.1") -> int:
    """Return `preferred` if we can bind it, otherwise an ephemeral port."""
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, candidate))
                return sock.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free local port")


def serve(app: Flask, host: str = "127.0.0.1", port: int = 8791) -> None:
    """Run the UI server. Threaded so SSE streams do not block the rest."""
    try:
        from waitress import serve as waitress_serve

        # Waitress is not great with long-lived SSE, so keep the threaded
        # werkzeug server for a single local user: it handles streams natively.
        raise ImportError
    except ImportError:
        app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)
    else:  # pragma: no cover - retained for deployments without SSE needs
        waitress_serve(app, host=host, port=port, threads=8)


def serve_background(app: Flask, host: str, port: int) -> threading.Thread:
    thread = threading.Thread(target=serve, args=(app, host, port), daemon=True)
    thread.start()
    return thread
