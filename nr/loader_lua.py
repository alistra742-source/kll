"""The Lua loader, as a template.

This is the script the user pastes into their executor's autoexec folder. It is
the only piece of NightRelay that runs inside Roblox, and it runs on the user's
own executor -- the app itself still executes nothing.

The bridge host and port are substituted in at copy time, so the loader a user
grabs always matches the running bridge. Kept as a Python string rather than a
data file so the source of truth ships inside the exe with no extra bundling.
"""

from __future__ import annotations

LOADER_TEMPLATE = r"""--[[ NightRelay loader
     Paste this into your executor's autoexec folder, or run it once per session.

     It registers with the NightRelay bridge, then polls for scripts, runs each
     one inside this client and reports the printed output back. This is the part
     that executes; NightRelay itself only carries the script across the loopback.

     The address below was baked in when you copied it. Move NightRelay to a
     different port and you copy the loader again from the Execution engine panel.
--]]
local HOST = "__HOST__"
local PORT = __PORT__

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")

local load_chunk = loadstring or load

-- The bridge host/port can also be overridden at runtime, which is handy when
-- the loader is shared between machines.
local cfg = (getgenv and getgenv().NightRelayConfig) or {}
HOST = tostring(cfg.host or HOST)
PORT = tonumber(cfg.port) or PORT

local function encode(t)
    local ok, s = pcall(HttpService.JSONEncode, HttpService, t)
    return ok and s or nil
end

local function decode(s)
    if type(s) ~= "string" or #s == 0 then return nil end
    local ok, t = pcall(HttpService.JSONDecode, HttpService, s)
    return ok and t or nil
end

-- Any one of the transport names executors use, in order of preference. Local
-- loopback HTTP is the whole requirement; no external network is ever touched.
local function http(method, path, body)
    local url = ("http://%s:%d%s"):format(HOST, PORT, path)
    local payload = body and encode(body) or nil
    local req = (typeof(request) == "function" and request)
        or (typeof(http_request) == "function" and http_request)
        or (typeof(syn) == "table" and syn.request)
        or (typeof(http) == "table" and http.request)
    if req then
        local ok, res = pcall(req, {
            Url = url,
            Method = method,
            Body = payload,
            Headers = { ["Content-Type"] = "application/json" },
            Timeout = 5,
        })
        if ok and type(res) == "table" then
            local txt = res.Body or res.body or res.Data
            if type(txt) == "string" and #txt > 0 then
                return decode(txt)
            end
        end
    end
    if method == "GET" then
        local ok, txt = pcall(game.HttpGet, game, url, true)
        if ok and type(txt) == "string" then
            return decode(txt)
        end
    end
    return nil
end

local function session_key()
    local who = "anon"
    local lp = Players and Players.LocalPlayer
    if lp then who = tostring(lp.UserId) end
    local job = ""
    local ok, j = pcall(function() return game.JobId end)
    if ok and j then job = tostring(j) end
    return ("nr|%s|%s|%s"):format(who, tostring(game.PlaceId or ""), job)
end

-- Print and warn are swapped for the duration of one run so the output can be
-- sent back with the result. They are restored even when the script errors.
local function capture_run(job_id, src)
    local lines = {}
    local real_print, real_warn = print, warn
    local function tap(...)
        local parts = {}
        for i = 1, select("#", ...) do
            local v = select(i, ...)
            parts[#parts + 1] = (type(v) == "string") and v or tostring(v)
        end
        lines[#lines + 1] = table.concat(parts, " ")
        return real_print(...)
    end
    print, warn = tap, tap

    local started = os.clock()
    local chunk, compile_err = nil, nil
    if load_chunk then
        chunk, compile_err = load_chunk(src, "nr:" .. tostring(job_id))
    else
        compile_err = "this executor exposes no loadstring"
    end

    local ok, err
    if not chunk then
        ok, err = false, compile_err
    else
        ok, err = pcall(chunk)
    end

    print, warn = real_print, real_warn
    return ok, (ok and "" or tostring(err)), table.concat(lines, "\n"),
        math.floor((os.clock() - started) * 1000)
end

local function report(id, job_id, ok, err, output, duration)
    http("POST", "/report", {
        id = id,
        job_id = job_id,
        ok = ok,
        error = err or "",
        output = output or "",
        duration_ms = duration or 0,
    })
end

local function pump(id, poll_s, hb_s)
    local last_hb = os.clock()
    local misses = 0
    while true do
        local res = http("GET", "/poll?id=" .. tostring(id))
        if res and res.ok == false then
            return  -- the bridge forgot us (maybe it restarted); re-register
        end
        if res and type(res.jobs) == "table" then
            misses = 0
            for _, job in ipairs(res.jobs) do
                local ok, err, output, duration = capture_run(job.job_id, job.script)
                report(id, job.job_id, ok, err, output, duration)
            end
        else
            misses = misses + 1
            if misses > 40 then return end
        end
        if os.clock() - last_hb > hb_s then
            http("POST", "/heartbeat", { id = id })
            last_hb = os.clock()
        end
        task.wait(poll_s)
    end
end

local function main()
    local key = session_key()
    while true do
        local reg = http("POST", "/register", {
            session = key,
            game = tostring(game.PlaceId or ""),
            place = tostring(game.PlaceId or ""),
            player = (Players and Players.LocalPlayer) and tostring(Players.LocalPlayer.Name) or "",
        })
        if reg and reg.ok and reg.id then
            local started_ok, started_err = pcall(pump, reg.id,
                (tonumber(reg.poll_ms) or 200) / 1000,
                (tonumber(reg.heartbeat_ms) or 5000) / 1000)
            if not started_ok and print then
                print("[NightRelay] loader stopped: " .. tostring(started_err))
            end
        end
        task.wait(3)
    end
end

-- A tiny surface for other scripts to drive the same bridge.
local g = getgenv and getgenv() or _G
g.NightRelay = {
    host = HOST,
    port = PORT,
    run = function(src)
        local ok, err, output = capture_run("local", src)
        return ok, err, output
    end,
}

task.spawn(main)
"""


def render(host: str = "127.0.0.1", port: int = 8792) -> str:
    """The loader with the bridge address filled in."""
    return LOADER_TEMPLATE.replace("__HOST__", host).replace("__PORT__", str(int(port)))
