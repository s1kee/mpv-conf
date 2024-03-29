-- https://github.com/LiTO773/trakt-mpv/raw/main/trakt-mpv.lua @ e02cebfc1c6bd4c8ec6461f963b26c7705ea132d

local utils = require 'mp.utils'

-- GLOBAL VARS:
local key = "t"
local py_location = utils.join_path(mp.get_script_directory(), "trakt-mpv.py")
local hello_ran = false

-- HELPER FUNCTIONS:
-- Joins two tables
local function merge_tables(t1, t2)
    local length = #t2
    for i = 1, length do
        t1[#t1 + 1] = t2[i]
    end

    return t1
end


-- Calls the Python file
local function evoque_python(flags, cancellable, retr_stdout, cb)
    -- Add the flags
    local args = merge_tables({ "python", py_location }, flags)

    -- Call the file
    return mp.command_native_async({
        name = "subprocess",
        capture_stdout = retr_stdout,
        playback_only = cancellable,
        args = args,
    }, cb)
end

-- Sends a message
local function send_message(msg, color, time)
    local ass_start = mp.get_property_osd("osd-ass-cc/0")
    local ass_stop = mp.get_property_osd("osd-ass-cc/1")
    mp.osd_message(ass_start .. "{\\1c&H" .. color .. "&}" .. "[trakt-mpv] " .. msg .. ass_stop, time)
end

-- Activate Function
local function activated()
    evoque_python({"--auth"}, true, false, function(success, result, error)
        mp.remove_key_binding("auth-trakt")
        if result.status == 0 then
            send_message("It's done. Enjoy!", "00FF00", 3)
        else
            send_message("Damn, there was an error in Python :/ Check the console for more info.", "0000FF", 4)
        end
    end)
end

local function activation()
    send_message("Querying trakt.tv... Hold tight", "FFFFFF", 10)
    evoque_python({"--code"}, true, true, function(success, result, error)
        mp.remove_key_binding("auth-trakt")
        if result.status == 0 then
            send_message("Open https://trakt.tv/activate and type: " .. result.stdout .. "\nPress {\\i1}" .. key .. "{\\i0} when done", "FF8800", 50)
            mp.add_forced_key_binding(key, "auth-trakt", activated)
        else
            send_message("Damn, there was an error in Python :/ Check the console for more info.", "0000FF", 4)
        end
    end)
end

-- Checkin Function
local function checkin(filename)
    evoque_python({"--query", filename}, false, true, function(success, result, error)
        if result.status == 0 then
            send_message(result.stdout, "00FF00", 2)
        elseif result.status == 14 then
            send_message("Couldn't find the show in trakt", "0000FF", 2)
        else
            send_message("Unable to scrobble " .. result.stdout, "0000FF", 2)
        end
    end)
end

-- MAIN FUNCTION

local function handlemessage()
    local filename = mp.get_property('media-title')
    if hello_ran then
        -- if we already had a successful hello invocation in one mpv session, we don't need to keep running it
        -- this assumption might fail if you leave mpv running for days at a time and the Trakt session expires for w/e reason
        checkin(filename)
    else
        evoque_python({"--hello"}, false, false, function(success, result, error)
            if not success then return end
            if result and result.killed_by_us then return end

            if result.status == 0 then
                hello_ran = true
                -- Plugin is setup, start the checkin
                checkin(filename)
                return
            end

            -- skip showing error messages if the file has changed
            if filename ~= mp.get_property('media-title') then return end

            -- Check status and act accordingly
            if result.status == 10 then
                -- Plugin is yet to be configured
                send_message("Please add your client_id and client_secret to config.json!", "0000FF", 4)
            elseif result.status == 11 then
                -- Plugin has to authenticate
                send_message("Press {\\i1}" .. key .. "{\\i0} to authenticate with Trakt.tv", "FF8800", 4)
                mp.add_forced_key_binding(key, "auth-trakt", activation)
            end
        end)
    end
end

mp.register_script_message("init_trakt_and_set_watched", handlemessage)
