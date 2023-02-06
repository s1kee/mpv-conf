--[[
Uses [guessit](https://github.com/guessit-io/guessit) to detect media title by filename.
Upon detection, sets `force-media-title` variable.
Useful for getting cleaner screenshot file names.

Script options can be specified in `script-opts/guess-media-title.conf` file.
If `show_detection_message` is set to `yes`, the script is going to show a flash message in OSD with a detected media title.

Requires `guessit` to be installed and runnable as `guessit` command.
--]]


local mp = require("mp")
local msg = require("mp.msg")
local utils = require("mp.utils")
local options = require("mp.options")


local opts = {
    show_detection_message = false
}

options.read_options(opts, "guess-media-title")


local function trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end


local function show_flash_message(text)
    local overlay = mp.create_osd_overlay("ass-events")
    overlay.data = "{\\a6\\fs14}" .. text
    overlay:update()

    mp.add_timeout(5, function()
        overlay:remove()
    end)
end


local function build_title(info)
    if info.type == "episode" and info.season ~= nil and info.episode ~= nil then
        local episode_spec = string.format("s%02de%02d", info.season, info.episode)
        return string.format("%s (%s)", info.title, episode_spec)
    else
        return info.title
    end
end


local function on_done(success, result, error)
    if not success then
        msg.error("failed to guess media title: " .. error)
		mp.set_property("force-media-title", mp.get_property("media-title"))
        return
    end

    local media_title = build_title(utils.parse_json(trim(result.stdout)))

    if media_title ~= nil then
        mp.set_property("force-media-title", media_title)

        if opts.show_detection_message then
            show_flash_message("Detected media title: {\\b1}" .. media_title)
        end
    end
end


local function guess_media_title()
    mp.set_property("force-media-title", mp.get_property("media-title"))
    mp.command_native_async({
        name = "subprocess",
        capture_stdout = true,
        args = { "guessit", "--json", mp.get_property_native("filename") }
    }, on_done)
end


mp.register_event("file-loaded", guess_media_title)
