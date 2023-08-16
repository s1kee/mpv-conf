function callback(success, result, error)
    if success then
        mp.osd_message("Rate Episode", 1)
    else
        mp.osd_message("Failed to activate Python script", 3)
    end
	if was_ontop then mp.set_property_native("ontop", true) end
end

function activate_script()
	local was_ontop = mp.get_property_native("ontop")
	if was_ontop then mp.set_property_native("ontop", false) 
	end
	
    local script_dir = debug.getinfo(1).source:match("@?(.*/)")
    local python_cmd = string.format('start /MIN "" cmd /C "python "%s/rating.py" --activate"', script_dir)
    local success = os.execute(python_cmd)
	
    if success then
        callback(true, { status = 0 })
    else
        callback(false, { status = -1 })
    end
end

-- Register the key binding
mp.add_key_binding('y', 'trakt-rating', function()
    mp.add_timeout(3, activate_script)
end)