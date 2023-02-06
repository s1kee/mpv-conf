local should_display = false

mp.add_periodic_timer(1, function()
    if mp.get_property_number"percent-pos" <= 80 then
        should_display = true
    elseif should_display then
        mp.osd_message("You've watched over 80% of the video.", "3")
        should_display = false
    end
end)