-- To the extent possible under law, the author(s) have dedicated all copyright
-- and related and neighboring rights to this software to the public domain
-- worldwide. This software is distributed without any warranty. See
-- <https://creativecommons.org/publicdomain/zero/1.0/> for a copy of the CC0
-- Public Domain Dedication, which applies to this software.

utils = require 'mp.utils'

function quit()
    local res = utils.subprocess({
		args = {"C:\Users\Therese\Documents\Portables\bat files\shim stop.bat"},
		cancellable = false,
	})
end

mp.add_key_binding('w', 'restart-on-quit', quit)
