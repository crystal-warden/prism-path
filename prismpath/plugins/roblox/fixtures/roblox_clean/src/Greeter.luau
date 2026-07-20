--!strict
-- Pure core ModuleScript: no DataModel/Instance access, runnable under Lune.
local Greeter = {}

function Greeter.hello(name: string): string
	return "Hello, " .. name
end

return Greeter
