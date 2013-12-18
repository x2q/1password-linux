JSON = (loadfile "JSON.lua")()

local function dumptable(tabname, tab, depth)
    if depth == nil then  -- first call, before any recursion?
        depth = 1
    end

    if tabname ~= nil then
        if tab == nil then
            print(tabname .. " = nil")
            return
        else
            print(tabname .. " = {")
        end
    end

    local depthstr = ""
    for i=1,(depth*4) do
        depthstr = depthstr .. " "
    end

    if tab.DUMPTABLE_ITERATED then
        print(depthstr .. "(...circular reference...)")
    else
        tab.DUMPTABLE_ITERATED = true
        for k,v in pairs(tab) do
            if type(v) == "table" then
                print(depthstr .. tostring(k) .. " = {")
                dumptable(nil, v, depth + 1)
                print(depthstr .. "}")
            else
                if k ~= "DUMPTABLE_ITERATED" then
                    print(depthstr .. tostring(k) .. " = " .. tostring(v))
                end
            end
        end
        tab.DUMPTABLE_ITERATED = nil
    end

    if tabname ~= nil then
        print("}")
    end
end

local function load_json(fname)
    local f = io.open(fname, "rb")
    if (f == nil) then
        return nil
    end

    local str = f:read("*all")
    f:close()

    local retval = JSON:decode(str)
    dumptable("JSON " .. fname, retval)
    return retval
end


function loadKey(basedir, level, password)
    local keysjson = load_json(basedir .. "/encryptionKeys.js");
    if (keysjson == nil) or (keysjson[level] == nil) then
        return nil
    end

    local identifier = keysjson[level]
    for i,v in ipairs(keysjson.list) do
        if v.identifier == identifier then
			local iterations = v.iterations
            if (iterations == nil) or (iterations < 1000) then
			    iterations = 1000
            end

			local decrypted = decryptUsingPBKDF2(v.data, password, iterations)
			if decrypted == nil then
                return nil
            end

			local validate = decryptBase64UsingKey(v.validation, decrypted)
			if validate ~= decrypted then
                return nil
            end

            return decrypted
        end
    end

    return nil
end

function showHint(basedir)
    local f = io.open(basedir .. "/.password.hint", "r")
    if (f == nil) then
        return
    end

    local str = f:read("*all")
    f:close()

    print("(hint is '" .. str .. "').")
end

-- end of 1pass.lua ...

