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

local function load_json_str(str, desc)
    local retval = JSON:decode(str)
    dumptable("JSON " .. desc, retval)
    return retval
end

local function load_json(fname)
    local f = io.open(fname, "rb")
    if (f == nil) then
        return nil
    end

    local str = f:read("*all")
    f:close()

    return load_json_str(str, fname)
end


local keys = {}
function loadKey(basedir, level, password)
    if keys[level] ~= nil then
        return keys[level]
    end

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

            keys[level] = decrypted
            return decrypted
        end
    end

    return nil
end

local function showHint(basedir)
    local f = io.open(basedir .. "/.password.hint", "r")
    if (f == nil) then
        return
    end

    local str = f:read("*all")
    f:close()

    print("(hint is '" .. str .. "').")
end


function loadContents(basedir)
    return load_json(basedir .. "/contents.js");
end


-- Mainline!

--for i,v in ipairs(argv) do
--    print("argv[" .. i .. "] = " .. v)
--end

local basedir = "1Password/1Password.agilekeychain/data/default"  -- !!! FIXME

local password = argv[3]
if password == nil then
    showHint(basedir)
    io.write("password: ")
    password = io.read("*l")
end

if loadKey(basedir, "SL5", password) == nil then
    print("wrong password?\n")
    os.exit(1)
end

items = loadContents(basedir)
for i,v in ipairs(items) do
    if v[2] ~= "system.Tombstone" then  -- I guess those are dead items?
        local metadata = load_json(basedir .. "/" .. v[1] .. ".1password")
        if metadata ~= nil then
            local plaintext = decryptBase64UsingKey(metadata.encrypted, loadKey(basedir, metadata.securityLevel, password))
            if plaintext ~= nil then
                local secure = load_json_str(plaintext, v[1])
            end
        end
    end
end

-- end of 1pass.lua ...

