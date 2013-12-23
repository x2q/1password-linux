JSON = (loadfile "JSON.lua")()
dofile("dumptable.lua")

local passwordTypeNameMap = {
    ["webforms.WebForm"] = "Logins",
    ["wallet.financial.CreditCard"] = "Credit cards",
    ["passwords.Password"] = "Passwords",
    ["wallet.financial.BankAccountUS"] = "Bank accounts",
    ["wallet.membership.Membership"] = "Memberships",
    ["wallet.government.DriversLicense"] = "Drivers licenses",
    ["system.Tombstone"] = "Dead items",
    -- !!! FIXME: more!
}

local passwordTypeOrdering = {
    "webforms.WebForm",
    "wallet.financial.CreditCard",
    "passwords.Password",
    "wallet.financial.BankAccountUS",
    "wallet.membership.Membership",
    "wallet.government.DriversLicense",
    -- never show "system.Tombstone",
    -- !!! FIXME: more!
}

local function load_json_str(str, desc)
    local retval = JSON:decode(str)
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

    local keysjson = load_json(basedir .. "/encryptionKeys.js")
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

local function getHint(basedir)
    local f = io.open(basedir .. "/.password.hint", "r")
    if (f == nil) then
        return
    end

    local str = "(hint is '" .. f:read("*all") .. "')."
    f:close()
    --print(str)
    return str
end


function loadContents(basedir)
    return load_json(basedir .. "/contents.js")
end

local function build_secret_menuitem(menu, type, str, hidden)
    if str == nil then
        return nil
    end

    local valuestr = str
    if hidden == true then
        valuestr = "*****"
    end
    local text = type .. " " .. valuestr

    local callback = function()
        copyToClipboard(str)
        --print("Copied data [" .. str .. "] to clipboard.")
    end
    return appendGuiMenuItem(menu, text, callback)
end


local secret_menuitem_builders = {}

local function build_secret_menuitem_webform(menu, info, secure)
    local addthis = false
    local username = nil
    local password = nil
    local email = nil
    for i,v in ipairs(secure.fields) do
        --print(info.name .. ": " .. v.type .. ", " .. v.value)
        local ignored = false
        if (v.type == "P") and (password == nil) and (v.value ~= "") then
            password = v.value
        elseif (v.type == "T") and (usenname == nil) and (v.value ~= "") then
            username = v.value
        elseif (v.type == "E") and (email == nil) and (v.value ~= "") then
            email = v.value
        else
            ignored = true
        end

        if not ignored then
            addthis = true
        end
    end

    if addthis then
        if (username ~= nil) and (email ~= nil) and (email == username) then
            email = nil
        end

        build_secret_menuitem(menu, "username", username)
        build_secret_menuitem(menu, "email", email)
        build_secret_menuitem(menu, "password", password, true)
    end
end
secret_menuitem_builders["webforms.WebForm"] = build_secret_menuitem_webform


local function build_secret_menuitem_password(menu, info, secure)
    build_secret_menuitem(menu, "password", secure.password, true)
end
secret_menuitem_builders["passwords.Password"] = build_secret_menuitem_password


local function build_secret_menuitem_bankacctus(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    build_secret_menuitem(menu, "Account type", secure.accountType)
    build_secret_menuitem(menu, "Routing number", secure.routingNo)
    build_secret_menuitem(menu, "Account number", secure.accountNo)
    build_secret_menuitem(menu, "Bank name", secure.bankName)
    build_secret_menuitem(menu, "Owner", secure.owner)
end
secret_menuitem_builders["wallet.financial.BankAccountUS"] = build_secret_menuitem_bankacctus


local function build_secret_menuitem_driverslic(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    local birthdate = secure.birthdate_yy .. "/" .. string.sub("00" .. secure.birthdate_mm, -2) .. "/" .. string.sub("00" .. secure.birthdate_dd, -2)
    local expiredate = secure.expiry_date_yy .. "/" .. string.sub("00" .. secure.expiry_date_mm, -2)
    build_secret_menuitem(menu, "License number", secure.number)
    build_secret_menuitem(menu, "Class", secure.class)
    build_secret_menuitem(menu, "Expires", expiredate)
    build_secret_menuitem(menu, "State", secure.state)
    build_secret_menuitem(menu, "Country", secure.country)
    build_secret_menuitem(menu, "Conditions", secure.conditions)
    build_secret_menuitem(menu, "Full name", secure.fullname)
    build_secret_menuitem(menu, "Address", secure.address)
    build_secret_menuitem(menu, "Gender", secure.sex)
    build_secret_menuitem(menu, "Birthdate", birthdate)
    build_secret_menuitem(menu, "Height", secure.height)
end
secret_menuitem_builders["wallet.government.DriversLicense"] = build_secret_menuitem_driverslic


local function build_secret_menuitem_membership(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    build_secret_menuitem(menu, "Membership number", secure.membership_no)
end
secret_menuitem_builders["wallet.membership.Membership"] = build_secret_menuitem_membership


local function build_secret_menuitem_creditcard(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    local expiredate = secure.expiry_yy .. "/" .. string.sub("00" .. secure.expiry_mm, -2)
    build_secret_menuitem(menu, "Type", secure.type)
    build_secret_menuitem(menu, "CC number", secure.ccnum, true)
    build_secret_menuitem(menu, "CVV", secure.cvv, true)
    build_secret_menuitem(menu, "Expires", secure.expirydate)
    build_secret_menuitem(menu, "Card holder", secure.cardholder)
    build_secret_menuitem(menu, "Bank", secure.bank)
end
secret_menuitem_builders["wallet.financial.CreditCard"] = build_secret_menuitem_creditcard


local function build_secret_menuitems(basedir, info, menu, password)
    local metadata = load_json(basedir .. "/" .. info.uuid .. ".1password")
    if metadata == nil then
        return
    end

    local plaintext = decryptBase64UsingKey(metadata.encrypted, loadKey(basedir, metadata.securityLevel, password))
    if plaintext == nil then
        return
    end

    local secure = load_json_str(plaintext, info.uuid)
    if secure == nil then
        return
    end
    --dumptable("secure " .. info.name, secure)

    local menuitem = appendGuiMenuItem(menu, info.name)

    if secret_menuitem_builders[info.type] == nil then
        print("WARNING: don't know how to handle items of type " .. info.type)
        dumptable("secure " .. info.type .. " (" .. info.name .. ")", secure)
        return
    end

    local submenu = makeGuiMenu()
    secret_menuitem_builders[info.type](submenu, info, secure)
    setGuiMenuItemSubmenu(menuitem, submenu)
end


-- Mainline!

--for i,v in ipairs(argv) do
--    print("argv[" .. i .. "] = " .. v)
--end

local basedir = "1Password/1Password.agilekeychain/data/default"  -- !!! FIXME

local password = argv[2]
while password == nil do
    password = runGuiPasswordPrompt(getHint(basedir))
    if password == nil then
        os.exit(1)
    end
    if loadKey(basedir, "SL5", password) == nil then
        password = nil  -- wrong password
        local start = os.time()  -- cook the CPU for three seconds.
        local now = start
        while os.difftime(now, start) < 3 do
            now = os.time()
        end
    end
end

local contents = loadContents(basedir)
local items = {}
for i,v in ipairs(contents) do
    local t = v[2]
    if items[t] == nil then
        items[t] = {}
    end
    local bucket = items[t]
    bucket[#bucket+1] = { uuid=v[1], type=t, name=v[3], url=v[4] }  -- !!! FIXME: there are more fields, don't know what they mean yet.
end
contents = nil

local topmenu = makeGuiMenu()
for orderi,type in ipairs(passwordTypeOrdering) do
    local bucket = items[type]
    local realname = passwordTypeNameMap[type]
    if realname == nil then
        realname = type
    end
    local menuitem = appendGuiMenuItem(topmenu, realname)
    local submenu = makeGuiMenu()
    table.sort(bucket, function(a, b) return a.name < b.name end)
    for i,v in pairs(bucket) do
        build_secret_menuitems(basedir, v, submenu, password)
    end
    setGuiMenuItemSubmenu(menuitem, submenu)
end

popupGuiMenu(topmenu)
giveControlToGui()

-- end of 1pass.lua ...

