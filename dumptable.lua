function dumptable(tabname, tab, depth)
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

