local str_byte = string.byte
local str_char = string.char
local str_sub = string.sub
local str_len = string.len
local str_find = string.find

local utils = {}

utils.debug = function(...)
    print("DEBUG:", ...)
end

utils.error = function(...)
    print("ERROR:", ...)
end

utils.parse_msg = function(payload)
    -- format: "cmd\nfd[\ndata]"
    if str_len(payload) < 3 then
        return nil, "payload error"
    end

    local cmd = str_sub(payload, 1, 1)
    if cmd ~= "A" and cmd ~= "C" and cmd ~= "D" then
        return nil, "payload cmd error"
    end
    local sep1 = str_find(payload, "\n", 1)
    local sep2 = str_find(payload, "\n", 3)
    if not sep1 then
        return nil, "payload error"
    end
    local data = nil
    local tcp_fd = nil
    local sep1_idx = tonumber(sep1)
    if sep2 then
        -- 有data
        local sep2_idx = tonumber(sep2)
        if sep2_idx - sep1_idx <= 1 then
            return nil, "payload error"
        end
        tcp_fd = str_sub(payload, sep1_idx + 1, sep2_idx - 1)
        if not tcp_fd then
            return nil, "payload tcp_fd error"
        end
        data = str_sub(payload, sep2_idx + 1)
        if not data then
            return nil, "payload data error"
        end
    else
        -- 无data
        tcp_fd = str_sub(payload, sep1_idx + 1)
    end
    return { cmd = cmd, tcp_fd = tonumber(tcp_fd), data = data }, "ok"
end

utils.dump = function(val)
    local function loop(val, keyType, _indent)
        _indent = _indent or 1
        keyType = keyType or "string"
        local res = ""
        local indentStr = "     " -- 缩进空格
        local indent = string.rep(indentStr, _indent)
        local end_indent = string.rep(indentStr, _indent - 1)
        local putline = function(...)
            local arr = { res, ... }
            for i = 1, #arr do
                if type(arr[i]) ~= "string" then arr[i] = tostring(arr[i]) end
            end
            res = table.concat(arr)
        end

        if type(val) == "table" then
            putline("{ ")

            if #val > 0 then
                local index = 0
                local block = false

                for i = 1, #val do
                    local n = val[i]
                    if type(n) == "table" or type(n) == "function" then
                        block = true
                        break
                    end
                end

                if block then
                    for i = 1, #val do
                        local n = val[i]
                        index = index + 1
                        if index == 1 then putline("\n") end
                        putline(indent, loop(n, type(i), _indent + 1), "\n")
                        if index == #val then putline(end_indent) end
                    end
                else
                    for i = 1, #val do
                        local n = val[i]
                        index = index + 1
                        putline(loop(n, type(i), _indent + 1))
                    end
                end
            else
                putline("\n")
                for k, v in pairs(val) do
                    putline(indent, k, " = ", loop(v, type(k), _indent + 1), "\n")
                end
                putline(end_indent)
            end

            putline("}, ")
        elseif type(val) == "string" then
            val = string.gsub(val, "\a", "\\a") -- 响铃(BEL)
            val = string.gsub(val, "\b", "\\b") -- 退格(BS),将当前位置移到前一列
            val = string.gsub(val, "\f", "\\f") -- 换页(FF),将当前位置移到下页开头
            val = string.gsub(val, "\n", "\\n") -- 换行(LF),将当前位置移到下一行开头
            val = string.gsub(val, "\r", "\\r") -- 回车(CR),将当前位置移到本行开头
            val = string.gsub(val, "\t", "\\t") -- 水平指标(HT),(调用下一个TAB位置)
            val = string.gsub(val, "\v", "\\v") -- 垂直指标(VT)
            putline("\"", val, "\", ")
        elseif type(val) == "boolean" then
            putline(val and "true, " or "false, ")
        elseif type(val) == "function" then
            putline(tostring(val), ", ")
        elseif type(val) == "nil" then
            putline("nil, ")
        else
            putline(val, ", ")
        end

        return res
    end

    local res = loop(val)
    res = string.gsub(res, ",(%s*})", "%1")
    res = string.gsub(res, ",(%s*)$", "%1")
    res = string.gsub(res, "{%s+}", "{}")

    print(res)
    return res
end

return utils


-- ---------------------------------- test ---------------------------------- --
-- local rt, err = utils.parse_msg("A\n89\nfasdfasdfas")
-- if not rt then
--     utils.error(err)
--     return
-- end
-- utils.dump(rt)
