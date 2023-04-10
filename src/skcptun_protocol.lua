--[[
protocol:
    protocol name(2B): "JJ"
    version(1B):0x01
    flg(1B):
    cmd(1B):
    payload length(4B):uint32
    payload(nB):
--]]
local str_byte = string.byte
local str_char = string.char
local str_sub = string.sub
local str_len = string.len

local NAME = "JJ"
local VERSION = 0x01
local CMD_DATA = 0x01
local CMD_PING = 0x02
local CMD_PONG = 0x03

local sp = {
    name = NAME,
    ver = VERSION,
    cmd_data = CMD_DATA,
    cmd_ping = CMD_PING,
    cmd_pong = CMD_PONG
}

sp.pack = function(cmd, payload, payload_len, flg, ver)
    flg = flg or 0x00
    ver = ver or VERSION
    -- print("pack payload_len:", payload_len)
    -- payload_len = skt.api.hton32(payload_len)
    -- local s1, s2, s3, s4 = skt.api.hton32(payload_len)
    -- print("pack str payload_len:", s1, s2, s3, s4)

    -- return NAME ..
    --     str_char(ver) .. str_char(flg) .. s1 .. s2 .. s3 .. s4 .. payload
    return NAME ..
        str_char(ver) .. str_char(flg) .. str_char(cmd) .. str_char(skt.api.band(skt.api.brshift(payload_len, 24), 0xff))
        .. str_char(skt.api.band(skt.api.brshift(payload_len, 16), 0xff))
        .. str_char(skt.api.band(skt.api.brshift(payload_len, 8), 0xff))
        .. str_char(skt.api.band(payload_len, 0xff)) .. payload
end

sp.unpack = function(buf)
    if not buf or str_len(buf) < 9 then
        return nil, "buf error"
    end
    local name = str_sub(buf, 1, 2)
    local ver, flg, cmd = str_byte(buf, 3, 5)
    if name ~= NAME then
        return nil, "name error"
    end
    if ver ~= VERSION then
        return nil, "version error"
    end
    if cmd ~= CMD_DATA and cmd ~= CMD_PING and cmd ~= CMD_PONG then
        return nil, "cmd error"
    end

    local len1, len2, len3, len4 = str_byte(buf, 6, 9)
    -- print("--- unpack", len1, len2, len3, len4)
    -- 计算剩余长度
    local payload_len = skt.api.bor(skt.api.blshift(len1, 24),
        skt.api.bor(skt.api.blshift(len2, 16), skt.api.bor(skt.api.blshift(len3, 8), len4)))
    -- payload_len = skt.api.ntoh32(payload_len)
    -- print("unpack payload_len:", payload_len)
    local payload = nil
    if payload_len > 0 then
        payload = str_sub(buf, 10, 10 + payload_len)
    end

    return {
        name = name,
        ver = ver,
        flg = flg,
        cmd = cmd,
        payload_len = payload_len,
        payload = payload
    }
end

sp.dump_table = function(val)
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

return sp


---------- test ----------

-- local payload = "abcdefg"
-- local buf = sp.pack(sp.cmd_ping, payload, #payload)
-- -- print("buf", buf)

-- print("============")
-- local msg, err = sp.unpack(buf)
-- if not msg then
--     print(err)
--     return
-- end
-- local s = dump_table(msg)
-- print("============")
-- print(s)
