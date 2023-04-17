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
    -- 计算剩余长度
    local payload_len = skt.api.bor(skt.api.blshift(len1, 24),
        skt.api.bor(skt.api.blshift(len2, 16), skt.api.bor(skt.api.blshift(len3, 8), len4)))
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
