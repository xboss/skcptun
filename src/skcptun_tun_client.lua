package.path = package.path .. ";../src/?.lua;"

-- local selector = require "skcptun_selector"
local utils = require "skcptun_utils"
local sp = require "skcptun_protocol"

local DBG = utils.debug
local ERR = utils.error

local str_byte = string.byte
local str_char = string.char
local str_sub = string.sub
local str_len = string.len
local str_find = string.find

local CMD_DATA = sp.cmd_data
local CMD_PING = sp.cmd_ping
local CMD_PONG = sp.cmd_pong

local g_skcp = nil
local g_cid = 0
-- local g_conf = skt.conf
local g_skcp_conf = skt.conf.skcp_conf_list[1]
local g_tun_fd = 0;


skt.cb.on_init = function(loop, tun_fd)
    g_tun_fd = tun_fd

    local err
    g_skcp, err = skt.api.skcp_init(g_skcp_conf.raw, loop, 2)
    if not g_skcp then
        ERR("skcp_init ", err);
        return
    end

    DBG("on_init ok")
end

skt.cb.on_skcp_recv_cid = function(skcp, cid)
    DBG("recv cid: " .. cid)
    -- local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    -- selector.update(T_UP_CID, udp_fd, cid, 0)
    g_cid = cid
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)
    -- DBG("on_skcp_recv_data cid:", cid, " buf:", buf)
    local msg, err = sp.unpack(buf)
    if not msg then
        ERR("on_skcp_recv_data unpack", err)
        return
    end

    -- TODO: auth ticket

    local payload = msg.payload
    if msg.cmd == CMD_DATA then
        local rt = nil
        rt, err = skt.api.tuntap_write(g_tun_fd, payload);
        if not rt then
            ERR("on_skcp_recv_data tuntap_write " .. err)
            return
        end
        -- DBG("on_skcp_recv_data rt: " .. rt)
        return
    end
    if msg.cmd == CMD_PONG then
        -- pong
        local snd_time = tonumber(payload)
        if not snd_time then
            ERR("send time is nil in pong")
            return
        end
        local now = skt.api.get_ms()
        -- DBG("rtt:", now - snd_time)
        return
    end
end

skt.cb.on_skcp_close = function(skcp, cid)
    ERR("on_skcp_close cid: " .. cid)
    -- local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    -- selector.update(T_UP_CID, udp_fd, 0, 0)
    g_cid = 0
end

skt.cb.on_beat = function()
    if g_cid <= 0 then
        skt.api.skcp_req_cid(g_skcp, g_skcp_conf.ticket)
        DBG("skcp_req_cid by beat_cb", g_skcp_conf.ticket, g_skcp)
        return
    end

    -- ping
    local now = skt.api.get_ms()
    local payload = "" .. now
    -- DBG("------ on_beat payload", payload)
    local raw = sp.pack(CMD_PING, payload, str_len(payload))
    -- DBG("------ on_beat raw ", raw)
    local rt, err = skt.api.skcp_send(g_skcp, g_cid, raw)
    if not rt then
        ERR("on_beat skcp_send ping ", err)
        return
    end
end

skt.cb.on_tun_read = function(buf)
    -- DBG("on_tun_read in lua buf: ", buf)
    if g_cid <= 0 then
        -- ERR("on_tun_read g_cid error")
        return
    end
    local raw = sp.pack(CMD_DATA, buf, str_len(buf))
    -- DBG("------ on_beat raw ", raw)
    local rt, err = skt.api.skcp_send(g_skcp, g_cid, raw)
    if not rt then
        ERR("on_tun_read skcp_send", err)
        return
    end
    -- DBG("on_tun_read rt", rt)
end
