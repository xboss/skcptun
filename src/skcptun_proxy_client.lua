package.path = package.path .. ";../src/?.lua;"

local selector = require "skcptun_selector"
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

local T_UP_CID = selector.t_up_cid
local T_UP_SND = selector.t_up_snd
local T_UP_RTT = selector.t_up_rtt

local g_etcp = nil


skt.cb.on_init = function(loop)
    for i = 1, skt.conf.skcp_conf_list_cnt, 1 do
        local skcp, err = skt.api.skcp_init(skt.conf.skcp_conf_list[i].raw, loop, 2)
        if not skcp then
            ERR("skcp_init " .. err);
            return
        end
        local udp_fd = skt.api.get_from_skcp(skcp, "fd")
        selector.add(udp_fd, skcp, skt.conf.skcp_conf_list[i])
    end

    local err = nil

    g_etcp, err = skt.api.etcp_server_init(skt.conf.etcp_serv_conf.raw, loop)
    if not g_etcp then
        ERR("etcp_server_init " .. err);
        return
    end

    DBG("on_init ok")
end

skt.cb.on_skcp_recv_cid = function(skcp, cid)
    DBG("recv cid: " .. cid)
    local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    selector.update(T_UP_CID, udp_fd, cid, 0)
    -- g_cid = cid
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
        -- sp.dump_table(msg)
        -- "D\nfd\ndata
        local pm = nil
        pm, err = utils.parse_msg(payload)
        if not pm then
            ERR("on_skcp_recv_data", err);
            return
        end

        local tcp_fd = pm.tcp_fd
        local cmd = pm.cmd
        if cmd == "C" then
            -- close tcp connection
            skt.api.etcp_server_close_conn(g_etcp, tcp_fd, 1)
        elseif cmd == "D" then
            local data = pm.data
            if not data then
                ERR("on_skcp_recv_data payload error")
                return
            end

            local rt = nil
            rt, err = skt.api.etcp_server_send(g_etcp, tcp_fd, data);
            if not rt then
                ERR("etcp_server_send " .. err)
                return
            end
            -- DBG("on_skcp_recv_data rt: " .. rt)
        end
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
        local udp_fd = skt.api.get_from_skcp(skcp, "fd")
        selector.update(T_UP_RTT, udp_fd, 0, now - snd_time)
        return
    end
end

skt.cb.on_skcp_close = function(skcp, cid)
    ERR("on_skcp_close cid: " .. cid)
    local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    selector.update(T_UP_CID, udp_fd, 0, 0)
end

skt.cb.on_tcp_accept = function(fd)
    -- DBG("on_tcp_accept in lua fd: " .. fd)
    -- format: "cmd(1B)\nfd"
    local payload = "A\n" .. fd
    local chan = selector.select(fd)
    -- DBG("select tcp_fd:", fd, "udp_fd:", chan.udp_fd, "avg_rtt", chan.avg_rtt)
    local buf = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, buf)
    if not rt then
        ERR("on_tcp_accept skcp_send " .. err)
        return
    end
    -- DBG("on_tcp_accept skcp_send ok rt: " .. rt)
end

skt.cb.on_tcp_recv = function(fd, buf)
    -- DBG("on_tcp_recv in lua fd: " .. fd)

    -- format: "cmd(1B)\nfd\ndata"
    local payload = "D\n" .. fd .. "\n" .. buf
    local chan = selector.select(fd)
    -- DBG("select tcp_fd:", fd, "udp_fd:", chan.udp_fd, "avg_rtt", chan.avg_rtt)
    local raw = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, raw)
    if not rt then
        ERR("on_tcp_recv skcp_send " .. err)
        return
    end
    -- DBG("on_tcp_recv skcp_send rt: " .. rt)
end

skt.cb.on_tcp_close = function(fd)
    -- DBG("on_tcp_close in lua fd: " .. fd)
    -- format: "cmd(1B)\nfd"
    local payload = "C\n" .. fd
    local chan = selector.select(fd)
    -- DBG("select tcp_fd:", fd, "udp_fd:", chan.udp_fd, "avg_rtt", chan.avg_rtt)
    local buf = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, buf)
    if not rt then
        ERR("on_tcp_close skcp_send " .. err)
        return
    end
    -- DBG("on_tcp_close skcp_send ok rt: " .. rt)
end

skt.cb.on_beat = function()
    for udp_fd, chan in pairs(selector.udp_fd_chan_map) do
        -- DBG("------ on_beat udp_fd cid", chan.udp_fd, chan.cid)
        if chan.cid <= 0 then
            skt.api.skcp_req_cid(chan.skcp, chan.skcp_conf.ticket)
            DBG("skcp_req_cid by beat_cb", chan.skcp_conf.ticket, chan.skcp)
            return
        end
        -- ping
        local now = skt.api.get_ms()
        local payload = "" .. now
        -- DBG("------ on_beat payload", payload)
        local raw = sp.pack(CMD_PING, payload, str_len(payload))
        -- DBG("------ on_beat raw ", raw)
        local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, raw)
        if not rt then
            ERR("on_beat skcp_send ping " .. err)
            return
        end
        selector.update(T_UP_SND, udp_fd, 0, 0)
        -- DBG("on_beat skcp_send ping ok rt: " .. rt)
    end
end
