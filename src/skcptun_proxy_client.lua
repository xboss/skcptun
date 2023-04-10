package.path = package.path .. ";../src/?.lua;"

local selector = require "skcptun_selector"
local sp = require "skcptun_protocol"

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
            print("skcp_init " .. err);
            return
        end
        local udp_fd = skt.api.get_from_skcp(skcp, "fd")
        selector.add(udp_fd, skcp, skt.conf.skcp_conf_list[i])
    end

    local err = nil

    g_etcp, err = skt.api.etcp_server_init(skt.conf.etcp_serv_conf.raw, loop)
    if not g_etcp then
        print("etcp_server_init " .. err);
        return
    end

    ---------------------------------- test ----------------------------------

    -- local payload = "abcdefg"
    -- local buf = sp.pack(CMD_PING, payload, #payload)
    -- print("buf", buf)

    -- print("============")
    -- local msg, err = sp.unpack(buf)
    -- if not msg then
    --     print(err)
    --     return
    -- end
    -- local s = sp.dump_table(msg)

    print("on_init ok")
end

skt.cb.on_skcp_recv_cid = function(skcp, cid)
    print("recv cid: " .. cid)
    local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    selector.update(T_UP_CID, udp_fd, cid, 0)
    -- g_cid = cid
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)
    -- print("on_skcp_recv_data cid: " .. cid .. " buf:" .. buf)
    local msg, err = sp.unpack(buf)
    if not msg then
        print("on_skcp_recv_data unpack", err)
        return
    end

    -- TODO: auth ticket

    local payload = msg.payload
    if msg.cmd == CMD_DATA then
        -- sp.dump_table(msg)
        -- "D\nfd\ndata
        if str_len(payload) < 5 then
            print("on_skcp_recv_data payload error")
            return
        end
        local sep1 = str_find(payload, "\n", 1)
        local sep2 = str_find(payload, "\n", 3)
        if not sep1 or not sep2 then
            print("on_skcp_recv_data payload error")
            return
        end
        local sep1_idx = tonumber(sep1)
        local sep2_idx = tonumber(sep2)
        if sep2_idx - sep1_idx <= 1 then
            print("on_skcp_recv_data payload error")
            return
        end
        local tcp_fd = str_sub(payload, sep1_idx + 1, sep2_idx - 1)
        if not tcp_fd then
            print("on_skcp_recv_data tcp_fd error")
            return
        end
        local data = str_sub(payload, sep2_idx + 1)
        if not data then
            print("on_skcp_recv_data data error")
            return
        end
        local rt = nil
        rt, err = skt.api.etcp_server_send(g_etcp, tonumber(tcp_fd), data);
        if not rt then
            print("etcp_server_send " .. err)
            return
        end
        -- print("on_skcp_recv_data rt: " .. rt)
        return
    end
    if msg.cmd == CMD_PONG then
        -- pong
        local snd_time = tonumber(payload)
        if not snd_time then
            print("send time is nil in pong")
            return
        end
        local now = skt.api.get_ms()
        local udp_fd = skt.api.get_from_skcp(skcp, "fd")
        selector.update(T_UP_RTT, udp_fd, 0, now - snd_time)
        return
    end

    -- local rt, err = skt.api.etcp_server_send(g_etcp, g_fd, buf);
    -- if not rt then
    --     print("etcp_server_send " .. err)
    --     return
    -- end
    -- print("on_skcp_recv_data rt: " .. rt)
end

skt.cb.on_skcp_close = function(skcp, cid)
    print("on_skcp_close cid: " .. cid)
    local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    selector.update(T_UP_CID, udp_fd, 0, 0)
end

skt.cb.on_tcp_accept = function(fd)
    -- print("on_tcp_accept in lua fd: " .. fd)
    -- format: "cmd(1B)\nfd"
    local payload = "A\n" .. fd
    local chan = selector.select(fd)
    -- print("select tcp_fd:", fd, "udp_fd:", chan.udp_fd, "avg_rtt", chan.avg_rtt)
    local buf = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, buf)
    if not rt then
        print("on_tcp_accept skcp_send " .. err)
        return
    end
    -- print("on_tcp_accept skcp_send ok rt: " .. rt)
end

skt.cb.on_tcp_recv = function(fd, buf)
    -- print("on_tcp_recv in lua fd: " .. fd)

    -- format: "cmd(1B)\nfd\ndata"
    local payload = "D\n" .. fd .. "\n" .. buf
    local chan = selector.select(fd)
    -- print("select tcp_fd:", fd, "udp_fd:", chan.udp_fd, "avg_rtt", chan.avg_rtt)
    local raw = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, raw)
    if not rt then
        print("on_tcp_recv skcp_send " .. err)
        return
    end
    -- print("on_tcp_recv skcp_send rt: " .. rt)
end

skt.cb.on_tcp_close = function(fd)
    -- print("on_tcp_close in lua fd: " .. fd)
    -- format: "cmd(1B)\nfd"
    local payload = "C\n" .. fd
    local chan = selector.select(fd)
    -- print("select tcp_fd:", fd, "udp_fd:", chan.udp_fd, "avg_rtt", chan.avg_rtt)
    local buf = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, buf)
    if not rt then
        print("on_tcp_close skcp_send " .. err)
        return
    end
    -- print("on_tcp_close skcp_send ok rt: " .. rt)
end

skt.cb.on_beat = function()
    for udp_fd, chan in pairs(selector.udp_fd_chan_map) do
        -- print("------ on_beat udp_fd cid", chan.udp_fd, chan.cid)
        if chan.cid <= 0 then
            skt.api.skcp_req_cid(chan.skcp, chan.skcp_conf.ticket)
            print("skcp_req_cid by beat_cb", chan.skcp_conf.ticket, chan.skcp)
            return
        end
        -- ping
        local now = skt.api.get_ms()
        local payload = "" .. now
        -- print("------ on_beat payload", payload)
        local raw = sp.pack(CMD_PING, payload, str_len(payload))
        -- print("------ on_beat raw ", raw)
        local rt, err = skt.api.skcp_send(chan.skcp, chan.cid, raw)
        if not rt then
            print("on_beat skcp_send ping " .. err)
            return
        end
        selector.update(T_UP_SND, udp_fd, 0, 0)
        -- print("on_beat skcp_send ping ok rt: " .. rt)
    end


    -- TODO:
    -- print("beat in lua file cid: " .. g_cid)
    -- if g_cid == 0 then
    --     local ok, err = skt.api.skcp_req_cid(g_skcp, skt.conf.skcp_conf_list[1].ticket)
    --     if not ok then
    --         print("skcp_req_cid " .. err);
    --         return
    --     end
    -- end
end
