package.path = package.path .. ";../src/?.lua;"

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

local tcp_target_addr = skt.conf.tcp_target_addr
local tcp_target_port = skt.conf.tcp_target_port

-- local g_skcp = nil
-- local g_cid = 0

-- udp_fd_ct_fd->st_fd
local g_ct_st_fd_map = {}

-- udp_fd_cid->st_fd[n]
local g_cid_st_fd_map = {}

-- st_fd->{skcp, udp_fd, cid, ct_fd, st_fd}
local g_tcp_skcp_map = {}

local g_etcp = nil

local g_test_dump_cnt = 0
local function dump_gt(tag)
    g_test_dump_cnt = g_test_dump_cnt + 1
    if g_test_dump_cnt >= 99999999 then
        g_test_dump_cnt = 0
    end

    if g_test_dump_cnt % 30 ~= 1 then
        return;
    end
    if tag then
        DBG(tag)
    end
    DBG("=====g_ct_st_fd_map=====")
    utils.dump(g_ct_st_fd_map)
    DBG("=====g_cid_st_fd_map=====")
    utils.dump(g_cid_st_fd_map)
    DBG("=====g_tcp_skcp_map=====")
    utils.dump(g_tcp_skcp_map)
end

skt.cb.on_init = function(loop)
    for i = 1, skt.conf.skcp_conf_list_cnt, 1 do
        local skcp, err = skt.api.skcp_init(skt.conf.skcp_conf_list[i].raw, loop, 1)
        if not skcp then
            ERR("skcp_init " .. err);
            return
        end
        -- DBG("skcp_init ok", i)
    end

    local err = nil
    g_etcp, err = skt.api.etcp_client_init(skt.conf.etcp_cli_conf.raw, loop)
    if not g_etcp then
        ERR("etcp_client_init " .. err);
        return
    end

    DBG("on_init ok")
end

skt.cb.on_skcp_accept = function(skcp, cid)
    DBG("on_skcp_accept cid: " .. cid)
end

skt.cb.on_skcp_check_ticket = function(skcp, ticket)
    DBG("on_skcp_accept ticket: " .. ticket)
    return 0;
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)
    -- DBG("on_skcp_recv_data cid: " .. cid .. " buf:" .. buf)

    local msg, err = sp.unpack(buf)
    if not msg then
        ERR("on_skcp_recv_data unpack", err)
        return
    end

    -- TODO: auth ticket

    local udp_fd = skt.api.get_from_skcp(skcp, "fd")

    local payload = msg.payload
    if msg.cmd == CMD_DATA then
        if msg.payload_len <= 0 then
            ERR("on_skcp_recv_data payload_len error", msg.payload_len)
            return
        end
        -- format: "cmd\nfd\ndata"
        local pm = nil
        pm, err = utils.parse_msg(payload)
        if not pm then
            ERR("on_skcp_recv_data", err);
            return
        end

        local ct_fd = pm.tcp_fd
        local cmd = pm.cmd
        local data = pm.data
        if cmd == "A" then
            -- new tcp connection
            local st_fd = nil
            st_fd, err = skt.api.etcp_client_create_conn(g_etcp, tcp_target_addr, tcp_target_port)
            if not st_fd then
                ERR("on_skcp_recv_data accept", err)
                return;
            end
            g_tcp_skcp_map[st_fd] = { skcp = skcp, udp_fd = udp_fd, cid = cid, ct_fd = ct_fd, st_fd = st_fd }
            g_ct_st_fd_map[udp_fd .. "_" .. ct_fd] = st_fd
            if not g_cid_st_fd_map[udp_fd .. "_" .. cid] then
                g_cid_st_fd_map[udp_fd .. "_" .. cid] = {}
                g_cid_st_fd_map[udp_fd .. "_" .. cid].size = 0
            end
            g_cid_st_fd_map[udp_fd .. "_" .. cid][st_fd] = st_fd
            g_cid_st_fd_map[udp_fd .. "_" .. cid].size = g_cid_st_fd_map[udp_fd .. "_" .. cid].size + 1
            -- dump_gt("accept>>>>>>>>>>>")
        elseif cmd == "C" then
            -- close tcp connection
            local st_fd = g_ct_st_fd_map[udp_fd .. "_" .. ct_fd]
            if not st_fd then
                ERR("on_skcp_recv_data close invalid ct_fd", ct_fd)
                return
            end
            skt.api.etcp_client_close_conn(g_etcp, st_fd, 1)
            g_ct_st_fd_map[udp_fd .. "_" .. ct_fd] = nil
            g_cid_st_fd_map[udp_fd .. "_" .. cid][st_fd] = nil
            g_cid_st_fd_map[udp_fd .. "_" .. cid].size = g_cid_st_fd_map[udp_fd .. "_" .. cid].size - 1
            g_tcp_skcp_map[st_fd] = nil
            if g_cid_st_fd_map[udp_fd .. "_" .. cid].size <= 0 then
                g_cid_st_fd_map[udp_fd .. "_" .. cid] = nil
            end
        elseif cmd == "D" then
            -- data
            if not data then
                ERR("on_skcp_recv_data invalid data", ct_fd)
                return
            end
            local st_fd = g_ct_st_fd_map[udp_fd .. "_" .. ct_fd]
            if not st_fd then
                ERR("on_skcp_recv_data data invalid ct_fd", ct_fd)
                return
            end
            local rt
            rt, err = skt.api.etcp_client_send(g_etcp, st_fd, data)
            if not rt then
                ERR("on_skcp_recv_data etcp_client_send error", ct_fd)
                return
            end
        end
        return
    end

    if msg.cmd == CMD_PING then
        local raw = sp.pack(CMD_PONG, payload, str_len(payload))
        local rt = nil
        rt, err = skt.api.skcp_send(skcp, cid, raw)
        if not rt then
            ERR("on_beat skcp_send pong " .. err)
            return
        end
        dump_gt("ping>>>>>>>>>>>")
        return
    end
end

skt.cb.on_skcp_close = function(skcp, cid)
    DBG("on_skcp_close cid: " .. cid)
    local udp_fd = skt.api.get_from_skcp(skcp, "fd")
    local t = g_cid_st_fd_map[udp_fd .. "_" .. cid]
    if t then
        for k, v in pairs(t) do
            if v then
                t[k] = nil
                local item = g_tcp_skcp_map[k]
                if item then
                    g_ct_st_fd_map[udp_fd .. "_" .. item.ct_fd] = nil
                    g_tcp_skcp_map[k] = nil
                end
            end
        end
        g_cid_st_fd_map[udp_fd .. "_" .. cid] = nil
    end
    -- dump_gt("on_skcp_close>>>>>>>>>>>")
end

skt.cb.on_tcp_recv = function(fd, buf)
    -- DBG("on_tcp_recv in lua fd: " .. fd)
    local item = g_tcp_skcp_map[fd]
    if not item then
        ERR("on_tcp_recv invalid fd", fd)
        return
    end
    local payload = "D\n" .. item.ct_fd .. "\n" .. buf
    local raw = sp.pack(CMD_DATA, payload, str_len(payload))
    local rt, err = skt.api.skcp_send(item.skcp, item.cid, raw);
    if not rt then
        ERR("on_tcp_recv skcp_send", err)
        return
    end
end

skt.cb.on_tcp_close = function(fd)
    -- DBG("on_tcp_close in lua fd: " .. fd)
    local item = g_tcp_skcp_map[fd]
    if not item then
        ERR("on_tcp_close invalid fd", fd)
        return
    end
    g_ct_st_fd_map[item.udp_fd .. "_" .. item.ct_fd] = nil
    g_cid_st_fd_map[item.udp_fd .. "_" .. item.cid][fd] = nil
    g_cid_st_fd_map[item.udp_fd .. "_" .. item.cid].size = g_cid_st_fd_map[item.udp_fd .. "_" .. item.cid].size - 1
    g_tcp_skcp_map[fd] = nil

    if g_cid_st_fd_map[item.udp_fd .. "_" .. item.cid].size <= 0 then
        g_cid_st_fd_map[item.udp_fd .. "_" .. item.cid] = nil
    end
end
