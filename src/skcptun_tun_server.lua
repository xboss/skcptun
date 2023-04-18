package.path = package.path .. ";../src/?.lua;"

-- local selector = require "skcptun_selector"
local utils = require "skcptun_utils"
local sp = require "skcptun_protocol"

local log_d = utils.debug
local log_i = utils.info
local log_w = utils.warn
local log_e = utils.error

local str_byte = string.byte
local str_char = string.char
local str_sub = string.sub
local str_len = string.len
local str_find = string.find

local CMD_DATA = sp.cmd_data
local CMD_PING = sp.cmd_ping
local CMD_PONG = sp.cmd_pong

local g_skcp = nil
-- local g_cid = 0
-- local g_conf = skt.conf
local g_skcp_conf = skt.conf.skcp_conf_list[1]
local g_tun_fd = 0;
-- src_ip->cid
local g_ip_cid_map = {}

local function get_src_ip(buf)
    -- ip fixed head 20B
    -- log_d("get_src_ip buf len", str_len(buf))
    local ip1 = str_sub(buf, 13, 13)
    local ip2 = str_sub(buf, 14, 14)
    local ip3 = str_sub(buf, 15, 15)
    local ip4 = str_sub(buf, 16, 16)
    local ip = str_byte(ip1) .. "." .. str_byte(ip2) .. "." .. str_byte(ip3) .. "." .. str_byte(ip4)
    -- log_d("src_ip:", src_ip, str_len(buf))
    return ip
end

local function get_dst_ip(buf)
    -- ip fixed head 20B
    -- log_d("get_src_ip buf len", str_len(buf))
    local ip1 = str_sub(buf, 17, 17)
    local ip2 = str_sub(buf, 18, 18)
    local ip3 = str_sub(buf, 19, 19)
    local ip4 = str_sub(buf, 20, 20)
    local ip = str_byte(ip1) .. "." .. str_byte(ip2) .. "." .. str_byte(ip3) .. "." .. str_byte(ip4)
    -- log_d("src_ip:", src_ip, str_len(buf))
    return ip
end

skt.cb.on_init = function(loop, tun_fd)
    g_tun_fd = tun_fd

    local err
    g_skcp, err = skt.api.skcp_init(g_skcp_conf.raw, loop, 1)
    if not g_skcp then
        log_e("skcp_init ", err);
        return
    end

    log_i("start skcp server ok", "addr:", g_skcp_conf.addr, "port:", g_skcp_conf.port)
end

skt.cb.on_skcp_accept = function(skcp, cid)
    log_d("on_skcp_accept cid: " .. cid)
end

skt.cb.on_skcp_check_ticket = function(skcp, ticket)
    log_d("on_skcp_accept ticket: " .. ticket)
    return 0;
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)
    -- log_d("on_skcp_recv_data cid:", cid, " buf:", buf)
    local msg, err = sp.unpack(buf)
    if not msg then
        log_e("on_skcp_recv_data unpack", err)
        return
    end

    -- TODO: auth ticket

    local payload = msg.payload
    if msg.cmd == CMD_DATA then
        local src_ip = get_src_ip(payload)
        if not src_ip or str_len(src_ip) < 6 then
            log_e("on_skcp_recv_data invalid src ip")
            return
        end
        g_ip_cid_map[src_ip] = cid
        -- TODO:
        -- log_d("on_skcp_recv_data src_ip", src_ip, "dst_ip", get_dst_ip(payload))

        local rt = nil
        rt, err = skt.api.tuntap_write(g_tun_fd, payload);
        if not rt then
            log_e("on_skcp_recv_data tuntap_write " .. err)
            return
        end
        -- log_d("on_skcp_recv_data rt: " .. rt, g_tun_fd)
        return
    end
    if msg.cmd == CMD_PING then
        -- ping
        local raw = sp.pack(CMD_PONG, payload, str_len(payload))
        local rt = nil
        rt, err = skt.api.skcp_send(skcp, cid, raw)
        if not rt then
            log_e("on_beat skcp_send pong " .. err)
            return
        end
        return
    end
end

skt.cb.on_skcp_close = function(skcp, cid)
    log_e("on_skcp_close cid: " .. cid)
    -- TODO:
end

skt.cb.on_tun_read = function(buf)
    -- log_d("on_tun_read in lua buf: ", buf)
    local dst_ip = get_dst_ip(buf)
    if not dst_ip then
        log_e("on_skcp_recv_data invalid src ip")
        return
    end

    if dst_ip == "0.0.0.0" or dst_ip == "127.0.0.1" then
        -- local ip
        return
    end

    -- log_d("dst_ip:", dst_ip)
    -- utils.dump(g_ip_cid_map)
    -- log_d("on_tun_read src_ip", get_src_ip(buf), "dst_ip", dst_ip)
    local cid = g_ip_cid_map[dst_ip]

    if not cid then
        log_e("on_tun_read cid error")
        return
    end

    local raw = sp.pack(CMD_DATA, buf, str_len(buf))
    -- log_d("------ on_beat raw ", raw)
    local rt, err = skt.api.skcp_send(g_skcp, cid, raw)
    if not rt then
        log_e("on_tun_read skcp_send", err)
        return
    end
    -- log_d("on_tun_read rt", rt)
end
