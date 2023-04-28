local utils = require "skcptun_utils"

local log_d = utils.debug
local log_i = utils.info
local log_w = utils.warn
local log_e = utils.error

local slt = {}

local RTT_MAX_CNT = 10
local T_UP_CID = 1
local T_UP_SND = 2
local T_UP_RTT = 3

slt.t_up_cid = T_UP_CID
slt.t_up_snd = T_UP_SND
slt.t_up_rtt = T_UP_RTT

-- udp_fd -> chan
slt.udp_fd_chan_map = {}

-- anykey -> chan
slt.hold_map = {}



local function gc_hold_map()
    -- 清理 hold_map
    for key, chan in pairs(slt.hold_map) do
        if chan.cid <= 0 then
            slt.hold_map[key] = nil
        end
    end
end

local function cal_best_chan()
    local best_chan = slt.best_chan
    local min_chan = nil
    -- 先选出最小的活着的chan
    for udp_fd, chan in pairs(slt.udp_fd_chan_map) do
        if chan.cid > 0 then
            -- alive
            if not min_chan then
                min_chan = chan
            else
                if chan.avg_rtt < min_chan.avg_rtt then
                    min_chan = chan
                end
            end
        end
    end

    if min_chan then
        if min_chan.avg_rtt < best_chan.avg_rtt then
            -- log_d("chg1 chan from ", best_chan.udp_fd, " to ", min_chan.udp_fd, best_chan.avg_rtt, min_chan.avg_rtt)
            log_d("chg1 chan from ", best_chan.udp_fd, " to ", min_chan.udp_fd, best_chan.avg_rtt, min_chan.avg_rtt,
                best_chan.pkt_snd, best_chan.pkt_recv)
            slt.best_chan = min_chan
            gc_hold_map()
        elseif best_chan.cid <= 0 then
            log_d("chg2 chan from ", best_chan.udp_fd, " to ", min_chan.udp_fd, best_chan.avg_rtt, min_chan.avg_rtt)
            slt.best_chan = min_chan
            gc_hold_map()
        end
    end
end

slt.add = function(udp_fd, skcp, skcp_conf)
    if slt.udp_fd_chan_map[udp_fd] then
        return
    end

    local chan = {
        udp_fd = udp_fd,
        skcp = skcp,
        skcp_conf = skcp_conf,
        cid = 0,
        rtt = {},
        min_rtt = 999999999,
        max_rtt = 0,
        avg_rtt = 9999,
        pkt_snd = 0,
        pkt_recv = 0,
        rtt_idx = 0,
        up_time = os.time()
    }

    slt.udp_fd_chan_map[udp_fd] = chan
    if not slt.best_chan then
        slt.best_chan = chan
    end
end

slt.update = function(type, udp_fd, cid, rtt)
    if type < 1 and type > 3 then
        log_e("type: " .. type .. " error")
        return
    end
    if not slt.udp_fd_chan_map[udp_fd] then
        log_e("udp_fd: " .. udp_fd .. " does not exist")
        return
    end
    local chan = slt.udp_fd_chan_map[udp_fd]
    chan.up_time = os.time()
    if type == T_UP_SND then
        -- update sending
        chan.pkt_snd = chan.pkt_snd + 1
    elseif type == T_UP_CID then
        -- update cid
        chan.cid = cid
    elseif type == T_UP_RTT then
        -- update rtt
        chan.pkt_recv = chan.pkt_recv + 1
        chan.rtt[chan.rtt_idx + 1] = rtt;
        chan.rtt_idx = chan.rtt_idx + 1
        chan.rtt_idx = chan.rtt_idx % RTT_MAX_CNT;

        local sum_rtt = 0
        local rtt_cnt = 0
        for i = 1, RTT_MAX_CNT, 1 do
            local rtt_tmp = chan.rtt[i]
            if rtt_tmp then
                sum_rtt = sum_rtt + rtt_tmp;
                if chan.max_rtt < rtt_tmp then
                    chan.max_rtt = rtt_tmp
                end
                if chan.min_rtt > rtt_tmp then
                    chan.min_rtt = rtt_tmp
                end
                rtt_cnt = rtt_cnt + 1
            end
        end

        if rtt_cnt > 0 then
            -- chan.avg_rtt = sum_rtt / rtt_cnt
            chan.avg_rtt = math.floor(sum_rtt / rtt_cnt)
        end

        if chan.pkt_snd > 99999999 or chan.pkt_recv > 99999999 then
            chan.pkt_snd = 0;
            chan.pkt_recv = 0;
        end

        -- 计算最优channel
        cal_best_chan()
    end
    -- log_d("chan:", chan.udp_fd, chan.cid, chan.avg_rtt, chan.pkt_snd, chan.pkt_recv)
end

slt.select = function(key)
    if not key then
        return slt.best_chan
    end

    local hold_chan = slt.hold_map[key]
    if hold_chan and hold_chan.cid > 0 then
        -- log_d("select hit hold_map", key)
        return hold_chan
    end
    if hold_chan and hold_chan.cid <= 0 then
        -- log_d("select remove hold_map", key)
        slt.hold_map[key] = nil
    end
    slt.hold_map[key] = slt.best_chan
    return slt.hold_map[key]
end

return slt

---------- test ----------
