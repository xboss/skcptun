local slt = {}

-- udp_fd -> chan
slt.udp_fd_chan_map = {}

-- anykey -> chan
slt.hold_map = {}

local RTT_MAX_CNT = 10
local T_UP_CID = 1
local T_UP_SND = 2
local T_UP_RTT = 3

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
            -- print("chg1 chan from " .. best_chan.udp_fd .. " to " .. min_chan.udp_fd)
            slt.best_chan = min_chan
            gc_hold_map()
        elseif best_chan.cid <= 0 then
            print("chg2 chan from " .. best_chan.udp_fd .. " to " .. min_chan.udp_fd)
            slt.best_chan = min_chan
            gc_hold_map()
        end
    end


    -- if cur_chan.udp_fd == best_chan.udp_fd then
    --     -- 不和自己比较
    --     return
    -- end
    -- print(cur_chan.udp_fd, " ", cur_chan.avg_rtt, " ", best_chan.udp_fd, " ", best_chan.avg_rtt);
    -- if best_chan.avg_rtt == -1 then
    --     print("firt chg chan from " .. best_chan.udp_fd .. " to " .. cur_chan.udp_fd)
    --     slt.best_chan = cur_chan
    -- end
    -- if cur_chan.avg_rtt < best_chan.avg_rtt then
    --     print("chg chan from " .. best_chan.udp_fd .. " to " .. cur_chan.udp_fd)
    --     slt.best_chan = cur_chan
    --     -- 清理 hold_map
    --     -- for key, chan in pairs(slt.hold_map) do
    --     --     if chan.cid <= 0 then
    --     --         slt.hold_map[key] = nil
    --     --     end
    --     -- end
    -- end
end

slt.add = function(udp_fd, skcp)
    if slt.udp_fd_chan_map[udp_fd] then
        return
    end

    local chan = {
        udp_fd = udp_fd,
        skcp = skcp,
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
    slt.best_chan = chan
end

slt.update = function(type, udp_fd, cid, rtt)
    if type < 1 and type > 3 then
        print("type: " .. type .. " error")
        return
    end
    if not slt.udp_fd_chan_map[udp_fd] then
        print("udp_fd: " .. udp_fd .. " does not exist")
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
end

slt.select = function(key)
    if not key then
        return slt.best_chan
    end

    local hold_chan = slt.hold_map[key]
    if hold_chan and hold_chan.cid > 0 then
        return hold_chan
    end
    if hold_chan and hold_chan.cid <= 0 then
        slt.hold_map[key] = nil
    end
    slt.hold_map[key] = slt.best_chan
    return slt.hold_map[key]
end

return slt

---------- test ----------
-- local function dump_table(val)
--     local function loop(val, keyType, _indent)
--         _indent = _indent or 1
--         keyType = keyType or "string"
--         local res = ""
--         local indentStr = "     " -- 缩进空格
--         local indent = string.rep(indentStr, _indent)
--         local end_indent = string.rep(indentStr, _indent - 1)
--         local putline = function(...)
--             local arr = { res, ... }
--             for i = 1, #arr do
--                 if type(arr[i]) ~= "string" then arr[i] = tostring(arr[i]) end
--             end
--             res = table.concat(arr)
--         end

--         if type(val) == "table" then
--             putline("{ ")

--             if #val > 0 then
--                 local index = 0
--                 local block = false

--                 for i = 1, #val do
--                     local n = val[i]
--                     if type(n) == "table" or type(n) == "function" then
--                         block = true
--                         break
--                     end
--                 end

--                 if block then
--                     for i = 1, #val do
--                         local n = val[i]
--                         index = index + 1
--                         if index == 1 then putline("\n") end
--                         putline(indent, loop(n, type(i), _indent + 1), "\n")
--                         if index == #val then putline(end_indent) end
--                     end
--                 else
--                     for i = 1, #val do
--                         local n = val[i]
--                         index = index + 1
--                         putline(loop(n, type(i), _indent + 1))
--                     end
--                 end
--             else
--                 putline("\n")
--                 for k, v in pairs(val) do
--                     putline(indent, k, " = ", loop(v, type(k), _indent + 1), "\n")
--                 end
--                 putline(end_indent)
--             end

--             putline("}, ")
--         elseif type(val) == "string" then
--             val = string.gsub(val, "\a", "\\a") -- 响铃(BEL)
--             val = string.gsub(val, "\b", "\\b") -- 退格(BS),将当前位置移到前一列
--             val = string.gsub(val, "\f", "\\f") -- 换页(FF),将当前位置移到下页开头
--             val = string.gsub(val, "\n", "\\n") -- 换行(LF),将当前位置移到下一行开头
--             val = string.gsub(val, "\r", "\\r") -- 回车(CR),将当前位置移到本行开头
--             val = string.gsub(val, "\t", "\\t") -- 水平指标(HT),(调用下一个TAB位置)
--             val = string.gsub(val, "\v", "\\v") -- 垂直指标(VT)
--             putline("\"", val, "\", ")
--         elseif type(val) == "boolean" then
--             putline(val and "true, " or "false, ")
--         elseif type(val) == "function" then
--             putline(tostring(val), ", ")
--         elseif type(val) == "nil" then
--             putline("nil, ")
--         else
--             putline(val, ", ")
--         end

--         return res
--     end

--     local res = loop(val)
--     res = string.gsub(res, ",(%s*})", "%1")
--     res = string.gsub(res, ",(%s*)$", "%1")
--     res = string.gsub(res, "{%s+}", "{}")

--     return res
-- end

-- for i = 1, 10, 1 do
--     slt.add(i, nil)
--     -- os.execute("sleep " .. 1)
-- end

-- print(#slt.udp_fd_chan_map)

-- for k = 1, 10, 1 do
--     for i = 1, 10, 1 do
--         print(">>>>>>>>>>>")
--         local udp_fd = i
--         local cid = math.random(5)
--         cid = cid - 1
--         local key = math.random(10)
--         print(cid, key)
--         slt.update(1, udp_fd, cid, 0)

--         for j = 1, 12, 1 do
--             slt.update(2, udp_fd, 0, 0)
--             -- os.execute("sleep " .. 1)
--             local rtt = math.random(10000)
--             slt.update(3, udp_fd, 0, rtt)
--         end


--         local chan = slt.select(key)
--     end
-- end


-- -- print("==========")
-- -- local s = dump_table(slt.hold_map)
-- -- print(s)
-- print("==========")
-- for key, value in pairs(slt.udp_fd_chan_map) do
--     print(key, " ", value.avg_rtt)
-- end

-- print("best ", slt.best_chan.udp_fd, " ", slt.best_chan.avg_rtt)
