-- TCP client base on OpenResty.
-- The "tcp_cli_or.conf" is config file for this script.
-- Use: resty --main-include tcp_cli_or.conf tcp_cli.lua [addr] [port] [client_cnt]

local str_char = string.char
local str_byte = string.byte
local str_format = string.format
local str_sub = string.sub
local str_find = string.find
local str_lower = string.lower
local str_upper = string.upper
local tbl_insert = table.insert
local tbl_concat = table.concat

-- local msg_id = 0
local msg_cnt = 0

local function split(s, delimiter)
    local result = {}
    local from = 1
    local delim_from, delim_to = str_find(s, delimiter, from)
    while delim_from do
        tbl_insert(result, str_sub(s, from, delim_from - 1))
        from = delim_to + 1
        delim_from, delim_to = str_find(s, delimiter, from)
    end
    tbl_insert(result, str_sub(s, from))
    return result
end

------ client start ------
local t_cli = {
    host = nil,
    port = 0,
    is_running = false,
    sock = nil,
    sock_timeout = 60000,
    send_timeout = 60000,
    read_timeout = 60000,
    msg_id = 0,
}
function t_cli:new()
    return setmetatable({}, { __index = t_cli })
end

function t_cli:connect(host, port)
    self.sock = ngx.socket.tcp()
    ngx.log(ngx.DEBUG, "connect start")
    local ok, err = self.sock:connect(host, port)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect ", host, " : ", port, " ", err)
        return nil, err
    end
    self.sock:settimeouts(self.sock_timeout, self.send_timeout, self.read_timeout)
    self.is_running = true
    self.host = host
    self.port = port
    ngx.log(ngx.DEBUG, "successfully connected to " .. host .. " " .. port)
    return self.sock
end

function t_cli:send(o)
    if not self.sock or not self.is_running then
        ngx.log(ngx.WARN, "sock is closed")
        return nil, "sock is closed"
    end
    local now = ngx.now() * 1000
    local msg = self.msg_id .. " " .. now .. " " .. o
    -- ngx.log(ngx.DEBUG, " ", msg)
    local bytes, err = self.sock:send(msg)
    if not bytes then
        ngx.log(ngx.ERR, "send failed ", err)
        return nil, err
    end
    self.msg_id = self.msg_id + 1
    return bytes, err
end

function t_cli:send_loop()
    ngx.log(ngx.DEBUG, "send loop start ")

    local msg_padding = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"

    ::continue::
    while self.is_running do
        local bytes, err = self:send(msg_padding)
        if err == "timeout" then
            ngx.log(ngx.DEBUG, "recv read timeout")
            goto continue
        end
        if not bytes then
            ngx.log(ngx.ERR, "send loop error ", err)
            self.is_running = false
            return
        end

        if self.msg_id >= msg_cnt then
            ngx.log(ngx.DEBUG, "send msg_id:", self.msg_id, " msg_cnt:", msg_cnt)
            return
        end
    end
    self.is_running = false
    ngx.log(ngx.DEBUG, "send loop end ")
end

function t_cli:recv_loop()
    ngx.log(ngx.DEBUG, "recv loop start ")

    ::continue::
    while self.is_running do
        local msg, err = self.sock:receive('*l') --receiveany(1024)
        if err == "timeout" then
            ngx.log(ngx.DEBUG, "recv read timeout")
            goto continue
        end
        if not msg then
            ngx.log(ngx.ERR, "recv msg error ", err)
            self.is_running = false
            return
        end
        -- ngx.log(ngx.DEBUG, "recv: ", msg)

        local now = ngx.now() * 1000
        local parts = split(msg, " ")
        local sid = tonumber(parts[1])
        local stm = tonumber(parts[2])
        ngx.log(ngx.DEBUG, "stat: ", sid .. " " .. stm .. " " .. now .. " " .. now - stm)

        -- if self.msg_id > msg_cnt then
        --     ngx.log(ngx.DEBUG, "recv msg_id:", self.msg_id, " msg_cnt:", msg_cnt)
        --     self.is_running = false
        -- end
    end
    self.is_running = false
    ngx.log(ngx.DEBUG, "recv loop end ")
end

------ client end ------

local addr = arg[1] or "127.0.0.1"
local port = arg[2] or 1111
local client_cnt = arg[3] or 1
msg_cnt = tonumber(arg[4]) or 100

-- local cli_thread = {}

for i = 1, client_cnt do
    local cli = t_cli:new();
    local ok, err = cli:connect(addr, port);
    if not ok then
        ngx.log(ngx.ERR, "connect error ", err)
        return
    end
    ngx.thread.spawn(cli.recv_loop, cli)
    ngx.thread.spawn(cli.send_loop, cli)
end
