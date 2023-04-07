#include <ev.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <unistd.h>

#include "easy_tcp.h"
#include "skcp.h"
#include "skt_api_lua.h"
#include "skt_config.h"
#include "skt_tuntap.h"
#include "skt_utils.h"

#define SKT_LUA_PUSH_CALLBACK_FUN(_v_fn_name)                 \
    int _m_rt_value = 0;                                      \
    do {                                                      \
        lua_getfield(g_ctx->L, -1, "cb");                     \
        if (!lua_istable(g_ctx->L, -1)) {                     \
            LOG_E("skt.cb is not table");                     \
            _m_rt_value = 1;                                  \
            break;                                            \
        }                                                     \
        lua_getfield(g_ctx->L, -1, (_v_fn_name));             \
        if (!lua_isfunction(g_ctx->L, -1)) {                  \
            LOG_E("skt.cb.%s is not function", (_v_fn_name)); \
            _m_rt_value = 1;                                  \
            break;                                            \
        }                                                     \
    } while (0);                                              \
    if (_m_rt_value != 0)

struct skt_s {
    lua_State *L;
    struct ev_loop *loop;
    int tun_fd;
    ///////////
    // skcp_t **skcp_list;
    // size_t skcp_list_cnt;
    // etcp_cli_t *etcp_cli;
    // etcp_serv_t *etcp_serv;
    ///////////
    skt_config_t *conf;
};
typedef struct skt_s skt_t;

static skt_t *g_ctx = NULL;

/* -------------------------------------------------------------------------- */
/*                                   common                                   */
/* -------------------------------------------------------------------------- */

static void sig_cb(struct ev_loop *loop, ev_signal *w, int revents) {
    LOG_I("sig_cb signal:%d", w->signum);
    if (w->signum == SIGPIPE) {
        return;
    }

    ev_break(loop, EVBREAK_ALL);
    LOG_I("sig_cb loop break all event ok");
}

static void usage(const char *msg) { printf("%s\n kcptun config_file\n", msg); }

static void finish() {
    if (!g_ctx) {
        return;
    }

    if (g_ctx->conf) {
        skt_free_conf(g_ctx->conf);
        g_ctx->conf = NULL;
    }

    if (g_ctx->L) {
        lua_settop(g_ctx->L, 0);
        lua_close(g_ctx->L);
        g_ctx->L = NULL;
    }

    if (g_ctx->tun_fd >= 0) {
        close(g_ctx->tun_fd);
        g_ctx->tun_fd = -1;
    }

    // if (g_ctx->etcp_cli) {
    //     etcp_free_client(g_ctx->etcp_cli);
    //     g_ctx->etcp_cli = NULL;
    // }

    // if (g_ctx->etcp_serv) {
    //     etcp_free_server(g_ctx->etcp_serv);
    //     g_ctx->etcp_serv = NULL;
    // }

    // if (g_ctx->skcp_list) {
    //     if (g_ctx->skcp_list_cnt > 0) {
    //         for (size_t i = 0; i < g_ctx->skcp_list_cnt; i++) {
    //             if (g_ctx->skcp_list[i]) {
    //                 skcp_free(g_ctx->skcp_list[i]);
    //                 g_ctx->skcp_list[i] = NULL;
    //             }
    //         }
    //     }
    //     FREE_IF(g_ctx->skcp_list);
    // }
}

static int lua_reg_config(lua_State *L) {
    if (!g_ctx->conf) {
        return -1;
    }
    lua_pushstring(L, "conf");  // key
    lua_gettable(L, -2);        // skt.conf table 压栈
    if (g_ctx->conf->mode) {
        lua_pushstring(L, g_ctx->conf->mode);  // value
        lua_setfield(L, -2, "mode");
    }

    if (g_ctx->conf->tun_ip) {
        lua_pushstring(L, g_ctx->conf->tun_ip);  // value
        lua_setfield(L, -2, "tun_ip");
    }

    if (g_ctx->conf->tun_mask) {
        lua_pushstring(L, g_ctx->conf->tun_mask);  // value
        lua_setfield(L, -2, "tun_mask");
    }

    if (g_ctx->conf->tcp_target_addr) {
        lua_pushstring(L, g_ctx->conf->tcp_target_addr);  // value
        lua_setfield(L, -2, "tcp_target_addr");
    }

    lua_pushinteger(L, g_ctx->conf->tcp_target_port);  // value
    lua_setfield(L, -2, "tcp_target_port");

    lua_pushinteger(L, g_ctx->conf->skcp_conf_list_cnt);  // value
    lua_setfield(L, -2, "skcp_conf_list_cnt");

    // skcp_conf_list
    lua_newtable(L);  // value
    lua_setfield(L, -2, "skcp_conf_list");
    lua_pushstring(L, "skcp_conf_list");  // key
    lua_gettable(L, -2);                  // skt.conf.skcp_conf_list table 压栈
    for (size_t i = 0; i < g_ctx->conf->skcp_conf_list_cnt; i++) {
        if (g_ctx->conf->skcp_conf_list[i]) {
            lua_pushinteger(L, i + 1);  // key
            lua_newtable(L);            // value
            lua_settable(L, -3);
            lua_pushinteger(L, i + 1);  // key
            lua_gettable(L, -2);        // skt.conf.skcp_conf_list[i] table 压栈

            lua_pushlightuserdata(L, g_ctx->conf->skcp_conf_list[i]);
            lua_setfield(L, -2, "raw");

            if (g_ctx->conf->skcp_conf_list[i]->addr) {
                lua_pushstring(L, g_ctx->conf->skcp_conf_list[i]->addr);  // value
                lua_setfield(L, -2, "addr");
            }

            lua_pushinteger(L, g_ctx->conf->skcp_conf_list[i]->port);  // value
            lua_setfield(L, -2, "port");

            lua_pushstring(L, g_ctx->conf->skcp_conf_list[i]->key);  // value
            lua_setfield(L, -2, "key");

            lua_pushstring(L, g_ctx->conf->skcp_conf_list[i]->ticket);  // value
            lua_setfield(L, -2, "ticket");

            lua_pushinteger(L, g_ctx->conf->skcp_conf_list[i]->max_conn_cnt);  // value
            lua_setfield(L, -2, "max_conn_cnt");

            lua_pop(L, 1);  // pop skcp_conf_list[i]
        }
    }
    lua_pop(L, 1);  // pop skcp_conf_list

    // etcp_serv_conf
    if (g_ctx->conf->etcp_serv_conf) {
        lua_newtable(L);  // value
        lua_setfield(L, -2, "etcp_serv_conf");
        lua_pushstring(L, "etcp_serv_conf");  // key
        lua_gettable(L, -2);                  // skt.conf.etcp_serv_conf table 压栈
        lua_pushlightuserdata(L, g_ctx->conf->etcp_serv_conf);
        lua_setfield(L, -2, "raw");
        if (g_ctx->conf->etcp_serv_conf->serv_addr) {
            lua_pushstring(L, g_ctx->conf->etcp_serv_conf->serv_addr);  // value
            lua_setfield(L, -2, "serv_addr");
        }
        lua_pushinteger(L, g_ctx->conf->etcp_serv_conf->serv_port);  // value
        lua_setfield(L, -2, "serv_port");
        lua_pop(L, 1);  // pop etcp_serv_conf
    }

    // etcp_cli_conf
    if (g_ctx->conf->etcp_cli_conf) {
        lua_newtable(L);  // value
        lua_setfield(L, -2, "etcp_cli_conf");
        lua_pushstring(L, "etcp_cli_conf");  // key
        lua_gettable(L, -2);                 // skt.conf.etcp_cli_conf table 压栈
        lua_pushlightuserdata(L, g_ctx->conf->etcp_cli_conf);
        lua_setfield(L, -2, "raw");
        if (g_ctx->conf->tcp_target_addr) {
            lua_pushstring(L, g_ctx->conf->tcp_target_addr);  // value
            lua_setfield(L, -2, "tcp_target_addr");
        }
        lua_pushinteger(L, g_ctx->conf->tcp_target_port);  // value
        lua_setfield(L, -2, "tcp_target_port");
        lua_pop(L, 1);  // pop etcp_cli_conf
    }

    lua_pop(L, 1);  // pop conf
    return 0;
}

static lua_State *init_lua(char *file_path) {
    lua_State *L = luaL_newstate();
    if (!L) {
        LOG_E("Init Lua VM error");
        lua_close(L);
        return NULL;
    }

    luaL_openlibs(L);

    int status = luaL_loadfile(L, file_path);
    if (status) {
        LOG_E("Couldn't load file when init lua vm %s", lua_tostring(L, -1));
        lua_close(L);
        return NULL;
    }

    lua_newtable(L);
    lua_setglobal(L, "skt");
    lua_getglobal(L, "skt");  // skt table 压栈
    lua_pushstring(L, "cb");  // key
    lua_newtable(L);          // value
    lua_settable(L, -3);
    lua_pushstring(L, "conf");  // key
    lua_newtable(L);            // value
    lua_settable(L, -3);
    lua_reg_config(L);
    // lua_pushstring(L, "cb");  // key
    // lua_gettable(L, -2);      // skt.cb table 压栈
    lua_pop(L, 1);

    int ret = lua_pcall(L, 0, 0, 0);
    if (ret != LUA_OK) {
        LOG_E("%s, when init lua vm", lua_tostring(L, -1));
        lua_close(L);
        return NULL;
    }

    return L;
}

static int init_vpn_cli() {
    char dev_name[32] = {0};
    int utunfd = skt_tuntap_open(dev_name, 32);

    if (utunfd == -1) {
        LOG_E("open tuntap error");
        return -1;
    }

    // 设置为非阻塞
    setnonblock(utunfd);

    skt_tuntap_setup(dev_name, g_ctx->conf->tun_ip, g_ctx->conf->tun_mask);

    return utunfd;
}

/* -------------------------------------------------------------------------- */
/*                                  callbacks                                 */
/* -------------------------------------------------------------------------- */

static int on_tcp_accept(int fd) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_tcp_accept") return 1;

    lua_pushinteger(g_ctx->L, fd);          // 自动弹出
    int rt = lua_pcall(g_ctx->L, 1, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_tcp_accept in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return 1;
    }
    lua_pop(g_ctx->L, 1);
    return 0;
}
static void on_tcp_recv(int fd, char *buf, int len) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_tcp_recv") return;
    lua_pushinteger(g_ctx->L, fd);          // 自动弹出
    lua_pushlstring(g_ctx->L, buf, len);    // 自动弹出
    int rt = lua_pcall(g_ctx->L, 2, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_tcp_recv in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
}
static void on_tcp_close(int fd) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_tcp_close") return;

    lua_pushinteger(g_ctx->L, fd);          // 自动弹出
    int rt = lua_pcall(g_ctx->L, 1, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_tcp_close in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
    return;
}
static void on_skcp_recv_cid(skcp_t *skcp, uint32_t cid) {
    LOG_I("on_skcp_recv_cid cid: %u", cid);

    SKT_LUA_PUSH_CALLBACK_FUN("on_skcp_recv_cid") return;

    lua_pushlightuserdata(g_ctx->L, skcp);  // 自动弹出
    lua_pushinteger(g_ctx->L, cid);         // 自动弹出
    int rt = lua_pcall(g_ctx->L, 2, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_skcp_recv_cid in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
}
static void on_skcp_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int len) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_skcp_recv_data") return;
    lua_pushlightuserdata(g_ctx->L, skcp);  // 自动弹出
    lua_pushinteger(g_ctx->L, cid);         // 自动弹出
    lua_pushlstring(g_ctx->L, buf, len);    // 自动弹出
    int rt = lua_pcall(g_ctx->L, 3, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_skcp_recv_data in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
}
static void on_skcp_close(skcp_t *skcp, uint32_t cid) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_skcp_close") return;

    lua_pushlightuserdata(g_ctx->L, skcp);  // 自动弹出
    lua_pushinteger(g_ctx->L, cid);         // 自动弹出
    int rt = lua_pcall(g_ctx->L, 2, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_skcp_close in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
}

static void on_skcp_accept(skcp_t *skcp, uint32_t cid) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_skcp_accept") return;

    lua_pushlightuserdata(g_ctx->L, skcp);  // 自动弹出
    lua_pushinteger(g_ctx->L, cid);         // 自动弹出
    int rt = lua_pcall(g_ctx->L, 2, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_skcp_accept in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
}

static int on_skcp_check_ticket(skcp_t *skcp, char *ticket, int len) {
    SKT_LUA_PUSH_CALLBACK_FUN("on_skcp_check_ticket") return -1;
    lua_pushlightuserdata(g_ctx->L, skcp);   // 自动弹出
    lua_pushlstring(g_ctx->L, ticket, len);  // 自动弹出
    int rt = lua_pcall(g_ctx->L, 2, 1, 0);   // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_skcp_check_ticket in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return -1;
    }
    int isnum = 0;
    int ret = lua_tointegerx(g_ctx->L, -1, &isnum);
    lua_pop(g_ctx->L, 1);
    if (!isnum) {
        LOG_E("return value is not integer, when call on_skcp_check_ticket in lua");
        lua_pop(g_ctx->L, 1);
        return -1;
    }

    lua_pop(g_ctx->L, 1);
    return ret;
}

static void on_beat(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("on_beat got invalid event");
        return;
    }

    SKT_LUA_PUSH_CALLBACK_FUN("on_beat") return;
    // lua_getfield(g_ctx->L, -1, "cb");  // skt.cb table 压栈
    // if (!lua_istable(g_ctx->L, -1)) {
    //     LOG_E("skt.cb is not table");
    //     return;
    // }

    // lua_getfield(g_ctx->L, -1, "on_beat");  // skt.cb.on_beat function 压栈， 会被lua_pcall自动弹出
    // if (!lua_isfunction(g_ctx->L, -1)) {
    //     LOG_E("skt.cb.on_beat is not function");
    //     return;
    // }

    int rt = lua_pcall(g_ctx->L, 0, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_beat in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    // LOG_I("stack top: %d, type: %d", lua_gettop(g_ctx->L), lua_type(g_ctx->L, -1));
    lua_pop(g_ctx->L, 1);
    // LOG_I("stack top: %d, type: %d", lua_gettop(g_ctx->L), lua_type(g_ctx->L, -1));
}

static void on_tun_read(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        LOG_E("on_tun_read got invalid event");
        return;
    }

    char buf[1500];
    int len = skt_tuntap_read(g_ctx->tun_fd, buf, 1500);
    if (len <= 0) {
        LOG_E("skt_tuntap_read error tun_fd: %d", g_ctx->tun_fd);
        return;
    }

    SKT_LUA_PUSH_CALLBACK_FUN("on_tun_read") return;

    lua_pushlstring(g_ctx->L, buf, len);    // 自动弹出
    int rt = lua_pcall(g_ctx->L, 1, 0, 0);  // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call skt_tuntap_read in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return;
    }
    lua_pop(g_ctx->L, 1);
}

static int on_init() {
    SKT_LUA_PUSH_CALLBACK_FUN("on_init") return -1;
    lua_pushlightuserdata(g_ctx->L, g_ctx->loop);  // 自动弹出
    int rt = lua_pcall(g_ctx->L, 1, 0, 0);         // 调用函数，调用完成以后，会将返回值压入栈中
    if (rt) {
        LOG_E("%s, when call on_init in lua", lua_tostring(g_ctx->L, -1));
        lua_pop(g_ctx->L, 2);
        return -1;
    }
    lua_pop(g_ctx->L, 1);

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                proxy client                                */
/* -------------------------------------------------------------------------- */

static int start_proxy_client() {
    // g_ctx->skcp_list_cnt = g_ctx->conf->skcp_conf_list_cnt;
    // g_ctx->skcp_list = (skcp_t **)calloc(g_ctx->skcp_list_cnt, sizeof(skcp_t *));
    // for (size_t i = 0; i < g_ctx->skcp_list_cnt; i++) {
    //     g_ctx->skcp_list[i] = skcp_init(g_ctx->conf->skcp_conf_list[i], g_ctx->loop, NULL, SKCP_MODE_CLI);
    //     if (!g_ctx->skcp_list[i]) {
    //         return -1;
    //     }
    //     g_ctx->conf->skcp_conf_list[i]->on_close = on_skcp_close;
    //     g_ctx->conf->skcp_conf_list[i]->on_recv_cid = on_skcp_recv_cid;
    //     g_ctx->conf->skcp_conf_list[i]->on_recv_data = on_skcp_recv_data;
    // }

    // g_ctx->etcp_serv = etcp_init_server(g_ctx->conf->etcp_serv_conf, g_ctx->loop, NULL);
    // if (!g_ctx->etcp_serv) {
    //     return -1;
    // }

    for (size_t i = 0; i < g_ctx->conf->skcp_conf_list_cnt; i++) {
        g_ctx->conf->skcp_conf_list[i]->on_close = on_skcp_close;
        g_ctx->conf->skcp_conf_list[i]->on_recv_cid = on_skcp_recv_cid;
        g_ctx->conf->skcp_conf_list[i]->on_recv_data = on_skcp_recv_data;
    }

    g_ctx->conf->etcp_serv_conf->on_accept = on_tcp_accept;
    g_ctx->conf->etcp_serv_conf->on_recv = on_tcp_recv;
    g_ctx->conf->etcp_serv_conf->on_close = on_tcp_close;

    if (on_init() != 0) {
        return -1;
    }

    // 定时
    struct ev_timer bt_watcher;
    ev_init(&bt_watcher, on_beat);
    ev_timer_set(&bt_watcher, 0, 1);
    ev_timer_start(g_ctx->loop, &bt_watcher);

    LOG_D("proxy client loop run");
    ev_run(g_ctx->loop, 0);
    LOG_D("loop end");

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                proxy server                                */
/* -------------------------------------------------------------------------- */
static int start_proxy_server() {
    for (size_t i = 0; i < g_ctx->conf->skcp_conf_list_cnt; i++) {
        g_ctx->conf->skcp_conf_list[i]->on_accept = on_skcp_accept;
        g_ctx->conf->skcp_conf_list[i]->on_check_ticket = on_skcp_check_ticket;
        g_ctx->conf->skcp_conf_list[i]->on_close = on_skcp_close;
        g_ctx->conf->skcp_conf_list[i]->on_recv_data = on_skcp_recv_data;
    }

    g_ctx->conf->etcp_cli_conf->on_recv = on_tcp_recv;
    g_ctx->conf->etcp_cli_conf->on_close = on_tcp_close;

    if (on_init() != 0) {
        return -1;
    }

    LOG_D("proxy server loop run");
    ev_run(g_ctx->loop, 0);
    LOG_D("loop end");

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                 tun client                                 */
/* -------------------------------------------------------------------------- */
static int start_tun_client() {
    for (size_t i = 0; i < g_ctx->conf->skcp_conf_list_cnt; i++) {
        g_ctx->conf->skcp_conf_list[i]->on_close = on_skcp_close;
        g_ctx->conf->skcp_conf_list[i]->on_recv_cid = on_skcp_recv_cid;
        g_ctx->conf->skcp_conf_list[i]->on_recv_data = on_skcp_recv_data;
    }

    g_ctx->tun_fd = init_vpn_cli();
    if (g_ctx->tun_fd < 0) {
        return -1;
    }

    // 定时
    struct ev_timer bt_watcher;
    ev_init(&bt_watcher, on_beat);
    ev_timer_set(&bt_watcher, 0, 1);
    ev_timer_start(g_ctx->loop, &bt_watcher);

    // 设置tun读事件循环
    struct ev_io r_watcher;
    ev_io_init(&r_watcher, on_tun_read, g_ctx->tun_fd, EV_READ);
    ev_io_start(g_ctx->loop, &r_watcher);

    LOG_D("tun client loop run");
    ev_run(g_ctx->loop, 0);
    LOG_D("loop end");

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                 tun server                                 */
/* -------------------------------------------------------------------------- */
static int start_tun_server() {
    for (size_t i = 0; i < g_ctx->conf->skcp_conf_list_cnt; i++) {
        g_ctx->conf->skcp_conf_list[i]->on_accept = on_skcp_accept;
        g_ctx->conf->skcp_conf_list[i]->on_check_ticket = on_skcp_check_ticket;
        g_ctx->conf->skcp_conf_list[i]->on_close = on_skcp_close;
        g_ctx->conf->skcp_conf_list[i]->on_recv_data = on_skcp_recv_data;
    }

    g_ctx->tun_fd = init_vpn_cli();
    if (g_ctx->tun_fd < 0) {
        return -1;
    }

    // 设置tun读事件循环
    struct ev_io r_watcher;
    ev_io_init(&r_watcher, on_tun_read, g_ctx->tun_fd, EV_READ);
    ev_io_start(g_ctx->loop, &r_watcher);

    return 0;
}

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage("param error");
        return -1;
    }

    // int (*start_fn)(struct ev_loop * loop, lua_State * L) = NULL;
    int (*start_fn)() = NULL;
    char *lua_file = NULL;

    const char *conf_file = argv[1];
    LOG_I("config file:%s", conf_file);
    // read config file
    skt_config_t *conf = skt_init_conf(conf_file);
    if (!conf) {
        return -1;
    }

    SKT_IF_TUN_SERV_MODE(conf->mode) { start_fn = start_tun_server; }
    else SKT_IF_TUN_CLI_MODE(conf->mode) {
        start_fn = start_tun_client;
    }
    else SKT_IF_PROXY_SERV_MODE(conf->mode) {
        start_fn = start_proxy_server;
    }
    else SKT_IF_PROXY_CLI_MODE(conf->mode) {
        start_fn = start_proxy_client;
    }
    else {
        usage("mode error");
        return -1;
    }

    LOG_I("run mode: %s script file: %s", conf->mode, conf->script_file);

    g_ctx = (skt_t *)calloc(1, sizeof(skt_t));
    g_ctx->conf = conf;

    // init libev
#if (defined(__linux__) || defined(__linux))
    g_ctx->loop = ev_loop_new(EVBACKEND_EPOLL);
#elif defined(__APPLE__)
    g_ctx->loop = ev_loop_new(EVBACKEND_KQUEUE);
#else
    g_ctx->loop = ev_default_loop(0);
#endif

    if (!g_ctx->loop) {
        lua_close(g_ctx->L);
        LOG_E("loop create failed");
        return -1;
    }

    ev_signal sig_pipe_watcher;
    ev_signal_init(&sig_pipe_watcher, sig_cb, SIGPIPE);
    ev_signal_start(g_ctx->loop, &sig_pipe_watcher);

    ev_signal sig_int_watcher;
    ev_signal_init(&sig_int_watcher, sig_cb, SIGINT);
    ev_signal_start(g_ctx->loop, &sig_int_watcher);

    ev_signal sig_stop_watcher;
    ev_signal_init(&sig_stop_watcher, sig_cb, SIGSTOP);
    ev_signal_start(g_ctx->loop, &sig_stop_watcher);

    // init lua vm
    g_ctx->L = init_lua(conf->script_file);
    if (!g_ctx->L) {
        finish();
        return -1;
    }
    // 注册 etcp 和 skcp 的方法
    if (skt_reg_api_to_lua(g_ctx->L) != 0) {
        finish();
        return -1;
    }

    lua_getglobal(g_ctx->L, "skt");
    if (!lua_istable(g_ctx->L, -1)) {
        LOG_E("skt is not table");
        finish();
        return -1;
    }

    // start
    int rt = start_fn();

    finish();
    LOG_I("bye");
    return rt;
}
