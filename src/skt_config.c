#include "skt_config.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "easy_tcp.h"
#include "skcp.h"
#include "skt_utils.h"

#define SKT_CONF_R_BUF_SIZE 1024
#define SKT_CONF_MAX_JSTR_LEN SKT_CONF_R_BUF_SIZE * 5

#define SKT_CONF_ERROR(_v_e_item)                                                 \
    if ((_v_e_item)) LOG_E("invalid '%s' in config file", ((char *)(_v_e_item))); \
    skt_free_conf(conf);                                                          \
    lua_close(L);                                                                 \
    return NULL

#define SKT_LUA_GET_INT(_v_i_value, _v_e_item) \
    lua_getfield(L, -1, (_v_e_item));          \
    (_v_i_value) = lua_tointeger(L, -1);       \
    if ((_v_i_value) > 0)

#define SKT_LUA_GET_STR(_v_dest_str, _v_e_item, _v_tmp_str, _v_tmp_str_len) \
    lua_getfield(L, -1, (_v_e_item));                                       \
    (_v_tmp_str) = lua_tolstring(L, -1, &(_v_tmp_str_len));                 \
    if ((_v_tmp_str)) {                                                     \
        (_v_dest_str) = (char *)calloc(1, (_v_tmp_str_len) + 1);            \
        strcpy((_v_dest_str), (_v_tmp_str));                                \
    }

#define SKT_INIT_SKCP_CONF_LIST(_v_item_name)                                                           \
    do {                                                                                                \
        lua_pop(L, 1);                                                                                  \
        lua_getfield(L, -1, (_v_item_name));                                                            \
        if (!lua_istable(L, -1)) {                                                                      \
            SKT_CONF_ERROR((_v_item_name));                                                             \
        }                                                                                               \
        conf->skcp_conf_list_cnt = lua_objlen(L, -1);                                                   \
        if (conf->skcp_conf_list_cnt <= 0) {                                                            \
            SKT_CONF_ERROR((_v_item_name));                                                             \
        }                                                                                               \
        conf->skcp_conf_list = (skcp_conf_t **)calloc(conf->skcp_conf_list_cnt, sizeof(skcp_conf_t *)); \
        for (size_t i = 0; i < conf->skcp_conf_list_cnt; i++) {                                         \
            lua_pushinteger(L, i + 1);                                                                  \
            lua_gettable(L, -2);                                                                        \
            if (init_skcp_conf(L, conf, i) != 0) {                                                      \
                SKT_CONF_ERROR(NULL);                                                                   \
            }                                                                                           \
            lua_pop(L, 2);                                                                              \
        }                                                                                               \
    } while (0)

static int init_etcp_serv_conf(lua_State *L, skt_config_t *conf) {
    conf->etcp_serv_conf = (etcp_serv_conf_t *)malloc(sizeof(etcp_serv_conf_t));
    ETCP_SERV_DEF_CONF(conf->etcp_serv_conf);

    int ivalue = 0;
    SKT_LUA_GET_INT(ivalue, "tcp_read_buf_size") { conf->etcp_serv_conf->r_buf_size = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_keepalive") {
        conf->etcp_serv_conf->w_keepalive = conf->etcp_serv_conf->r_keepalive = ivalue;
    }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_recv_timeout") { conf->etcp_serv_conf->recv_timeout = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_send_timeout") { conf->etcp_serv_conf->send_timeout = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_timeout_interval") { conf->etcp_serv_conf->timeout_interval = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_listen_port") { conf->etcp_serv_conf->serv_port = ivalue; }
    else {
        LOG_E("invalid 'tcp_listen_port' in config file");
        return -1;
    }

    lua_pop(L, 1);
    size_t len = 0;
    const char *str = NULL;
    SKT_LUA_GET_STR(conf->etcp_serv_conf->serv_addr, "tcp_listen_addr", str, len) else {
        LOG_E("invalid 'tcp_listen_addr' in config file");
        return -1;
    }

    return 0;
}

static int init_etcp_cli_conf(lua_State *L, skt_config_t *conf) {
    conf->etcp_cli_conf = (etcp_cli_conf_t *)malloc(sizeof(etcp_cli_conf_t));
    ETCP_CLI_DEF_CONF(conf->etcp_cli_conf);

    int ivalue = 0;
    SKT_LUA_GET_INT(ivalue, "tcp_read_buf_size") { conf->etcp_cli_conf->r_buf_size = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_keepalive") {
        conf->etcp_cli_conf->w_keepalive = conf->etcp_cli_conf->r_keepalive = ivalue;
    }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_recv_timeout") { conf->etcp_cli_conf->recv_timeout = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_send_timeout") { conf->etcp_cli_conf->send_timeout = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "tcp_target_port") { conf->tcp_target_port = ivalue; }
    else {
        LOG_E("invalid 'tcp_target_port' in config file");
        return -1;
    }

    lua_pop(L, 1);
    size_t len = 0;
    const char *str = NULL;
    SKT_LUA_GET_STR(conf->tcp_target_addr, "tcp_target_addr", str, len) else {
        LOG_E("invalid 'tcp_target_addr' in config file");
        return -1;
    }

    return 0;
}

static int init_skcp_conf(lua_State *L, skt_config_t *conf, size_t i) {
    conf->skcp_conf_list[i] = (skcp_conf_t *)malloc(sizeof(skcp_conf_t));
    SKCP_DEF_CONF(conf->skcp_conf_list[i]);

    int ivalue = 0;

    SKT_LUA_GET_INT(ivalue, "skcp_speed_mode") {
        if (1 != ivalue) {
            conf->skcp_conf_list[i]->nodelay = 0;
            conf->skcp_conf_list[i]->resend = 0;
            conf->skcp_conf_list[i]->nc = 0;
        }
    }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "skcp_keepalive") {
        conf->skcp_conf_list[i]->w_keepalive = conf->skcp_conf_list[i]->r_keepalive = ivalue;
    }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "skcp_max_conn_cnt") { conf->skcp_conf_list[i]->max_conn_cnt = ivalue; }

    lua_pop(L, 1);
    SKT_LUA_GET_INT(ivalue, "port") { conf->skcp_conf_list[i]->port = ivalue; }

    size_t len = 0;
    const char *str = NULL;
    lua_pop(L, 1);
    SKT_LUA_GET_STR(conf->skcp_conf_list[i]->addr, "address", str, len) else {
        LOG_E("invalid 'address' in config file");
        return -1;
    }

    lua_pop(L, 1);
    lua_getfield(L, -1, "ticket");
    str = lua_tolstring(L, -1, &len);
    if (str) {
        len = len < SKCP_TICKET_LEN ? len : SKCP_TICKET_LEN;
        memcpy(conf->skcp_conf_list[i]->ticket, str, len);
    }

    lua_pop(L, 1);
    lua_getfield(L, -1, "password");
    str = lua_tolstring(L, -1, &len);
    if (str) {
        char padding[16] = {0};
        len = len > 16 ? 16 : len;
        memcpy(padding, str, len);
        char_to_hex(padding, len, conf->skcp_conf_list[i]->key);
    }

    return 0;
}

skt_config_t *skt_init_conf(const char *conf_file) {
    // init lua vm
    lua_State *L = luaL_newstate();
    if (!L) {
        LOG_E("Init Lua VM error");
        lua_close(L);
        return NULL;
    }

    luaL_openlibs(L);

    int status = luaL_loadfile(L, conf_file);
    if (status) {
        LOG_E("Couldn't load file when init lua vm %s", lua_tostring(L, -1));
        lua_close(L);
        return NULL;
    }

    int ret = lua_pcall(L, 0, 0, 0);
    if (ret != LUA_OK) {
        LOG_E("%s, when init lua vm", lua_tostring(L, -1));
        lua_close(L);
        return NULL;
    }

    lua_getglobal(L, "config");
    if (!lua_istable(L, -1)) {
        LOG_E("invalid 'config' in config file");
        lua_close(L);
        return NULL;
    }

    // 生成配置
    skt_config_t *conf = (skt_config_t *)calloc(1, sizeof(skt_config_t));

    size_t len = 0;
    const char *str = NULL;
    SKT_LUA_GET_STR(conf->mode, "mode", str, len) else { SKT_CONF_ERROR("mode"); }

    lua_pop(L, 1);
    SKT_LUA_GET_STR(conf->script_file, "script_file", str, len) else { SKT_CONF_ERROR("script_file"); }

    lua_pop(L, 1);
    lua_getfield(L, -1, conf->mode);
    if (!lua_istable(L, -1)) {
        SKT_CONF_ERROR(conf->mode);
    }

    SKT_IF_PROXY_CLI_MODE(conf->mode) {
        if (init_etcp_serv_conf(L, conf) != 0) {
            SKT_CONF_ERROR(NULL);
        }

        SKT_INIT_SKCP_CONF_LIST("skcp_remote_servers");
    }

    SKT_IF_PROXY_SERV_MODE(conf->mode) {
        if (init_etcp_cli_conf(L, conf) != 0) {
            SKT_CONF_ERROR(NULL);
        }

        SKT_INIT_SKCP_CONF_LIST("skcp_servers");
        // lua_pop(L, 1);
        // lua_getfield(L, -1, "skcp_server");
        // if (!lua_istable(L, -1)) {
        //     SKT_CONF_ERROR("skcp_server");
        // }

        // conf->skcp_conf_list_cnt = 1;
        // conf->skcp_conf_list = (skcp_conf_t **)calloc(conf->skcp_conf_list_cnt, sizeof(skcp_conf_t *));
        // if (init_skcp_conf(L, conf, 0) != 0) {
        //     SKT_CONF_ERROR(NULL);
        // }
    }

    SKT_IF_TUN_CLI_MODE(conf->mode) {
        SKT_LUA_GET_STR(conf->tun_ip, "tun_ip", str, len);
        lua_pop(L, 1);
        SKT_LUA_GET_STR(conf->tun_mask, "tun_mask", str, len);

        SKT_INIT_SKCP_CONF_LIST("skcp_remote_servers");
    }

    SKT_IF_TUN_SERV_MODE(conf->mode) {
        SKT_LUA_GET_STR(conf->tun_ip, "tun_ip", str, len);
        lua_pop(L, 1);
        SKT_LUA_GET_STR(conf->tun_mask, "tun_mask", str, len);

        SKT_INIT_SKCP_CONF_LIST("skcp_servers");
        // lua_pop(L, 1);
        // lua_getfield(L, -1, "skcp_server");
        // if (!lua_istable(L, -1)) {
        //     SKT_CONF_ERROR("skcp_server");
        // }

        // conf->skcp_conf_list_cnt = 1;
        // conf->skcp_conf_list = (skcp_conf_t **)calloc(conf->skcp_conf_list_cnt, sizeof(skcp_conf_t *));
        // if (init_skcp_conf(L, conf, 0) != 0) {
        //     SKT_CONF_ERROR(NULL);
        // }
    }

    return conf;
}

void skt_free_conf(skt_config_t *conf) {
    if (!conf) {
        return;
    }

    if (conf->mode) {
        FREE_IF(conf->mode);
    }

    if (conf->script_file) {
        FREE_IF(conf->script_file);
    }

    if (conf->tun_ip) {
        FREE_IF(conf->tun_ip);
    }

    if (conf->tun_mask) {
        FREE_IF(conf->tun_mask);
    }

    if (conf->tcp_target_addr) {
        FREE_IF(conf->tcp_target_addr);
    }

    if (conf->skcp_conf_list && conf->skcp_conf_list_cnt > 0) {
        for (size_t i = 0; i < conf->skcp_conf_list_cnt; i++) {
            if (conf->skcp_conf_list[i]) {
                if (conf->skcp_conf_list[i]->addr) {
                    FREE_IF(conf->skcp_conf_list[i]->addr);
                }
                FREE_IF(conf->skcp_conf_list[i]);
            }
        }
        FREE_IF(conf->skcp_conf_list);
        conf->skcp_conf_list_cnt = 0;
    }

    if (conf->etcp_serv_conf) {
        if (conf->etcp_serv_conf->serv_addr) {
            FREE_IF(conf->etcp_serv_conf->serv_addr);
        }
        FREE_IF(conf->etcp_serv_conf);
    }

    if (conf->etcp_cli_conf) {
        FREE_IF(conf->etcp_cli_conf);
    }

    // TODO:

    FREE_IF(conf);
}

/* ---------------------------------- test ---------------------------------- */

// int main(int argc, char const *argv[]) {
//     skt_config_t *conf = skt_init_conf("../skcptun_config.lua");
//     assert(conf);
//     skt_free_conf(conf);
//     return 0;
// }
