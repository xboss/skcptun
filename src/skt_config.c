#define LUA_COMPAT_5_3

#include "skt_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "easy_tcp.h"
#include "lauxlib.h"
#include "lua.h"
#include "luaconf.h"
#include "lualib.h"
#include "skcp.h"
#include "skt_utils.h"

#define SKT_CONF_R_BUF_SIZE 1024
#define SKT_CONF_MAX_JSTR_LEN SKT_CONF_R_BUF_SIZE * 5

#define SKT_CONF_ERROR(_v_e_item, _rt_value)                                      \
    if ((_v_e_item)) LOG_E("invalid '%s' in config file", ((char *)(_v_e_item))); \
    skt_free_conf(conf);                                                          \
    lua_close(L);                                                                 \
    return (_rt_value)

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

static etcp_serv_conf_t **init_tcp_serv_list_conf(lua_State *L, size_t size) {
    etcp_serv_conf_t **etcp_serv_conf_list = (etcp_serv_conf_t **)calloc(size, sizeof(etcp_serv_conf_t *));
    for (size_t i = 0; i < size; i++) {
        lua_pushinteger(L, i + 1);
        lua_gettable(L, -2);
        etcp_serv_conf_list[i] = (etcp_serv_conf_t *)malloc(sizeof(etcp_serv_conf_t));
        ETCP_SERV_DEF_CONF(etcp_serv_conf_list[i]);

        int ivalue = 0;
        SKT_LUA_GET_INT(ivalue, "tcp_read_buf_size") { etcp_serv_conf_list[i]->r_buf_size = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_keepalive") {
            etcp_serv_conf_list[i]->w_keepalive = etcp_serv_conf_list[i]->r_keepalive = ivalue;
        }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_recv_timeout") { etcp_serv_conf_list[i]->recv_timeout = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_send_timeout") { etcp_serv_conf_list[i]->send_timeout = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_timeout_interval") { etcp_serv_conf_list[i]->timeout_interval = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_listen_port") { etcp_serv_conf_list[i]->serv_port = ivalue; }
        else {
            LOG_E("invalid 'tcp_listen_port' in config file");
        }

        lua_pop(L, 1);
        size_t len = 0;
        const char *str = NULL;
        SKT_LUA_GET_STR(etcp_serv_conf_list[i]->serv_addr, "tcp_listen_addr", str, len) else {
            LOG_E("invalid 'tcp_listen_addr' in config file");
        }
        lua_pop(L, 2);
    }

    return etcp_serv_conf_list;
}

static etcp_cli_conf_t **init_tcp_cli_list_conf(lua_State *L, size_t size) {
    etcp_cli_conf_t **etcp_cli_conf_list = (etcp_cli_conf_t **)calloc(size, sizeof(etcp_cli_conf_t *));
    for (size_t i = 0; i < size; i++) {
        lua_pushinteger(L, i + 1);
        lua_gettable(L, -2);
        etcp_cli_conf_list[i] = (etcp_cli_conf_t *)malloc(sizeof(etcp_cli_conf_t));
        ETCP_CLI_DEF_CONF(etcp_cli_conf_list[i]);

        int ivalue = 0;
        SKT_LUA_GET_INT(ivalue, "tcp_read_buf_size") { etcp_cli_conf_list[i]->r_buf_size = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_keepalive") {
            etcp_cli_conf_list[i]->w_keepalive = etcp_cli_conf_list[i]->r_keepalive = ivalue;
        }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_recv_timeout") { etcp_cli_conf_list[i]->recv_timeout = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_send_timeout") { etcp_cli_conf_list[i]->send_timeout = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "tcp_target_port") { etcp_cli_conf_list[i]->target_port = ivalue; }

        lua_pop(L, 1);
        size_t len = 0;
        const char *str = NULL;
        SKT_LUA_GET_STR(etcp_cli_conf_list[i]->target_addr, "tcp_target_addr", str, len)
        lua_pop(L, 2);
    }

    return etcp_cli_conf_list;
}

static skcp_conf_t **init_skcp_list_conf(lua_State *L, size_t size) {
    skcp_conf_t **skcp_conf_list = (skcp_conf_t **)calloc(size, sizeof(skcp_conf_t *));
    for (size_t i = 0; i < size; i++) {
        lua_pushinteger(L, i + 1);
        lua_gettable(L, -2);

        skcp_conf_list[i] = (skcp_conf_t *)malloc(sizeof(skcp_conf_t));
        SKCP_DEF_CONF(skcp_conf_list[i]);

        int ivalue = 0;

        SKT_LUA_GET_INT(ivalue, "skcp_speed_mode") {
            if (1 != ivalue) {
                skcp_conf_list[i]->nodelay = 0;
                skcp_conf_list[i]->resend = 0;
                skcp_conf_list[i]->nc = 0;
            }
        }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "skcp_keepalive") {
            skcp_conf_list[i]->w_keepalive = skcp_conf_list[i]->r_keepalive = ivalue;
        }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "skcp_max_conn_cnt") { skcp_conf_list[i]->max_conn_cnt = ivalue; }

        lua_pop(L, 1);
        SKT_LUA_GET_INT(ivalue, "port") { skcp_conf_list[i]->port = ivalue; }

        size_t len = 0;
        const char *str = NULL;
        lua_pop(L, 1);
        SKT_LUA_GET_STR(skcp_conf_list[i]->addr, "address", str, len) else {
            LOG_E("invalid 'address' in config file");
        }

        lua_pop(L, 1);
        lua_getfield(L, -1, "ticket");
        str = lua_tolstring(L, -1, &len);
        if (str) {
            len = len < SKCP_TICKET_LEN ? len : SKCP_TICKET_LEN;
            memcpy(skcp_conf_list[i]->ticket, str, len);
        }

        lua_pop(L, 1);
        lua_getfield(L, -1, "password");
        str = lua_tolstring(L, -1, &len);
        if (str) {
            char padding[16] = {0};
            len = len > 16 ? 16 : len;
            memcpy(padding, str, len);
            char_to_hex(padding, len, skcp_conf_list[i]->key);
        }

        lua_pop(L, 2);
    }

    return skcp_conf_list;
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
    SKT_LUA_GET_STR(conf->script_file, "script_file", str, len) else { SKT_CONF_ERROR("script_file", NULL); }

    lua_pop(L, 1);
    SKT_LUA_GET_STR(conf->tun_ip, "tun_ip", str, len);
    lua_pop(L, 1);
    SKT_LUA_GET_STR(conf->tun_mask, "tun_mask", str, len);

    // init skcp_servers
    lua_pop(L, 1);
    lua_getfield(L, -1, "skcp_servers");
    if (!lua_isnoneornil(L, -1) && lua_istable(L, -1)) {
        conf->skcp_serv_conf_list_size = lua_objlen(L, -1);
        if (conf->skcp_serv_conf_list_size <= 0) {
            SKT_CONF_ERROR("skcp_servers", NULL);
        }
        conf->skcp_serv_conf_list = init_skcp_list_conf(L, conf->skcp_serv_conf_list_size);
    }

    // init skcp_clients
    lua_pop(L, 1);
    lua_getfield(L, -1, "skcp_clients");
    if (!lua_isnoneornil(L, -1) && lua_istable(L, -1)) {
        conf->skcp_cli_conf_list_size = lua_objlen(L, -1);
        if (conf->skcp_cli_conf_list_size <= 0) {
            SKT_CONF_ERROR("skcp_clients", NULL);
        }
        conf->skcp_cli_conf_list = init_skcp_list_conf(L, conf->skcp_cli_conf_list_size);
    }

    // init tcp server config
    lua_pop(L, 1);
    lua_getfield(L, -1, "tcp_servers");
    if (!lua_isnoneornil(L, -1) && lua_istable(L, -1)) {
        conf->etcp_serv_conf_list_size = lua_objlen(L, -1);
        if (conf->etcp_serv_conf_list_size <= 0) {
            SKT_CONF_ERROR("tcp_servers", NULL);
        }
        conf->etcp_serv_conf_list = init_tcp_serv_list_conf(L, conf->etcp_serv_conf_list_size);
    }

    // init tcp client config
    lua_pop(L, 1);
    lua_getfield(L, -1, "tcp_clients");
    if (!lua_isnoneornil(L, -1) && lua_istable(L, -1)) {
        conf->etcp_cli_conf_list_size = lua_objlen(L, -1);
        if (conf->etcp_cli_conf_list_size <= 0) {
            SKT_CONF_ERROR("tcp_clients", NULL);
        }
        conf->etcp_cli_conf_list = init_tcp_cli_list_conf(L, conf->etcp_cli_conf_list_size);
    }

    return conf;
}

void skt_free_conf(skt_config_t *conf) {
    if (!conf) {
        return;
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

    if (conf->skcp_serv_conf_list && conf->skcp_serv_conf_list_size > 0) {
        for (size_t i = 0; i < conf->skcp_serv_conf_list_size; i++) {
            if (conf->skcp_serv_conf_list[i]) {
                if (conf->skcp_serv_conf_list[i]->addr) {
                    FREE_IF(conf->skcp_serv_conf_list[i]->addr);
                }
                FREE_IF(conf->skcp_serv_conf_list[i]);
            }
        }
        FREE_IF(conf->skcp_serv_conf_list);
        conf->skcp_serv_conf_list_size = 0;
    }

    if (conf->skcp_cli_conf_list && conf->skcp_cli_conf_list_size > 0) {
        for (size_t i = 0; i < conf->skcp_cli_conf_list_size; i++) {
            if (conf->skcp_cli_conf_list[i]) {
                if (conf->skcp_cli_conf_list[i]->addr) {
                    FREE_IF(conf->skcp_cli_conf_list[i]->addr);
                }
                FREE_IF(conf->skcp_cli_conf_list[i]);
            }
        }
        FREE_IF(conf->skcp_cli_conf_list);
        conf->skcp_cli_conf_list_size = 0;
    }

    if (conf->etcp_serv_conf_list && conf->etcp_serv_conf_list_size > 0) {
        for (size_t i = 0; i < conf->etcp_serv_conf_list_size; i++) {
            if (conf->etcp_serv_conf_list[i]) {
                if (conf->etcp_serv_conf_list[i]->serv_addr) {
                    FREE_IF(conf->etcp_serv_conf_list[i]->serv_addr);
                }
                FREE_IF(conf->etcp_serv_conf_list[i]);
            }
        }
        FREE_IF(conf->etcp_serv_conf_list);
        conf->etcp_serv_conf_list_size = 0;
    }

    if (conf->etcp_cli_conf_list && conf->etcp_cli_conf_list_size > 0) {
        for (size_t i = 0; i < conf->etcp_cli_conf_list_size; i++) {
            if (conf->etcp_cli_conf_list[i]) {
                FREE_IF(conf->etcp_cli_conf_list[i]);
            }
        }
        FREE_IF(conf->etcp_cli_conf_list);
        conf->etcp_cli_conf_list_size = 0;
    }

    FREE_IF(conf);
}

/* ---------------------------------- test ---------------------------------- */

// int main(int argc, char const *argv[]) {
//     skt_config_t *conf = skt_init_conf("../skcptun_config_sample.lua");
//     assert(conf);
//     printf("%p\n", conf);
//     skt_free_conf(conf);
//     return 0;
// }
