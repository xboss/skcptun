#include "skt_api_lua.h"

#include <arpa/inet.h>

#include "skt_tuntap.h"
#include "skt_utils.h"

#define SKT_LUA_RET_ERROR(_V_L, _V_ERR_MSG) \
    lua_pushnil((_V_L));                    \
    lua_pushstring((_V_L), (_V_ERR_MSG));   \
    return 2

#define SKT_LUA_REG_FUN(_V_FUN_NAME, _V_LUA_FUN) \
    lua_pushcfunction(L, (_V_LUA_FUN));          \
    lua_setfield(L, -2, (_V_FUN_NAME))

/* -------------------------------------------------------------------------- */
/*                                   api                                   */
/* -------------------------------------------------------------------------- */

/* ---------------------------------- skcp api ---------------------------------- */

// 共3个参数： conf, loop, skcp_mode
static int lua_skcp_init(lua_State *L) {
    // LOG_I("stack top: %d, type: %d", lua_gettop(L), lua_type(L, -3));
    skcp_conf_t *conf = (skcp_conf_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!conf) {
        SKT_LUA_RET_ERROR(L, "conf is nil");
    }

    struct ev_loop *loop = (struct ev_loop *)lua_touserdata(L, -2);
    if (!loop) {
        SKT_LUA_RET_ERROR(L, "loop is nil");
    }

    int skcp_mode = luaL_checkinteger(L, 3);
    if (skcp_mode != SKCP_MODE_CLI && skcp_mode != SKCP_MODE_SERV) {
        SKT_LUA_RET_ERROR(L, "skcp_mode is not 1 or 2");
    }

    skcp_t *skcp = skcp_init(conf, loop, NULL, skcp_mode);
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "error");
    }

    lua_pushlightuserdata(L, skcp);
    return 1;
}

// 共1个参数： skcp
static int lua_skcp_free(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, -1);  // 取栈第一个参数
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "skcp is nil");
    }

    skcp_free(skcp);
    return 0;
}

// 共2个参数： skcp, ticket
static int lua_skcp_req_cid(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, -2);  // 取栈第一个参数
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "skcp is nil");
    }
    const char *ticket = luaL_checkstring(L, 2);
    if (!ticket) {
        SKT_LUA_RET_ERROR(L, "ticket is nil");
    }

    int len = strlen(ticket);

    int rt = skcp_req_cid(skcp, ticket, len);
    if (rt < 0) {
        SKT_LUA_RET_ERROR(L, "error");
    }

    lua_pushstring(L, "ok");
    return 1;
}

// 共3个参数： skcp, cid, buf
static int lua_skcp_send(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "skcp is nil");
    }

    uint32_t cid = luaL_checkinteger(L, 2);

    size_t len = 0;
    const char *buf = lua_tolstring(L, -1, &len);
    if (!buf || len == 0) {
        SKT_LUA_RET_ERROR(L, "buf is nil");
    }

    // LOG_I("====== lua_skcp_send cid: %u len: %lu", cid, len);
    int rt = skcp_send(skcp, cid, buf, len);
    if (rt < 0) {
        SKT_LUA_RET_ERROR(L, "skcp send error");
    }

    lua_pushinteger(L, rt);  // 返回值入栈
    return 1;
}

static int lua_skcp_get_conn(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "skcp is nil");
    }

    uint32_t cid = luaL_checkinteger(L, 2);

    skcp_conn_t *conn = skcp_get_conn(skcp, cid);
    if (!conn) {
        SKT_LUA_RET_ERROR(L, "conn is nil");
    }

    lua_pushlightuserdata(L, conn);  // 返回值入栈
    return 1;
}

static int lua_skcp_close_conn(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "skcp is nil");
    }

    uint32_t cid = luaL_checkinteger(L, 2);

    skcp_close_conn(skcp, cid);
    return 0;
}

/* ----------------------------- etcp server api ---------------------------- */

static int lua_etcp_server_init(lua_State *L) {
    // LOG_I("stack top: %d, type: %d", lua_gettop(L), lua_type(L, -2));
    etcp_serv_conf_t *conf = (etcp_serv_conf_t *)lua_touserdata(L, -2);  // 取栈第一个参数
    if (!conf) {
        SKT_LUA_RET_ERROR(L, "conf is nil");
    }

    struct ev_loop *loop = (struct ev_loop *)lua_touserdata(L, -1);
    if (!loop) {
        SKT_LUA_RET_ERROR(L, "loop is nil");
    }

    etcp_serv_t *etcp = etcp_init_server(conf, loop, NULL);
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "error");
    }

    lua_pushlightuserdata(L, etcp);
    return 1;
}

static int lua_etcp_server_free(lua_State *L) {
    etcp_serv_t *etcp = (etcp_serv_t *)lua_touserdata(L, -1);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }
    etcp_free_server(etcp);
    return 0;
}

static int lua_etcp_server_send(lua_State *L) {
    etcp_serv_t *etcp = (etcp_serv_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }

    int fd = luaL_checkinteger(L, 2);

    size_t len = 0;
    const char *buf = lua_tolstring(L, -1, &len);
    if (!buf || len == 0) {
        SKT_LUA_RET_ERROR(L, "buf is nil");
    }
    int rt = etcp_server_send(etcp, fd, (char *)buf, len);
    if (rt <= 0) {
        SKT_LUA_RET_ERROR(L, "tcp send error");
    }

    lua_pushinteger(L, rt);  // 返回值入栈
    return 1;
}

static int lua_etcp_server_get_conn(lua_State *L) {
    etcp_serv_t *etcp = (etcp_serv_t *)lua_touserdata(L, -2);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }

    int fd = luaL_checkinteger(L, 2);

    etcp_serv_conn_t *conn = etcp_server_get_conn(etcp, fd);
    if (!conn) {
        SKT_LUA_RET_ERROR(L, "conn is nil");
    }
    lua_pushlightuserdata(L, conn);
    return 1;
}

/* ----------------------------- etcp client api ---------------------------- */

static int lua_etcp_client_init(lua_State *L) {
    etcp_cli_conf_t *conf = (etcp_cli_conf_t *)lua_touserdata(L, -2);  // 取栈第一个参数
    if (!conf) {
        SKT_LUA_RET_ERROR(L, "conf is nil");
    }

    struct ev_loop *loop = (struct ev_loop *)lua_touserdata(L, -1);
    if (!loop) {
        SKT_LUA_RET_ERROR(L, "loop is nil");
    }

    etcp_cli_t *etcp = etcp_init_client(conf, loop, NULL);
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "error");
    }

    lua_pushlightuserdata(L, etcp);
    return 1;
}

static int lua_etcp_client_free(lua_State *L) {
    etcp_cli_t *etcp = (etcp_cli_t *)lua_touserdata(L, -1);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }
    etcp_free_client(etcp);
    return 0;
}

// etcp, fd, buf
static int lua_etcp_client_send(lua_State *L) {
    etcp_cli_t *etcp = (etcp_cli_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }
    int fd = luaL_checkinteger(L, 2);

    size_t len = 0;
    const char *buf = lua_tolstring(L, -1, &len);
    if (!buf || len == 0) {
        SKT_LUA_RET_ERROR(L, "buf is nil");
    }
    int rt = etcp_client_send(etcp, fd, (char *)buf, len);
    if (rt <= 0) {
        SKT_LUA_RET_ERROR(L, "tcp send error");
    }

    lua_pushinteger(L, rt);  // 返回值入栈
    return 1;
}

// etcp, addr, port
static int lua_etcp_client_create_conn(lua_State *L) {
    etcp_cli_t *etcp = (etcp_cli_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }
    const char *addr = luaL_checkstring(L, 2);
    if (!addr) {
        SKT_LUA_RET_ERROR(L, "addr is nil");
    }

    int port = luaL_checkinteger(L, 3);
    int fd = etcp_client_create_conn(etcp, (char *)addr, port, NULL);
    if (fd <= 0) {
        SKT_LUA_RET_ERROR(L, "conn is nil");
    }
    lua_pushinteger(L, fd);
    return 1;
}

static int lua_etcp_client_close_conn(lua_State *L) {
    etcp_cli_t *etcp = (etcp_cli_t *)lua_touserdata(L, -3);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }
    int fd = luaL_checkinteger(L, 2);
    int silent = luaL_checkinteger(L, 3);
    etcp_client_close_conn(etcp, fd, silent);
    return 0;
}

static int lua_etcp_client_get_conn(lua_State *L) {
    etcp_cli_t *etcp = (etcp_cli_t *)lua_touserdata(L, -2);  // 取栈第一个参数
    if (!etcp) {
        SKT_LUA_RET_ERROR(L, "etcp is nil");
    }

    int fd = luaL_checkinteger(L, 2);

    etcp_cli_conn_t *conn = etcp_client_get_conn(etcp, fd);
    if (!conn) {
        SKT_LUA_RET_ERROR(L, "conn is nil");
    }
    lua_pushlightuserdata(L, conn);
    return 1;
}

/* ------------------------------- tuntap api ------------------------------- */

// fd, buf
static int lua_tuntap_write(lua_State *L) {
    int fd = luaL_checkinteger(L, 1);

    size_t len = 0;
    const char *buf = lua_tolstring(L, -1, &len);
    if (!buf || len == 0) {
        SKT_LUA_RET_ERROR(L, "buf is nil");
    }
    int rt = skt_tuntap_write(fd, (char *)buf, len);
    if (rt <= 0) {
        SKT_LUA_RET_ERROR(L, "tcp send error");
    }

    lua_pushinteger(L, rt);  // 返回值入栈
    return 1;
}

/* -------------------------------- other api ------------------------------- */
static int lua_get_ms(lua_State *L) {
    uint64_t t = getmillisecond();
    lua_pushinteger(L, t);
    return 1;
}

static int check_endian() {
    int n = 0x12345678;
    char *p = (char *)&n;

    if (0x78 == p[0]) {
        // 小端，低地址存低位数据
        return -1;
    } else if (0x12 == p[0]) {
        // 大端，低地址存储高位数据
        return 1;
    }
    return 0;
}

static int lua_hton32(lua_State *L) {
    int x = luaL_checkinteger(L, 1);
    int y = htonl(x);

    // char s[2] = {0};
    // for (size_t i = 0; i < 4; i++) {
    //     s[0] = *((char *)(&y) + i);
    //     lua_pushstring(L, s);
    // }

    // for (size_t i = 3; i >= 0; i--) {
    //     s[0] = (char)((y >> (i * 8)) & 0xFF);
    //     lua_pushstring(L, s);
    // }

    lua_pushinteger(L, y);
    return 1;
}

static int lua_ntoh32(lua_State *L) {
    int x = luaL_checkinteger(L, 1);
    int y = ntohl(x);

    // char s[2] = {0};
    // for (size_t i = 3; i >= 0; i--) {
    //     s[0] = (char)((y >> (i * 8)) & 0xFF);
    //     lua_pushstring(L, s);
    // }

    lua_pushinteger(L, y);
    return 1;
}

// static int lua_htonll(lua_State *L) {
//     int x = luaL_checkinteger(L, 1);
//     int y = htonll(x);
//     lua_pushinteger(L, y);
//     return 1;
// }

// static int lua_ntohll(lua_State *L) {
//     int x = luaL_checkinteger(L, 1);
//     int y = ntohll(x);
//     lua_pushinteger(L, y);
//     return 1;
// }

static int lua_band(lua_State *L) {
    int a = luaL_checkinteger(L, 1);
    int b = luaL_checkinteger(L, 2);

    // char s[2] = {0};
    // s[0] = (char)(0xff & (a & b));
    // lua_pushstring(L, s);

    // char c = (char)(0xff & (a & b));
    lua_pushinteger(L, a & b);

    return 1;
}
static int lua_bor(lua_State *L) {
    int a = luaL_checkinteger(L, 1);
    int b = luaL_checkinteger(L, 2);

    // char s[2] = {0};
    // s[0] = (char)(0xff & (a | b));
    // lua_pushstring(L, s);

    // char c = (char)(0xff & (a | b));
    lua_pushinteger(L, a | b);
    return 1;
}
static int lua_bxor(lua_State *L) {
    int a = luaL_checkinteger(L, 1);
    int b = luaL_checkinteger(L, 2);

    // char s[2] = {0};
    // s[0] = (char)(0xff & (a ^ b));
    // lua_pushstring(L, s);

    // char c = (char)(0xff & (a ^ b));
    lua_pushinteger(L, a ^ b);
    return 1;
}
static int lua_blshift(lua_State *L) {
    int v = luaL_checkinteger(L, 1);
    int n = luaL_checkinteger(L, 2);

    // char s[2] = {0};
    // s[0] = (char)((0xff & v) << n);
    // lua_pushstring(L, s);

    // char c = (char)((0xff & v) << n);
    // char c = (char)(v << n);
    lua_pushinteger(L, v << n);
    return 1;
}
static int lua_brshift(lua_State *L) {
    int v = luaL_checkinteger(L, 1);
    int n = luaL_checkinteger(L, 2);

    // char s[2] = {0};
    // s[0] = (char)((0xff & v) >> n);
    // lua_pushstring(L, s);

    // char c = (char)((0xff & v) >> n);
    lua_pushinteger(L, v >> n);
    return 1;
}

static int lua_get_from_skcp(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, -2);  // 取栈第一个参数
    if (!skcp) {
        SKT_LUA_RET_ERROR(L, "skcp is nil");
    }
    const char *name = luaL_checkstring(L, 2);
    if (!name) {
        SKT_LUA_RET_ERROR(L, "name is nil");
    }

    int len = strlen(name);

    if (strcmp(name, "fd") == 0) {
        lua_pushinteger(L, skcp->fd);
        return 1;
    }

    lua_pushnil(L);
    lua_pushstring(L, "name does not exist");
    return 2;
}

// static int lua_get_conf(lua_State *L) {
//     skt_config_t *conf = (skt_config_t *)lua_touserdata(L, 1);  // 取栈第一个参数
//     if (!conf) {
//         SKT_LUA_RET_ERROR(L, "conf is nil");
//     }

//     const char *name = luaL_checkstring(L, 2);
//     if (!name) {
//         SKT_LUA_RET_ERROR(L, "name is nil");
//     }

//     if (strcmp(name, "skcp_conf_list_cnt")) {
//         /* code */
//     }

//     lua_pushstring(L, "ok");
//     return 1;
// }

int skt_reg_api_to_lua(lua_State *L) {
    lua_getglobal(L, "skt");
    // 判断是否是table类型
    if (!lua_istable(L, -1)) {
        luaL_error(L, "skt is not a table");
        return -1;
    }

    lua_newtable(L);  // value
    lua_setfield(L, -2, "api");

    lua_pushstring(L, "api");  // key
    lua_gettable(L, -2);       // api table 压栈

    char l_fn_nm[128] = {0};
    int l_fn_nm_len = 0;

    // skcp api
    // lua_pushcfunction(L, lua_skcp_init);  // value
    // lua_setfield(L, -2, "skcp_init");
    SKT_LUA_REG_FUN("skcp_init", lua_skcp_init);
    SKT_LUA_REG_FUN("skcp_free", lua_skcp_free);
    SKT_LUA_REG_FUN("skcp_req_cid", lua_skcp_req_cid);
    SKT_LUA_REG_FUN("skcp_send", lua_skcp_send);
    SKT_LUA_REG_FUN("skcp_close_conn", lua_skcp_close_conn);
    SKT_LUA_REG_FUN("skcp_get_conn", lua_skcp_get_conn);

    // etcp server api
    SKT_LUA_REG_FUN("etcp_server_init", lua_etcp_server_init);
    SKT_LUA_REG_FUN("etcp_server_free", lua_etcp_server_free);
    SKT_LUA_REG_FUN("etcp_server_send", lua_etcp_server_send);
    SKT_LUA_REG_FUN("etcp_server_get_conn", lua_etcp_server_get_conn);

    // etcp server api
    SKT_LUA_REG_FUN("etcp_client_init", lua_etcp_client_init);
    SKT_LUA_REG_FUN("etcp_client_free", lua_etcp_client_free);
    SKT_LUA_REG_FUN("etcp_client_send", lua_etcp_client_send);
    SKT_LUA_REG_FUN("etcp_client_create_conn", lua_etcp_client_create_conn);
    SKT_LUA_REG_FUN("etcp_client_close_conn", lua_etcp_client_close_conn);
    SKT_LUA_REG_FUN("etcp_client_get_conn", lua_etcp_client_get_conn);

    // tuntap api
    SKT_LUA_REG_FUN("tuntap_write", lua_tuntap_write);

    // other api
    SKT_LUA_REG_FUN("get_from_skcp", lua_get_from_skcp);
    SKT_LUA_REG_FUN("get_ms", lua_get_ms);
    SKT_LUA_REG_FUN("hton32", lua_hton32);
    SKT_LUA_REG_FUN("ntoh32", lua_ntoh32);
    // SKT_LUA_REG_FUN("htonll", lua_htonll);
    // SKT_LUA_REG_FUN("ntohll", lua_ntohll);
    SKT_LUA_REG_FUN("band", lua_band);
    SKT_LUA_REG_FUN("bor", lua_bor);
    SKT_LUA_REG_FUN("bxor", lua_bxor);
    SKT_LUA_REG_FUN("blshift", lua_blshift);
    SKT_LUA_REG_FUN("brshift", lua_brshift);

    // TODO: add get item from userdata

    lua_pop(L, 2);  // skt & api table 出栈

    return 0;
}
