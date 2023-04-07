#include "skt_api_lua.h"

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
    LOG_I("stack top: %d, type: %d", lua_gettop(L), lua_type(L, -3));
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
    // char *buf = (char *)calloc(1, len);
    // memcpy(buf, str, len);
    int rt = skcp_send(skcp, cid, buf, len);
    if (rt < 0) {
        SKT_LUA_RET_ERROR(L, "send error");
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
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_server_free(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_server_send(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_server_get_conn(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

/* ----------------------------- etcp client api ---------------------------- */

static int lua_etcp_client_init(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_client_free(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_client_send(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_client_create_conn(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_client_close_conn(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_etcp_client_get_conn(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
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

    // lua_pushstring(L, "skcp_send");       // key
    // lua_pushcfunction(L, lua_skcp_send);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "skcp_get_conn");       // key
    // lua_pushcfunction(L, lua_skcp_get_conn);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "etcp_server_send");       // key
    // lua_pushcfunction(L, lua_etcp_server_send);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "etcp_server_get_conn");       // key
    // lua_pushcfunction(L, lua_etcp_server_get_conn);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "etcp_client_send");       // key
    // lua_pushcfunction(L, lua_etcp_client_send);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "etcp_client_create_conn");       // key
    // lua_pushcfunction(L, lua_etcp_client_create_conn);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "etcp_client_close_conn");       // key
    // lua_pushcfunction(L, lua_etcp_client_close_conn);  // value
    // lua_settable(L, -3);

    // lua_pushstring(L, "etcp_client_get_conn");       // key
    // lua_pushcfunction(L, lua_etcp_client_get_conn);  // value
    // lua_settable(L, -3);

    // TODO: add get item from userdata

    lua_pop(L, 2);  // skt & api table 出栈

    return 0;
}
