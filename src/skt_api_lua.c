#include "skt_api_lua.h"

#include "easy_tcp.h"
#include "skcp.h"
#include "skt_utils.h"

#define SCKT_LUA_RET_ERROR(_V_L, _V_ERR_MSG) \
    lua_pushnil((_V_L));                     \
    lua_pushstring((_V_L), (_V_ERR_MSG));    \
    return 2

/* -------------------------------------------------------------------------- */
/*                                   api                                   */
/* -------------------------------------------------------------------------- */

static int lua_skcp_req_cid(lua_State *L) {
    skcp_t *skcp = (skcp_t *)lua_touserdata(L, 1);  // 取栈第一个参数
    if (!skcp) {
        SCKT_LUA_RET_ERROR(L, "skcp is nil");
    }
    const char *ticket = luaL_checkstring(L, 2);
    if (!ticket) {
        SCKT_LUA_RET_ERROR(L, "ticket is nil");
    }

    int len = strlen(ticket);

    int rt = skcp_req_cid(skcp, ticket, len);
    if (rt != 0) {
        SCKT_LUA_RET_ERROR(L, "error");
    }

    lua_pushstring(L, "ok");
    return 1;
}

static int lua_skcp_send(lua_State *L) {
    // const char *a = luaL_checkstring(L, 1);  // 取栈第一个参数
    // lua_pushstring(L, (const char *)a);      // 返回值入栈
    return 1;
}

static int lua_skcp_get_conn(lua_State *L) {
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
//         SCKT_LUA_RET_ERROR(L, "conf is nil");
//     }

//     const char *name = luaL_checkstring(L, 2);
//     if (!name) {
//         SCKT_LUA_RET_ERROR(L, "name is nil");
//     }

//     if (strcmp(name, "skcp_conf_list_cnt")) {
//         /* code */
//     }

//     lua_pushstring(L, "ok");
//     return 1;
// }

int skt_reg_api_to_lua(lua_State *L) {
    lua_getglobal(L, "SKCPTUN");
    // 判断是否是table类型
    if (!lua_istable(L, -1)) {
        luaL_error(L, "SKCPTUN is not a table");
        return -1;
    }

    lua_pushstring(L, "API");  // key
    lua_newtable(L);           // value
    lua_settable(L, -3);

    lua_pushstring(L, "API");  // key
    lua_gettable(L, -2);       // API table 压栈

    lua_pushstring(L, "skcp_req_cid");       // key
    lua_pushcfunction(L, lua_skcp_req_cid);  // value
    lua_settable(L, -3);

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

    lua_pop(L, 2);  // SKCPTUN & API table 出栈

    return 0;
}
