#ifndef _SKT_API_LUA_H
#define _SKT_API_LUA_H

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int skt_reg_api_to_lua(lua_State *L);

#endif  // SKT_API_LUA_H
