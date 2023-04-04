// #include <lauxlib.h>
// #include <lua.h>
// #include <lualib.h>

// #include "easy_tcp.h"
// #include "skcp.h"
// #include "skt_api_lua.h"
// #include "skt_config.h"
// #include "skt_utils.h"

// // #define SKT_TUN_SERV_MODE "tun_server"
// // #define SKT_TUN_CLI_MODE "tun_client"
// // #define SKT_PROXY_SERV_MODE "proxy_server"
// // #define SKT_PROXY_CLI_MODE "proxy_client"

// // #define SKT_IF_TUN_SERV_MODE(_v_mode) if (strcmp((_v_mode), SKT_TUN_SERV_MODE) == 0)
// // #define SKT_IF_TUN_CLI_MODE(_v_mode) if (strcmp((_v_mode), SKT_TUN_CLI_MODE) == 0)
// // #define SKT_IF_PROXY_SERV_MODE(_v_mode) if (strcmp((_v_mode), SKT_PROXY_SERV_MODE) == 0)
// // #define SKT_IF_PROXY_CLI_MODE(_v_mode) if (strcmp((_v_mode), SKT_PROXY_CLI_MODE) == 0)

// lua_State *L = NULL;

// /* -------------------------------------------------------------------------- */
// /*                                   common                                   */
// /* -------------------------------------------------------------------------- */

// static void sig_cb(struct ev_loop *loop, ev_signal *w, int revents) {
//     LOG_I("sig_cb signal:%d", w->signum);
//     if (w->signum == SIGPIPE) {
//         return;
//     }

//     ev_break(loop, EVBREAK_ALL);
//     LOG_I("sig_cb loop break all event ok");
// }

// static void usage(const char *msg) { printf("%s\n kcptun mode\n", msg); }

// static void close_lua() {
//     if (L) {
//         lua_settop(L, 0);
//         lua_close(L);
//     }
// }

// static lua_State *init_lua(file_path) {
//     L = luaL_newstate();
//     if (!L) {
//         LOG_E("Init Lua VM error");
//         lua_close(L);
//         return NULL;
//     }

//     luaL_openlibs(L);

//     int status = luaL_loadfile(L, file_path);
//     if (status) {
//         LOG_E("Couldn't load file when init lua vm %s", lua_tostring(L, -1));
//         lua_close(L);
//         return NULL;
//     }

//     int ret = lua_pcall(L, 0, 0, 0);
//     if (ret != LUA_OK) {
//         LOG_E("%s, when init lua vm", lua_tostring(L, -1));
//         lua_close(L);
//         return NULL;
//     }

//     lua_newtable(L);
//     lua_setglobal(L, "SKCPTUN");

//     return L;
// }

// /* -------------------------------------------------------------------------- */
// /*                                proxy client                                */
// /* -------------------------------------------------------------------------- */

// static int on_tcp_accept(int fd) {
//     // TODO:
//     return 0;
// }
// static void on_tcp_recv(int fd, char *buf, int len) {
//     // TODO:
// }
// static void on_tcp_close(int fd) {
//     // TODO:
// }
// static void on_skcp_recv_cid(skcp_t *skcp, uint32_t cid) {
//     // TODO: SCKP_TUN.proxy_client.on_skcp_recv_cid
//     lua_getglobal(L, "SCKPTUN");
//     lua_getfield(L, -1, "proxy_client");      // SCKPTUN.proxy_client table 压栈
//     lua_getfield(L, -1, "on_skcp_recv_cid");  // SCKPTUN.proxy_client.on_skcp_recv_cid function 压栈
//     lua_pushlightuserdata(L, skcp);           // 自动弹出
//     lua_pushinteger(L, cid);                  // 自动弹出
//     int rt = lua_pcall(L, 2, 0, 0);           // 调用函数，调用完成以后，会将返回值压入栈中
//     if (rt) {
//         LOG_E("call on_skcp_recv_cid in lua error");
//         return;
//     }
//     lua_pop(2);
// }
// static void on_skcp_recv_data(skcp_t *skcp, uint32_t cid, char *buf, int len) {
//     // TODO:
// }
// static void on_skcp_close(skcp_t *skcp, uint32_t cid) {
//     // TODO:
// }
// static void on_beat(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
//     // TODO:
// }

// static int start_proxy_client(struct ev_loop *loop) {
//     // 注册 etcp 和 skcp 的方法
//     if (skt_reg_api_to_lua(L) != 0) {
//         return -1;
//     }

//     // TODO: 获取配置信息
//     lua_getglobal(L, "SCKPTUN");
//     lua_getfield(L, -1, "config");  // SCKPTUN.config table 压栈

//     // TODO: 生成配置
//     skt_config_t *conf = NULL;

//     skcp_t *skcp = skcp_init(conf->skcp_conf, loop, NULL, SKCP_MODE_CLI);
//     if (!skcp) {
//         return -1;
//     };

//     etcp_serv_t *etcp = etcp_init_server(conf->etcp_serv_conf, loop, NULL);
//     if (!etcp) {
//         return -1;
//     }

//     // 回调方法
//     conf->skcp_conf->on_close = on_skcp_close;
//     conf->skcp_conf->on_recv_cid = on_skcp_recv_cid;
//     conf->skcp_conf->on_recv_data = on_skcp_recv_data;

//     conf->etcp_serv_conf->on_accept = on_tcp_accept;
//     conf->etcp_serv_conf->on_recv = on_tcp_recv;
//     conf->etcp_serv_conf->on_close = on_tcp_close;

//     // 定时
//     g_ctx->bt_watcher = malloc(sizeof(ev_timer));
//     g_ctx->bt_watcher->data = skcp;
//     ev_init(g_ctx->bt_watcher, on_beat);
//     ev_timer_set(g_ctx->bt_watcher, 0, 1);
//     ev_timer_start(g_ctx->loop, g_ctx->bt_watcher);

//     LOG_D("proxy client loop run");
//     ev_run(loop, 0);
//     LOG_D("loop end");

//     skt_proxy_client_free();
//     return 0;
// }

// /* -------------------------------------------------------------------------- */
// /*                                    main                                    */
// /* -------------------------------------------------------------------------- */

// int main(int argc, char *argv[]) {
//     if (argc < 2) {
//         usage("param error");
//         return -1;
//     }

//     int (*start_fn)(struct ev_loop * loop, lua_State * L) = NULL;
//     char *lua_file = NULL;

//     // const char *mode = argv[1];
//     const char *conf_file = argv[1];
//     LOG_I("config file:%s", conf_file);
//     // read config file
//     skt_config_t *conf = skt_init_conf(conf_file);
//     if (!conf) {
//         return -1;
//     }

//     SKT_IF_TUN_SERV_MODE(conf->mode) {
//         // TODO:
//         start_fn = NULL;
//     }
//     else SKT_IF_TUN_CLI_MODE(conf->mode) {
//         // TODO:
//         start_fn = NULL;
//     }
//     else SKT_IF_PROXY_SERV_MODE(conf->mode) {
//         // TODO:
//         start_fn = NULL;
//     }
//     else SKT_IF_PROXY_CLI_MODE(conf->mode) {
//         // TODO:
//         start_fn = start_proxy_client;
//     }
//     else {
//         usage("mode error");
//         return -1;
//     }

//     LOG_I("run mode: %s script file: %", conf->mode, conf->script_file);

//     // init lua vm
//     init_lua(conf->script_file);
//     if (!L) {
//         return -1;
//     }

//     // init libev
// #if (defined(__linux__) || defined(__linux))
//     struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL);
// #elif defined(__APPLE__)
//     struct ev_loop *loop = ev_loop_new(EVBACKEND_KQUEUE);
// #else
//     struct ev_loop *loop = ev_default_loop(0);
// #endif

//     if (!loop) {
//         close_lua(L);
//         LOG_E("loop create failed");
//         return -1;
//     }

//     ev_signal sig_pipe_watcher;
//     ev_signal_init(&sig_pipe_watcher, sig_cb, SIGPIPE);
//     ev_signal_start(loop, &sig_pipe_watcher);

//     ev_signal sig_int_watcher;
//     ev_signal_init(&sig_int_watcher, sig_cb, SIGINT);
//     ev_signal_start(loop, &sig_int_watcher);

//     ev_signal sig_stop_watcher;
//     ev_signal_init(&sig_stop_watcher, sig_cb, SIGSTOP);
//     ev_signal_start(loop, &sig_stop_watcher);

//     // start
//     int rt = start_fn(loop, L);

//     close_lua(L);
//     LOG_I("bye");
//     return rt;
// }
