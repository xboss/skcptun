cmake_minimum_required(VERSION 3.10)
project(skcptun)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wno-unused-function -D_GNU_SOURCE")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -D_GNU_SOURCE")

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# 添加源文件
set(SOURCE_FILES
src/ikcp.c
src/crypto.c
src/skt_udp_peer.c
src/skt_kcp_conn.c
src/tun.c
src/tun_osx.c
src/skcptun.c
src/ssconfig.c
src/sslog.c
src/skt_remote.c
src/skt_local.c
src/main.c
)


############# skcptun #############
add_executable(skcptun ${SOURCE_FILES})
target_link_libraries(skcptun ssl)
target_link_libraries(skcptun crypto)
target_link_libraries(skcptun pthread)
# target_link_libraries(skcptun ev)


############# static #############
# add_executable(skcptun_static ${SOURCE_FILES})
# target_link_libraries(skcptun_static ssl -static)
# target_link_libraries(skcptun_static crypto -static)
# target_link_libraries(skcptun_static pthread -static)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
