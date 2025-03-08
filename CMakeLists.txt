cmake_minimum_required(VERSION 3.10)
project(skcptun)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# 添加源文件
set(SOURCE_FILES
src/crypto.c
# src/main.c
src/skcptun.c
src/ssconf.c
src/sslog.c
src/sstcp.c
src/ssbuff.c
src/ssudp.c
src/test_ssudp.c
src/tun.c
src/tun_osx.c
src/ikcp.c
# src/test_proxy.c
)


############# skcptun #############
add_executable(skcptun ${SOURCE_FILES})
target_link_libraries(skcptun ssl)
target_link_libraries(skcptun crypto)
target_link_libraries(skcptun pthread)
target_link_libraries(skcptun ev)


############# static #############
# add_executable(skcptun_static ${SOURCE_FILES})
# target_link_libraries(skcptun_static ssl -static)
# target_link_libraries(skcptun_static crypto -static)
# target_link_libraries(skcptun_static pthread -static)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
