cmake_minimum_required(VERSION 3.0.0)
project(skcptun VERSION 0.1.0)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR}")

link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/core)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/cJSON)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/uthash)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/kcp)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/core DIR_SRCS_CORE)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/cJSON DIR_SRCS_CJSON)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/kcp DIR_SRCS_KCP)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/uthash DIR_SRCS_UTHASH)

# ############# main #############
add_executable(skcptun ${DIR_SRCS} ${DIR_SRCS_CORE} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
target_link_libraries(skcptun ssl)
target_link_libraries(skcptun crypto)
target_link_libraries(skcptun ev)

# ############# static #############
# add_executable(skcptun_static ${DIR_SRCS} ${DIR_SRCS_CORE} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
# target_link_libraries(skcptun_static ssl -static)
# target_link_libraries(skcptun_static crypto -static)
# target_link_libraries(skcptun_static ev -static)

# ############# test #############
SET(TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/test/test_tcp_serv.c ${DIR_SRCS_CORE} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
add_executable(test_tcp_serv ${TEST_SRC_FILES})
target_link_libraries(test_tcp_serv ssl)
target_link_libraries(test_tcp_serv crypto)
target_link_libraries(test_tcp_serv ev)

SET(TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/test/test_kcp_serv.c ${DIR_SRCS_CORE} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
add_executable(test_kcp_serv ${TEST_SRC_FILES})
target_link_libraries(test_kcp_serv ssl)
target_link_libraries(test_kcp_serv crypto)
target_link_libraries(test_kcp_serv ev)

SET(TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/test/test_kcp_cli.c ${DIR_SRCS_CORE} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
add_executable(test_kcp_cli ${TEST_SRC_FILES})
target_link_libraries(test_kcp_cli ssl)
target_link_libraries(test_kcp_cli crypto)
target_link_libraries(test_kcp_cli ev)

SET(TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/test/test_skcp_protocol.c ${DIR_SRCS_CORE} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
add_executable(test_skcp_protocol  ${TEST_SRC_FILES})
target_link_libraries(test_skcp_protocol ssl)
target_link_libraries(test_skcp_protocol crypto)
target_link_libraries(test_skcp_protocol ev)

# SET(TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/src/skt_tuntap_osx.c ${PROJECT_SOURCE_DIR}/src/skt_utils.c)
# add_executable(test_tuntap_osx  ${TEST_SRC_FILES})

