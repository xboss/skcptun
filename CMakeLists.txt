cmake_minimum_required(VERSION 3.0.0)
project(skcptun VERSION 0.1.0)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# include(CTest)
# enable_testing()

link_directories("/usr/local/lib")

aux_source_directory(./src DIR_SRCS)
aux_source_directory(./src/3rd/cJSON DIR_SRCS_CJSON)
aux_source_directory(./src/3rd/kcp DIR_SRCS_KCP)
aux_source_directory(./src/3rd/uthash DIR_SRCS_UTHASH)

add_executable(skcptun ${DIR_SRCS} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})
target_link_libraries(skcptun ssl)
target_link_libraries(skcptun crypto)
target_link_libraries(skcptun ev)

############# test #############
# aux_source_directory(./test DIR_SRCS_TEST)
SET(TEST_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test/test_tcp_serv.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_tcp.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_utils.c)
add_executable(test_tcp_serv  ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH} ${TEST_SRC_FILES})
target_link_libraries(test_tcp_serv ssl)
target_link_libraries(test_tcp_serv crypto)
target_link_libraries(test_tcp_serv ev)

SET(TEST_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test/test_kcp_serv.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_kcp.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skcp.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_cipher.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_utils.c)
add_executable(test_kcp_serv ${DIR_SRCS_TEST} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH} ${TEST_SRC_FILES})
target_link_libraries(test_kcp_serv ssl)
target_link_libraries(test_kcp_serv crypto)
target_link_libraries(test_kcp_serv ev)

SET(TEST_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test/test_kcp_cli.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_kcp.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skcp.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_cipher.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skt_utils.c)
add_executable(test_kcp_cli ${DIR_SRCS_TEST} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH} ${TEST_SRC_FILES})
target_link_libraries(test_kcp_cli ssl)
target_link_libraries(test_kcp_cli crypto)
target_link_libraries(test_kcp_cli ev)

SET(TEST_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test/test_skcp_protocol.c ${CMAKE_CURRENT_SOURCE_DIR}/src/skcp_protocol.c)
add_executable(test_skcp_protocol  ${TEST_SRC_FILES})


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)