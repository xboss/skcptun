cmake_minimum_required(VERSION 3.0.0)
project(skcptun VERSION 0.1.0)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# include(CTest)
# enable_testing()

FIND_LIBRARY(SSL_LIB ssl /usr/lib  /usr/local/lib NO_DEFAULT_PATH)
FIND_LIBRARY(CRYPTO_LIB crypto /usr/lib  /usr/local/lib NO_DEFAULT_PATH)
FIND_LIBRARY(EV_LIB ev /usr/lib  /usr/local/lib NO_DEFAULT_PATH)
link_libraries(${SSL_LIB})
link_libraries(${CRYPTO_LIB})
link_libraries(${EV_LIB})

aux_source_directory(./src DIR_SRCS)
aux_source_directory(./src/3rd/cJSON DIR_SRCS_CJSON)
aux_source_directory(./src/3rd/kcp DIR_SRCS_KCP)
aux_source_directory(./src/3rd/uthash DIR_SRCS_UTHASH)

add_executable(skcptun ${DIR_SRCS} ${DIR_SRCS_CJSON} ${DIR_SRCS_KCP} ${DIR_SRCS_UTHASH})

# target_link_libraries(skcptun ssl)
# target_link_libraries(skcptun crypto)
# target_link_libraries(skcptun ev)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)