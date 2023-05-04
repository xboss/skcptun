cmake_minimum_required(VERSION 3.0.0)
project(skcptun VERSION 0.1.0)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR}")

link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/skcp/src)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/uthash)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/EasyTCP/src)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/lua)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/skcp/src DIR_SRCS_SKCP)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/uthash DIR_SRCS_UTHASH)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/EasyTCP/src DIR_SRCS_EASYTCP)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/lua DIR_SRCS_LUA)

list(REMOVE_ITEM DIR_SRCS_LUA ${PROJECT_SOURCE_DIR}/src/3rd/lua/lua.c)
list(REMOVE_ITEM DIR_SRCS_LUA ${PROJECT_SOURCE_DIR}/src/3rd/lua/onelua.c)

# ############# main #############
add_executable(skcptun ${DIR_SRCS} ${DIR_SRCS_SKCP} ${DIR_SRCS_UTHASH} ${DIR_SRCS_EASYTCP} ${DIR_SRCS_LUA})
target_link_libraries(skcptun ssl)
target_link_libraries(skcptun crypto)
target_link_libraries(skcptun ev)
target_link_libraries(skcptun m)

# ############# static #############
# add_executable(skcptun_static ${DIR_SRCS} ${DIR_SRCS_SKCP} ${DIR_SRCS_UTHASH} ${DIR_SRCS_EASYTCP} ${DIR_SRCS_LUA})
# target_link_libraries(skcptun_static ssl -static)
# target_link_libraries(skcptun_static crypto -static)
# target_link_libraries(skcptun_static ev -static)
# target_link_libraries(skcptun_static m -static)
# target_link_libraries(skcptun_static dl -static)

############# test #############
# add_executable(test_config ${DIR_SRCS} ${DIR_SRCS_SKCP} ${DIR_SRCS_UTHASH} ${DIR_SRCS_EASYTCP})
# target_link_libraries(test_config ssl)
# target_link_libraries(test_config crypto)
# target_link_libraries(test_config ev)
# target_link_libraries(test_config luajit)


