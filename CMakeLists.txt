cmake_minimum_required(VERSION 3.0.0)
project(skcptun VERSION 0.1.0)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR}")

link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/skcp)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/uthash)
include_directories(${PROJECT_SOURCE_DIR}/src/3rd/EasyTCP)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/skcp DIR_SRCS_SKCP)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/uthash DIR_SRCS_UTHASH)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/3rd/EasyTCP DIR_SRCS_EASYTCP)

# ############# main #############
# add_executable(skcptun ${DIR_SRCS} ${DIR_SRCS_SKCP} ${DIR_SRCS_CJSON} ${DIR_SRCS_UTHASH} ${DIR_SRCS_EASYTCP})
# target_link_libraries(skcptun ssl)
# target_link_libraries(skcptun crypto)
# target_link_libraries(skcptun ev)

# ############# static #############
# add_executable(skcptun_static ${DIR_SRCS} ${DIR_SRCS_SKCP} ${DIR_SRCS_CJSON} ${DIR_SRCS_UTHASH})
# target_link_libraries(skcptun_static ssl -static)
# target_link_libraries(skcptun_static crypto -static)
# target_link_libraries(skcptun_static ev -static)

############# test #############
# add_executable(test_config ${DIR_SRCS} ${DIR_SRCS_SKCP} ${DIR_SRCS_UTHASH} ${DIR_SRCS_EASYTCP})
# target_link_libraries(test_config ssl)
# target_link_libraries(test_config crypto)
# target_link_libraries(test_config ev)
# target_link_libraries(test_config luajit)


