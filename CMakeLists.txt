cmake_minimum_required(VERSION 3.5)
project(cryptosocket)

set(SOURCE_FILES
    src/smsdk_ext.cpp
    src/smn_cryptosocket.cpp
    src/extension.cpp
    src/encrypted_socket.cpp)

if(NOT TARGET)
    set(TARGET linux)
endif()
set (CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -DSOURCEMOD_BUILD -fno-strict-aliasing -m32")

if(${TARGET} STREQUAL linux)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_LINUX")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32 -D_STAT_DEFINED -DSODIUM_STATIC")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

set(CMAKE_SKIP_BUILD_RPATH true)
set(CMAKE_VERBOSE_MAKEFILE false)

include_directories(sourcemod/public sourcepawn/include amtl amtl/amtl)

add_library(cryptosocket.ext SHARED ${SOURCE_FILES})

if(${TARGET} STREQUAL linux)
    target_link_libraries(cryptosocket.ext -lpthread -Wl,--no-undefined -Wl,-Bstatic -lsodium -static-libgcc -lboost_thread -lboost_system -lstdc++ -Wl,-Bdynamic -lm -ldl)
else()
    target_link_libraries(cryptosocket.ext -lpthread -Wl,--no-undefined -Wl,-Bstatic -lsodium -static-libgcc -lboost_thread-mt -lboost_system -lstdc++ -Wl,-Bdynamic -lm -lwsock32 -lgdi32 -lws2_32)
endif()

set_target_properties(cryptosocket.ext PROPERTIES PREFIX "")

if(NOT ${TARGET} STREQUAL linux)
    set_target_properties(rpc.ext PROPERTIES SUFFIX ".dll")
endif()