cmake_minimum_required(VERSION 3.5)
project(cryptosocket)

set(SOURCE_FILES
    src/smsdk_ext.cpp
    src/smn_cryptosocket.cpp
    src/extension.cpp
    src/encrypted_socket.cpp
    src/crypto_ev.cpp)

if(NOT TARGET)
    set(TARGET linux)
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pipe -DSOURCEMOD_BUILD -fno-strict-aliasing -m32")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3")

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
    target_link_libraries(cryptosocket.ext -lpthread -Wl,--no-undefined -Wl,-Bstatic -lsodium -static-libgcc -lboost_system -static-libstdc++ -Wl,-Bdynamic)
else()
    target_link_libraries(cryptosocket.ext -Wl,--no-undefined -Wl,-Bstatic -lsodium -static-libgcc -lboost_system -static-libstdc++ -lstdc++ -lpthread -Wl,-Bdynamic -lwsock32 -lgdi32 -lws2_32)
endif()


set_target_properties(cryptosocket.ext PROPERTIES PREFIX "")

if(NOT ${TARGET} STREQUAL linux)
    set_target_properties(cryptosocket.ext PROPERTIES SUFFIX ".dll")
endif()