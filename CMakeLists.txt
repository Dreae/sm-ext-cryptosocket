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
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")
    add_definitions(-DWIN32 -DSODIUM_STATIC)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pipe -DSOURCEMOD_BUILD -fno-strict-aliasing -m32")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3")
endif()

if(${TARGET} STREQUAL linux)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_LINUX")
endif()

set(CMAKE_SKIP_BUILD_RPATH true)
set(CMAKE_VERBOSE_MAKEFILE false)

include_directories(sourcemod/public sourcepawn/include amtl amtl/amtl)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    include_directories(C:/Libraries/boost_1_73_0 C:/Libraries/libsodium-stable/src/libsodium/include)
    link_directories(C:/Libraries/boost_1_73_0/stage/lib)
endif()

add_library(cryptosocket.ext SHARED ${SOURCE_FILES})

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    find_library(LIBSODIUM libsodium.lib HINTS C:/Libraries/libsodium-stable/bin/Win32/Release/v142/static)
    target_link_libraries(cryptosocket.ext ${LIBSODIUM})
else()
    target_link_libraries(cryptosocket.ext -lpthread -Wl,--no-undefined -Wl,-Bstatic -lsodium -static-libgcc -lboost_system -static-libstdc++ -Wl,-Bdynamic)
endif()


set_target_properties(cryptosocket.ext PROPERTIES PREFIX "")

if(NOT ${TARGET} STREQUAL linux)
    set_target_properties(cryptosocket.ext PROPERTIES SUFFIX ".dll")
endif()