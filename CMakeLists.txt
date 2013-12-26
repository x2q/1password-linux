cmake_minimum_required(VERSION 2.8.10)
project(1pass)

include(FindPkgConfig)
pkg_check_modules(PKG_GTKPLUS2 gtk+-2.0)
if(NOT PKG_GTKPLUS2_FOUND)
    MESSAGE(FATAL_ERROR "Couldn't find GTK+ libs.")
endif()

# Set up some sanity stuff...
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    SET(LINUX TRUE)
endif()
if(APPLE)
    SET(MACOSX TRUE)
endif()
if(MSVC)
    SET(WINDOWS TRUE)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "None Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()
SET(DEBUG FALSE)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(DEBUG TRUE)
endif()


add_definitions(-D_REENTRANT=1)

if(DEBUG)
    add_definitions(-DDEBUG=1)
    add_definitions(-D_DEBUG=1)
else()
    add_definitions(-DNDEBUG=1)
    add_definitions(-D_NDEBUG=1)
endif()

if(WINDOWS)
    add_definitions(-DWIN32=1)
    add_definitions(-DOS_WIN32=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE=1)
endif()

if(LINUX)
    set(CMAKE_SKIP_RPATH ON CACHE BOOL "Skip RPATH" FORCE)
    add_definitions(-D_FILE_OFFSET_BITS=64)
    add_definitions(-D_LARGEFILE_SOURCE=1)
endif()

if(LINUX OR MACOSX)
    if(DEBUG)
        add_definitions(-O0 -ggdb3)
    endif(DEBUG)
    add_definitions(-pthread)
    add_definitions(-pipe -fsigned-char)
    set(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}" CACHE STRING "compile flags" FORCE)

    add_definitions(-DLUA_USE_MKSTEMP=1)  # as opposed to tmpnam(), yuck!
    add_definitions(-DLUA_USE_ULONGJMP=1)
endif()


include(TestBigEndian)
test_big_endian(ONEPASS_IS_BIGENDIAN)
if(ONEPASS_IS_BIGENDIAN)
    add_definitions(-DPLATFORM_BIGENDIAN=1)
else()
    add_definitions(-DPLATFORM_LITTLEENDIAN=1)
endif()

include_directories("lua")

add_executable(1pass
    1pass.c
    keyhook.c
    pkcs5_pbkdf2.c
    aes.c
    md5.c
    sha1.c
    base64.c
    lua/lapi.c
    lua/ldebug.c
    lua/ldo.c
    lua/ldump.c
    lua/lfunc.c
    lua/lgc.c
    lua/lmem.c
    lua/lobject.c
    lua/lopcodes.c
    lua/lstate.c
    lua/lstring.c
    lua/ltable.c
    lua/ltm.c
    lua/lundump.c
    lua/lvm.c
    lua/lzio.c
    lua/lauxlib.c
    lua/lbaselib.c
    lua/lstrlib.c
    lua/ltablib.c
    lua/lctype.c
    lua/lparser.c
    lua/llex.c
    lua/lcode.c
    lua/linit.c
    lua/lctype.c
    lua/ldblib.c
    lua/liolib.c
    lua/lmathlib.c
    lua/loslib.c
    lua/lbitlib.c
    lua/lcorolib.c
    lua/loadlib.c
)

include_directories(${PKG_GTKPLUS2_INCLUDE_DIRS})
target_link_libraries(1pass ${PKG_GTKPLUS2_LIBRARIES})

if(LINUX)
    set_target_properties(1pass PROPERTIES LINK_FLAGS "-Wl,-rpath,$ORIGIN")
    target_link_libraries(1pass "m")
    target_link_libraries(1pass "Xtst")
    target_link_libraries(1pass "X11")
endif()

# end of CMakeLists.txt ...

