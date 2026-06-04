cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_ice
        VERSION   1.0.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        if(COMMAND goodnet_patch_rapidcheck_targets)
            goodnet_patch_rapidcheck_targets()
        endif()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# ICE link plugin — full ICE controlled / controlling FSM with STUN
# srflx and TURN relay candidates per RFC 8445 / 5389 / 5766.

find_package(OpenSSL REQUIRED)

add_library(goodnet_ice_objects OBJECT
    link_ice.cpp
    session.cpp
    stun.cpp
    turn.cpp
    dns_ext_client.cpp
    portmap_ext_client.cpp
    mdns.cpp
    path_mtu.cpp
    interface_watcher.cpp
)
target_link_libraries(goodnet_ice_objects PUBLIC
    GoodNet::sdk asio::asio Threads::Threads OpenSSL::Crypto PkgConfig::SODIUM)
target_compile_features(goodnet_ice_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_ice_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_ice_objects
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${SODIUM_INCLUDE_DIRS})
if(SODIUM_CFLAGS)
    target_compile_options(goodnet_ice_objects PRIVATE ${SODIUM_CFLAGS})
endif()
set_target_properties(goodnet_ice_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_ice
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_ice
    PRIVATE goodnet_ice_objects asio::asio Threads::Threads OpenSSL::Crypto PkgConfig::SODIUM)
target_include_directories(goodnet_link_ice
    PRIVATE ${SODIUM_INCLUDE_DIRS})
if(SODIUM_CFLAGS)
    target_compile_options(goodnet_link_ice PRIVATE ${SODIUM_CFLAGS})
endif()

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
