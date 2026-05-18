# ICE link plugin unit tests.
include(GoogleTest)

add_executable(test_ice
    test_ice.cpp
    test_ice_composer.cpp
    test_ice_conformance.cpp
    test_ice_multi_turn.cpp
    test_ice_pmtu.cpp
    test_ice_turn_framing.cpp
    test_ice_dns.cpp
    test_ice_mdns.cpp
    test_ice_lite_and_pred.cpp
    test_ice_tcp.cpp
    test_ice_auto_restart.cpp)
target_link_libraries(test_ice PRIVATE
    GoodNet::sdk
    goodnet_ice_objects
    asio::asio
    Threads::Threads
    OpenSSL::Crypto
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_ice PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_ice)
endif()
gtest_discover_tests(test_ice
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
