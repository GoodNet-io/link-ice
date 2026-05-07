# ICE link plugin unit tests.
include(GoogleTest)

add_executable(test_ice
    test_ice.cpp
    test_ice_conformance.cpp)
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
