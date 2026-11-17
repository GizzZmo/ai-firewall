add_executable(aifw_tests
    test_types.cpp
    test_entropy.cpp
    test_feature_extractor.cpp
    test_flow_tracker.cpp
    test_rule_engine.cpp
    test_verdict_cache.cpp
    test_ai_engine.cpp
    test_coordinator.cpp
    test_learning.cpp
    test_config_ipc.cpp
    test_feature_parity.cpp
    test_dns_parser.cpp
    test_reject.cpp)
if(AIFW_WITH_ONNX)
    target_sources(aifw_tests PRIVATE test_onnx_model.cpp)
endif()
target_link_libraries(aifw_tests PRIVATE aifw::core aifw::options GTest::gtest_main)
target_compile_definitions(aifw_tests PRIVATE
    AIFW_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
include(GoogleTest)
gtest_discover_tests(aifw_tests DISCOVERY_TIMEOUT 60 DISCOVERY_MODE PRE_TEST)
