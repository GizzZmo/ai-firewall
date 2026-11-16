cmake_minimum_required(VERSION 3.24)

project(AiFirewall
    VERSION 0.1.0
    DESCRIPTION "KI-basert brannmur for Windows 11 (WinDivert + WFP + ONNX Runtime)"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Valg
# ---------------------------------------------------------------------------
option(AIFW_BUILD_TESTS   "Bygg GoogleTest-enhetstester"                     ON)
option(AIFW_BUILD_TOOLS   "Bygg verktøy (aifw_sim trafikk-simulator)"         ON)
option(AIFW_BUILD_SERVICE "Bygg Windows-tjenesten (kun Windows)"              ${WIN32})
option(AIFW_BUILD_GUI     "Bygg Qt 6 system tray-GUI"                         ${WIN32})
option(AIFW_WITH_ONNX     "Bruk ONNX Runtime for AI-inferens"                 ${WIN32})
option(AIFW_FETCH_DEPS    "Hent spdlog/nlohmann_json/GoogleTest med FetchContent hvis de ikke finnes" ON)
option(AIFW_WARNINGS_AS_ERRORS "Behandle advarsler som feil"                  OFF)

set(WINDIVERT_DIR   "" CACHE PATH "Rotmappe for utpakket WinDivert 2.2.x (inneholder include/ og x64/)")
set(ONNXRUNTIME_DIR "" CACHE PATH "Rotmappe for ONNX Runtime (include/ og lib/) hvis ikke via vcpkg")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

include(Dependencies)  # cmake/Dependencies.cmake

# ---------------------------------------------------------------------------
# Felles kompilatorvalg som INTERFACE-target (ingen globale flagg)
# ---------------------------------------------------------------------------
add_library(aifw_options INTERFACE)
add_library(aifw::options ALIAS aifw_options)
if(MSVC)
    target_compile_options(aifw_options INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc
        $<$<BOOL:${AIFW_WARNINGS_AS_ERRORS}>:/WX>)
    target_compile_definitions(aifw_options INTERFACE
        WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00)
else()
    target_compile_options(aifw_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
        $<$<BOOL:${AIFW_WARNINGS_AS_ERRORS}>:-Werror>)
    if(WIN32)  # MinGW/clang på Windows
        target_compile_definitions(aifw_options INTERFACE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    endif()
endif()

# ---------------------------------------------------------------------------
# Kjernebibliotek
# ---------------------------------------------------------------------------
add_library(aifw_core STATIC
    src/core/Types.cpp
    src/core/Entropy.cpp
    src/core/FeatureExtractor.cpp
    src/core/FlowTracker.cpp
    src/core/RuleEngine.cpp
    src/core/Config.cpp
    src/core/VerdictCache.cpp
    src/core/Notifier.cpp
    src/core/Model.cpp
    src/core/AIDecisionEngine.cpp
    src/core/LearningMode.cpp
    src/core/DecisionCoordinator.cpp
    src/core/IpcProtocol.cpp
    src/core/Log.cpp
    src/core/FirewallCore.cpp
)
add_library(aifw::core ALIAS aifw_core)
target_include_directories(aifw_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_link_libraries(aifw_core
    PUBLIC  nlohmann_json::nlohmann_json spdlog::spdlog Threads::Threads
    PRIVATE aifw::options)

if(AIFW_WITH_ONNX)
    target_sources(aifw_core PRIVATE src/core/OnnxModel.cpp)
    target_compile_definitions(aifw_core PUBLIC AIFW_WITH_ONNX=1)
    target_link_libraries(aifw_core PUBLIC onnxruntime::onnxruntime)
endif()

if(WIN32)
    target_sources(aifw_core PRIVATE
        src/core/FeatureExtractorWin.cpp
        src/core/PacketEngine.cpp
        src/core/ProcessResolver.cpp
        src/core/WfpManager.cpp
        src/core/WinUtil.cpp)
    target_link_libraries(aifw_core PUBLIC WinDivert::WinDivert fwpuclnt ws2_32 rpcrt4 advapi32)
endif()

# ---------------------------------------------------------------------------
# Windows-tjeneste
# ---------------------------------------------------------------------------
if(AIFW_BUILD_SERVICE)
    if(NOT WIN32)
        message(FATAL_ERROR "AIFW_BUILD_SERVICE krever Windows")
    endif()
    add_executable(aifw_service
        src/service/main.cpp
        src/service/ServiceHost.cpp
        src/service/PipeServer.cpp
        src/service/WfpRuleSink.cpp)
    target_link_libraries(aifw_service PRIVATE aifw::core aifw::options)
    if(MSVC)
        # Krever administrator ved oppstart (UAC-manifest).
        target_link_options(aifw_service PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
    else()
        target_link_options(aifw_service PRIVATE -municode)  # MinGW/clang: wmain som inngangspunkt
    endif()
    aifw_copy_runtime_files(aifw_service)
endif()

# ---------------------------------------------------------------------------
# Qt 6 GUI
# ---------------------------------------------------------------------------
if(AIFW_BUILD_GUI)
    find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Network)
    qt_standard_project_setup()
    qt_add_executable(aifw_gui WIN32
        src/gui/main.cpp
        src/gui/TrayApp.cpp src/gui/TrayApp.hpp
        src/gui/ServiceClient.cpp src/gui/ServiceClient.hpp
        src/gui/LogWindow.cpp src/gui/LogWindow.hpp)
    target_link_libraries(aifw_gui PRIVATE Qt6::Widgets Qt6::Network aifw::options)
endif()

# ---------------------------------------------------------------------------
# Verktøy og tester
# ---------------------------------------------------------------------------
if(AIFW_BUILD_TOOLS)
    add_executable(aifw_sim src/tools/aifw_sim.cpp)
    target_link_libraries(aifw_sim PRIVATE aifw::core aifw::options)
endif()

if(AIFW_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(DIRECTORY config/ DESTINATION config)
if(TARGET aifw_service)
    install(TARGETS aifw_service RUNTIME DESTINATION .)
endif()
if(TARGET aifw_gui)
    install(TARGETS aifw_gui RUNTIME DESTINATION .)
endif()
