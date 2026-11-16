# Finner avhengigheter. Rekkefølge: vcpkg/systempakker (find_package) -> FetchContent.
include(FetchContent)
find_package(Threads REQUIRED)

macro(aifw_dep_or_fetch pkg target name repo tag)
    find_package(${pkg} CONFIG QUIET)
    if(NOT TARGET ${target})
        if(NOT AIFW_FETCH_DEPS)
            message(FATAL_ERROR "${pkg} ikke funnet. Installer via vcpkg eller sett AIFW_FETCH_DEPS=ON")
        endif()
        message(STATUS "${pkg} ikke funnet – henter ${repo}@${tag}")
        FetchContent_Declare(${name} GIT_REPOSITORY ${repo} GIT_TAG ${tag} GIT_SHALLOW TRUE)
        FetchContent_MakeAvailable(${name})
    else()
        message(STATUS "${pkg} funnet")
    endif()
endmacro()

set(JSON_BuildTests OFF CACHE INTERNAL "")
aifw_dep_or_fetch(nlohmann_json nlohmann_json::nlohmann_json nlohmann_json
    https://github.com/nlohmann/json.git v3.11.3)
aifw_dep_or_fetch(spdlog spdlog::spdlog spdlog https://github.com/gabime/spdlog.git v1.15.3)

if(AIFW_BUILD_TESTS)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)  # MSVC: samme CRT som resten
    find_package(GTest CONFIG QUIET)
    if(NOT TARGET GTest::gtest_main)
        if(NOT AIFW_FETCH_DEPS)
            message(FATAL_ERROR "GoogleTest ikke funnet")
        endif()
        FetchContent_Declare(googletest GIT_REPOSITORY https://github.com/google/googletest.git GIT_TAG v1.15.2 GIT_SHALLOW TRUE)
        FetchContent_MakeAvailable(googletest)
    endif()
endif()

if(AIFW_WITH_ONNX)
    find_package(onnxruntime CONFIG QUIET)  # vcpkg-porten "onnxruntime"
    if(NOT TARGET onnxruntime::onnxruntime)
        find_package(OnnxRuntime REQUIRED)  # cmake/FindOnnxRuntime.cmake (ONNXRUNTIME_DIR)
    endif()
endif()

if(WIN32)
    find_package(WinDivert REQUIRED)  # cmake/FindWinDivert.cmake (WINDIVERT_DIR)
endif()

# Kopierer runtime-filer ved siden av exe-filen: alle importerte DLL-er (WinDivert.dll,
# onnxruntime.dll, Qt-DLL-er via vcpkg) + WinDivert64.sys som ikke er en DLL.
function(aifw_copy_runtime_files target)
    if(NOT WIN32)
        return()
    endif()
    # WinDivert::WinDivert er SHARED IMPORTED, så listen er aldri tom.
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:${target}> $<TARGET_FILE_DIR:${target}>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${WINDIVERT_SYS} $<TARGET_FILE_DIR:${target}>
        COMMAND_EXPAND_LISTS
        COMMENT "Kopierer WinDivert.dll/.sys og andre runtime-DLL-er")
endfunction()
