# Finner ONNX Runtime fra en offisiell release (onnxruntime-win-x64-<ver>.zip / -linux-x64-<ver>.tgz).
# Sett -DONNXRUNTIME_DIR=<mappe med include/ og lib/>
# Gir: onnxruntime::onnxruntime, ONNXRUNTIME_DLLS
find_path(ONNXRUNTIME_INCLUDE_DIR onnxruntime_cxx_api.h
    HINTS ${ONNXRUNTIME_DIR} ENV ONNXRUNTIME_DIR
    PATH_SUFFIXES include include/onnxruntime include/onnxruntime/core/session)
find_library(ONNXRUNTIME_LIBRARY onnxruntime HINTS ${ONNXRUNTIME_DIR} ENV ONNXRUNTIME_DIR PATH_SUFFIXES lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OnnxRuntime REQUIRED_VARS ONNXRUNTIME_INCLUDE_DIR ONNXRUNTIME_LIBRARY
    FAIL_MESSAGE "ONNX Runtime ikke funnet. Bruk vcpkg-featuren 'onnx' eller sett -DONNXRUNTIME_DIR=<mappe>")

if(OnnxRuntime_FOUND AND NOT TARGET onnxruntime::onnxruntime)
    if(WIN32)
        file(GLOB ONNXRUNTIME_DLLS "${ONNXRUNTIME_DIR}/lib/*.dll")
        add_library(onnxruntime::onnxruntime SHARED IMPORTED)
        list(GET ONNXRUNTIME_DLLS 0 _ort_dll)
        set_target_properties(onnxruntime::onnxruntime PROPERTIES
            IMPORTED_IMPLIB "${ONNXRUNTIME_LIBRARY}" IMPORTED_LOCATION "${_ort_dll}")
    else()
        add_library(onnxruntime::onnxruntime SHARED IMPORTED)
        set_target_properties(onnxruntime::onnxruntime PROPERTIES IMPORTED_LOCATION "${ONNXRUNTIME_LIBRARY}")
    endif()
    set_target_properties(onnxruntime::onnxruntime PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${ONNXRUNTIME_INCLUDE_DIR}")
endif()
mark_as_advanced(ONNXRUNTIME_INCLUDE_DIR ONNXRUNTIME_LIBRARY)
