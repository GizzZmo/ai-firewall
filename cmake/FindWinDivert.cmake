# Finner WinDivert 2.2.x (https://reqrypt.org/windivert.html).
# Sett -DWINDIVERT_DIR=C:/libs/WinDivert-2.2.2-A
# Gir: WinDivert::WinDivert, WINDIVERT_DLL, WINDIVERT_SYS
find_path(WINDIVERT_INCLUDE_DIR windivert.h HINTS ${WINDIVERT_DIR} ENV WINDIVERT_DIR PATH_SUFFIXES include)
find_library(WINDIVERT_LIBRARY WinDivert HINTS ${WINDIVERT_DIR} ENV WINDIVERT_DIR PATH_SUFFIXES x64)
find_file(WINDIVERT_DLL WinDivert.dll HINTS ${WINDIVERT_DIR} ENV WINDIVERT_DIR PATH_SUFFIXES x64)
find_file(WINDIVERT_SYS WinDivert64.sys HINTS ${WINDIVERT_DIR} ENV WINDIVERT_DIR PATH_SUFFIXES x64)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WinDivert
    REQUIRED_VARS WINDIVERT_INCLUDE_DIR WINDIVERT_LIBRARY WINDIVERT_DLL WINDIVERT_SYS
    FAIL_MESSAGE "WinDivert ikke funnet. Last ned WinDivert-2.2.2-A.zip og sett -DWINDIVERT_DIR=<mappe>")

if(WinDivert_FOUND AND NOT TARGET WinDivert::WinDivert)
    add_library(WinDivert::WinDivert SHARED IMPORTED)
    set_target_properties(WinDivert::WinDivert PROPERTIES
        IMPORTED_IMPLIB "${WINDIVERT_LIBRARY}"
        IMPORTED_LOCATION "${WINDIVERT_DLL}"
        INTERFACE_INCLUDE_DIRECTORIES "${WINDIVERT_INCLUDE_DIR}")
endif()
mark_as_advanced(WINDIVERT_INCLUDE_DIR WINDIVERT_LIBRARY WINDIVERT_DLL WINDIVERT_SYS)
