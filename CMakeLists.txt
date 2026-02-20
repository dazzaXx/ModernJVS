cmake_minimum_required(VERSION 3.10)

project(modernjvs
        VERSION "5.7.0"
        LANGUAGES "C"
        DESCRIPTION "JVS I/O Emulator"
        HOMEPAGE_URL "https://github.com/dazzaXx/ModernJVS"
)

find_package(Threads REQUIRED)

# libgpiod is required for GPIO character-device API
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBGPIOD REQUIRED libgpiod)

configure_file(src/version.h.in version.h)

# Source files - explicitly listed for better dependency tracking
set(SOURCES
    src/modernjvs.c
    src/console/cli.c
    src/console/config.c
    src/console/debug.c
    src/console/watchdog.c
    src/controller/input.c
    src/controller/threading.c
    src/ffb/ffb.c
    src/hardware/device.c
    src/hardware/rotary.c
    src/jvs/io.c
    src/jvs/jvs.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES
        C_STANDARD 99
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}
    ${LIBGPIOD_INCLUDE_DIRS}
)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    m
    ${LIBGPIOD_LIBRARIES}
)

# Detect libgpiod major version to handle API differences
string(REGEX MATCH "^([0-9]+)" LIBGPIOD_VERSION_MAJOR "${LIBGPIOD_VERSION}")
message(STATUS "Found libgpiod version: ${LIBGPIOD_VERSION} (major: ${LIBGPIOD_VERSION_MAJOR})")
if(LIBGPIOD_VERSION_MAJOR GREATER_EQUAL 2)
    target_compile_definitions(${PROJECT_NAME} PRIVATE GPIOD_API_V2)
    message(STATUS "Using libgpiod v2 API")
else()
    message(STATUS "Using libgpiod v1 API")
endif()

# Installation rules
install(TARGETS ${PROJECT_NAME}
    COMPONENT ${PROJECT_NAME}
    RUNTIME DESTINATION "bin/"
    LIBRARY DESTINATION "lib/"
)

install(FILES
    ${CMAKE_SOURCE_DIR}/docs/modernjvs.service
    ${CMAKE_SOURCE_DIR}/docs/modernjvs@.service
    COMPONENT ${PROJECT_NAME}
    DESTINATION "/etc/systemd/system/"
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/docs/modernjvs
    COMPONENT ${PROJECT_NAME}
    DESTINATION "/etc/"
)

install(FILES
    ${CMAKE_SOURCE_DIR}/docs/wiimote.conf
    COMPONENT ${PROJECT_NAME}
    DESTINATION "/etc/modules-load.d/"
)

# WebUI – Python3 local-network web interface (opt-out with -DENABLE_WEBUI=OFF)
option(ENABLE_WEBUI "Include the WebUI server in the installation" ON)
if(ENABLE_WEBUI)
    message(STATUS "WebUI: enabled (use -DENABLE_WEBUI=OFF to exclude)")
    install(PROGRAMS
        ${CMAKE_SOURCE_DIR}/src/webui/modernjvs-webui
        COMPONENT ${PROJECT_NAME}
        DESTINATION "bin/"
    )

    install(FILES
        ${CMAKE_SOURCE_DIR}/docs/modernjvs-webui.service
        COMPONENT ${PROJECT_NAME}
        DESTINATION "/etc/systemd/system/"
    )

    install(FILES
        ${CMAKE_SOURCE_DIR}/docs/modernjvs2.png
        COMPONENT ${PROJECT_NAME}
        DESTINATION "/usr/share/modernjvs/"
    )
else()
    message(STATUS "WebUI: disabled")
endif()

# CPack configuration for DEB package generation
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "dazzaXx")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)
