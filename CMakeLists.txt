cmake_minimum_required(VERSION 3.10)

project(openjvs
        VERSION "4.5.2"
        LANGUAGES "C"
        DESCRIPTION "An emulator for arcade JVS I/O boards"
        HOMEPAGE_URL "https://github.com/dazzaXx/OpenJVS-Updated-libgpiod"
)

find_package(Threads REQUIRED)

# Optionally find libgpiod for modern GPIO character-device API
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBGPIOD QUIET libgpiod)
endif()

configure_file(src/version.h.in version.h)

# Source files - explicitly listed for better dependency tracking
set(SOURCES
    src/openjvs.c
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
)

# Add libgpiod includes if found
if(LIBGPIOD_FOUND)
    target_include_directories(${PROJECT_NAME} PRIVATE ${LIBGPIOD_INCLUDE_DIRS})
endif()

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    m
)

# Enable libgpiod support if found
if(LIBGPIOD_FOUND)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_LIBGPIOD)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBGPIOD_LIBRARIES})
    
    # Detect libgpiod major version to handle API differences
    string(REGEX MATCH "^([0-9]+)" LIBGPIOD_VERSION_MAJOR "${LIBGPIOD_VERSION}")
    message(STATUS "Found libgpiod version: ${LIBGPIOD_VERSION} (major: ${LIBGPIOD_VERSION_MAJOR})")
    if(LIBGPIOD_VERSION_MAJOR GREATER_EQUAL 2)
        target_compile_definitions(${PROJECT_NAME} PRIVATE GPIOD_API_V2)
        message(STATUS "Using libgpiod v2 API")
    else()
        message(STATUS "Using libgpiod v1 API")
    endif()
endif()

# Installation rules
install(TARGETS ${PROJECT_NAME}
    COMPONENT ${PROJECT_NAME}
    RUNTIME DESTINATION "bin/"
    LIBRARY DESTINATION "lib/"
)

install(FILES
    ${CMAKE_SOURCE_DIR}/docs/openjvs.service
    ${CMAKE_SOURCE_DIR}/docs/openjvs@.service
    COMPONENT ${PROJECT_NAME}
    DESTINATION "/etc/systemd/system/"
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/docs/openjvs
    COMPONENT ${PROJECT_NAME}
    DESTINATION "/etc/"
)

# CPack configuration for DEB package generation
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "bobby@dilley.uk")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)
