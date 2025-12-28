cmake_minimum_required(VERSION 3.10)

project(openjvs
        VERSION "3.7"
		LANGUAGES "C"
        DESCRIPTION "An emulator for arcade JVS I/O boards"
        HOMEPAGE_URL "https://github.com/OpenJVS"
)

find_package(Threads REQUIRED)

# Optionally find libgpiod for modern GPIO character-device API
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
	pkg_check_modules(LIBGPIOD QUIET libgpiod)
endif()

configure_file(src/version.h.in version.h)

include_directories(${THREAD_INLCUDE_DIRS} ${PROJECT_SOURCE_DIR}/src ${PROJECT_BINARY_DIR})

# Add libgpiod includes if found
if(LIBGPIOD_FOUND)
	include_directories(${LIBGPIOD_INCLUDE_DIRS})
endif()

FILE(GLOB_RECURSE Sources src/*.c) #Assume we want to include everything from src/

add_executable( ${PROJECT_NAME} ${Sources} )

set_target_properties(${PROJECT_NAME} PROPERTIES
        C_STANDARD 99
)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)

# Enable libgpiod support if found
if(LIBGPIOD_FOUND)
	target_compile_definitions(${PROJECT_NAME} PRIVATE USE_LIBGPIOD)
	target_link_libraries(${PROJECT_NAME} ${LIBGPIOD_LIBRARIES})
endif()

target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT} m)

install(TARGETS ${PROJECT_NAME}
		COMPONENT ${PROJECT_NAME}
		RUNTIME DESTINATION "bin/"
		LIBRARY DESTINATION "lib/"
)

install(FILES ${CMAKE_SOURCE_DIR}/docs/openjvs.service ${CMAKE_SOURCE_DIR}/docs/openjvs@.service
		COMPONENT ${PROJECT_NAME}
		DESTINATION "/etc/systemd/system/"
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/docs/openjvs
		COMPONENT ${PROJECT_NAME}
		DESTINATION "/etc/"
)

SET(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "bobby@dilley.uk") #required
INCLUDE(CPack)
