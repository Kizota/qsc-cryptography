cmake_minimum_required(VERSION 3.10)
project(BIKE_KEM C)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_STANDARD 99)

# For MSVC
if(MSVC)
    set(CMAKE_C_FLAGS_RELEASE "/O2 /MD")
    set(CMAKE_C_FLAGS_DEBUG "/Zi")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra")
endif()

# Main library - only core implementation files
set(SOURCES
    src/bike_kem.c
    src/crypto.c
    src/gf2x.c
    src/decoder.c
)

add_library(bike_kem STATIC ${SOURCES})
target_include_directories(bike_kem PUBLIC include)

# Executable for testing
add_executable(bike_test src/test_bike.c ${SOURCES})
target_include_directories(bike_test PRIVATE include)
if(MSVC)
    target_link_libraries(bike_test bike_kem)
else()
    target_link_libraries(bike_test bike_kem m)
endif()

# Demo executable
add_executable(bike_demo src/demo.c ${SOURCES})
target_include_directories(bike_demo PRIVATE include)
if(MSVC)
    target_link_libraries(bike_demo bike_kem)
else()
    target_link_libraries(bike_demo bike_kem m)
endif()

# Evaluation executable
add_executable(bike_eval src/evaluation.c ${SOURCES})
target_include_directories(bike_eval PRIVATE include)
if(MSVC)
    target_link_libraries(bike_eval bike_kem)
else()
    target_link_libraries(bike_eval bike_kem m)
endif()

# Optional: Build as shared library
add_library(bike_kem_shared SHARED ${SOURCES})
set_target_properties(bike_kem_shared PROPERTIES OUTPUT_NAME "bike_kem")
target_include_directories(bike_kem_shared PUBLIC include)

# Installation
install(TARGETS bike_kem bike_kem_shared
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
