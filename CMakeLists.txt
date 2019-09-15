cmake_minimum_required(VERSION 3.5)
project(libsslpp)

option(ADD_COVERAGE "use codecoverage" OFF)
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 17)
add_definitions(-Weffc++ -Wall -Wextra)

set ("${PROJECT}_BINARY_DIR"  out)
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/${${PROJECT}_BINARY_DIR})
set (TEST_OUTPUT_PATH ${EXECUTABLE_OUTPUT_PATH}/test)
set (EXAMPLE_OUTPUT_PATH ${EXECUTABLE_OUTPUT_PATH}/example)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/out/lib)
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/out/lib)
set (COVERAGE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/out/coverage)

enable_testing()
add_subdirectory(lib)
add_subdirectory(tests)
