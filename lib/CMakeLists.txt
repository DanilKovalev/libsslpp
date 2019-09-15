project(libsslpp)

file(GLOB_RECURSE SOURCE_FILES
        "*.cpp"
        "*.h")

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} PUBLIC /home/ostik/projects/mirrors/openssl/libcrypto.a  -lssl)
target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads -ldl)
add_library(SslWrapper::lib ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ./)

