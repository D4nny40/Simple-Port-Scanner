cmake_minimum_required(VERSION 3.16)

project(SimplePortScanner VERSION 3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(simplePortScanner
    main.cpp
    src/PortScanner.cpp
)

target_include_directories(simplePortScanner PRIVATE src)

if (WIN32)
    target_link_libraries(simplePortScanner PRIVATE ws2_32)
endif()