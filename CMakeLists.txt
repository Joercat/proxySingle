cmake_minimum_required(VERSION 3.10)
project(CPPProxy CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find necessary dependencies
find_package(Boost REQUIRED COMPONENTS system thread url asio)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Brotli REQUIRED)
find_package(SQLite3 REQUIRED)

# Link against system libraries
find_library(GUMBO_LIBRARY gumbo REQUIRED)

# Use vcpkg to manage third-party dependencies like spdlog
find_package(spdlog CONFIG REQUIRED)

# Add the executable
add_executable(CPPProxy proxy.cpp)

# Link libraries
target_link_libraries(CPPProxy 
    PRIVATE
    Boost::system 
    Boost::thread 
    Boost::url
    Boost::asio
    Boost::ssl
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ZLIB::ZLIB
    Brotli::brotli
    ${GUMBO_LIBRARY}
    SQLite3::SQLite3
    spdlog::spdlog
)

# Set common compiler flags for optimization and warnings
target_compile_options(CPPProxy PRIVATE -O2 -Wall -pedantic)
