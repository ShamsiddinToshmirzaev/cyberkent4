cmake_minimum_required(VERSION 3.16)
project(c03_signer C)

set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O2")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(signer signer.c)
target_link_libraries(signer OpenSSL::Crypto Threads::Threads)
