# analysis/dynamorio/CMakeLists.txt — out-of-tree build against the
# DynamoRIO release tree (RFC rfc_dynamorio.md §2.1).
#
#   cmake -DDynamoRIO_DIR=/tmp/DynamoRIO-Linux-*/build \
#         -S analysis/dynamorio -B analysis/dynamorio/build
#   cmake --build analysis/dynamorio/build -j
#
# Produces libdr_bindumpty.so.
cmake_minimum_required(VERSION 3.10)
project(bindumpty_client C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(DynamoRIO REQUIRED)

add_library(dr_bindumpty SHARED dr_bindumpty.cpp)
configure_DynamoRIO_client(dr_bindumpty)

# RFC §2.1: official extensions
use_DynamoRIO_extension(dr_bindumpty drmgr)
use_DynamoRIO_extension(dr_bindumpty drwrap)
use_DynamoRIO_extension(dr_bindumpty drsyms)

# Edge-pass client (RFC §5.2): raw BB event, no drwrap — see
# dr_edges.cpp for why this is a separate process invocation.
add_library(dr_edges SHARED dr_edges.cpp)
configure_DynamoRIO_client(dr_edges)
