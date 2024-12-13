cmake_minimum_required(VERSION 3.30)
project(spats)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../depends/x86_64-pc-linux-gnu/include)

add_library(spats STATIC
        spark_asset.hpp
        constrained_value.hpp
        util.hpp
        scaled_amount.hpp
        registry.cpp
        registry.hpp
        base_asset.hpp
        identification.hpp)
