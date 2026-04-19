# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

cmake_path(GET RAW_SOURCE_PATH STEM raw_source_basename)

file(READ ${RAW_SOURCE_PATH} hex_content HEX)
string(REGEX REPLACE "................" "\\0\n" formatted_bytes "${hex_content}")
string(REGEX REPLACE "[^\n][^\n]" "std::byte{0x\\0}, " formatted_bytes "${formatted_bytes}")

string(LENGTH "${hex_content}" content_length)
math(EXPR array_size "${content_length} / 2")

set(header_content
"#include <array>
#include <cstddef>

namespace ${RAW_NAMESPACE} {
inline constexpr std::array<std::byte, ${array_size}> ${raw_source_basename} {{
${formatted_bytes}
}};
}
")
file(WRITE ${HEADER_PATH} "${header_content}")
