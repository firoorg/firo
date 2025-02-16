# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

message(STATUS "Generating header ${HEADER_PATH} from ${JSON_SOURCE_PATH}")

# Generate a header file from a JSON file containing a hex dump
function(generate_json_header JSON_SOURCE_PATH HEADER_PATH)
    # Use get_filename_component instead of cmake_path
    get_filename_component(json_source_basename "${JSON_SOURCE_PATH}" NAME_WE)

    # Create directory
    get_filename_component(header_dir "${HEADER_PATH}" DIRECTORY)
    file(MAKE_DIRECTORY "${header_dir}")
    
    # Read and convert to hex
    file(READ ${JSON_SOURCE_PATH} hex_content HEX)
    string(REGEX REPLACE ".." "0x\\0, " formatted_bytes "${hex_content}")

    # Generate content
    set(header_content
        "namespace json_tests{
            static unsigned const char ${json_source_basename}[] = { 
                ${formatted_bytes}
            };
         };"
    )
    
    # Atomic write using temporary file
    file(WRITE "${HEADER_PATH}.new" "${header_content}")
    file(RENAME "${HEADER_PATH}.new" "${HEADER_PATH}")
endfunction()

generate_json_header(${JSON_SOURCE_PATH} ${HEADER_PATH})
