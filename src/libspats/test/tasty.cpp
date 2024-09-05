#include "../../test/test_bitcoin.h"
#include <iostream>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include "../../libspark/params.h"

namespace spark {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(okay_of_this, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_verify)
{
    int result = 1 + 2;
    std::cout << "========= this is result ========" << std::endl;
    std::string filename = "abc.txt";

    // Create an ofstream (output file stream) object and open the file
    std::ofstream outputFile(filename);

    // Check if the file opened successfully
    if (!outputFile.is_open()) {
        std::cerr << "Failed to open the file: " << filename << std::endl;
    }

    

    // Parameters
    const Params* params;
    params = Params::get_default();

    outputFile << "Hello, World!\n";
    outputFile << "param";
    outputFile << "param";
    outputFile << "\nparam = " << params;
    outputFile << "\nmemo_bytes = " << params->get_memo_bytes();
    outputFile << "\nmemo_bytes = " << (*params).get_memo_bytes();
    outputFile << "\nget_G = " << (*params).get_G();
    outputFile << "\nget_max_M_range = " << params->get_max_M_range();
    outputFile << "\nget_n_grootle = " << params->get_n_grootle();
    outputFile << "\nget_m_grootle = " << params->get_m_grootle();

    // Close the file
    outputFile.close();

    // Check if the file was closed successfully
    if (outputFile.fail()) {
        std::cerr << "Failed to close the file: " << filename << std::endl;
    }

    // Verify
    BOOST_CHECK(result == 3);
}

BOOST_AUTO_TEST_SUITE_END()

}