#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size);

int main(int argc, char** argv)
{
    if (argc != 2) {
        return 1;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        return 1;
    }
    std::vector<uint8_t> data{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
    return LLVMFuzzerTestOneInput(data.data(), data.size());
}
