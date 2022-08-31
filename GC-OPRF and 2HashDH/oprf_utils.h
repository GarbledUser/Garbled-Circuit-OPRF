#ifndef OPRF_UTILS
#define OPRF_UTILS
#include <string>

const int AES_INPUT_SIZE = 128;
const int AES_KEY_SIZE = 128;
const int SHA3_OUTPUT_SIZE = 256;

const std::string gc_filename = "bin/garbled_aes_from_oprf.txt";
const std::string circuit_filename = "emp-tool/emp-tool/circuits/files/bristol_format/AES-non-expanded.txt";

#endif