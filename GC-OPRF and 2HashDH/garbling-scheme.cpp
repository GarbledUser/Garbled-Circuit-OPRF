#include <iostream>
#include <string>

#include "emp-tool/emp-tool/emp-tool.h"
#include "garbling-scheme.h"

using namespace emp;
using std::cout;
using std::endl;


void encode(vector<block>* encoded_input, const vector<bool>& input, const vector<block>& encoding_info) {
	encoded_input->resize(input.size());
	//pseudocode
	//if input[i] = FALSE
	//  output[i] = encoding_info[i+1]
	//else
	//  output[i] = encoding_info[i+1] XOR encoding_info[0]
	for(size_t i=0; i<input.size(); i++){
		if (input[i] == false) {
			(*encoded_input)[i] = encoding_info[i+1];
		}
		else {
			(*encoded_input)[i] = encoding_info[i+1] ^ encoding_info[0];
		}
	}
	cout << endl;

}


void decode(vector<bool>* output, const vector<block>& encoded_output, const vector<bool>& decoding_info) {
    output->resize(encoded_output.size());
	//pseudocode
	//output[i] = decoding_info[i] XOR getLSB(labels[i])
	for(size_t i=0; i<decoding_info.size(); i++){
		(*output)[i] = decoding_info[i] ^ getLSB(encoded_output[i]);
	}
}
