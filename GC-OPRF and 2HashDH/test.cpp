#include <iostream>
#include <string>

#include "garbling-scheme.h"

using namespace std;
using namespace emp;
//--------------------------------------------------------------------------------------------------------------------------

// trying to find cause of segfault in circuits/circuit_file.h problem is that the fopen call fails. debugging code in file_io_channel.h and circuit_file.h -> use absolute path?

//--------------------------------------------------------------------------------------------------------------------------

/*Converts a hex string of length 32 to a bitset*/
vector<bool>* toBitVector(const string& s){
	assert(s.size() == 32);
	uint64_t hi, li;
	sscanf(s.c_str(), "%16lx%16lx", &hi, &li);	
	bitset<64> hbitset(hi);
	bitset<64> lbitset(li);
	// last character is lsb
	vector<bool>* res = new vector<bool>(128);
	for(int i = 0; i < 64; ++i){
		(*res)[63-i] = hbitset[i];
	}
	for (int i = 0; i < 64; ++i){
		(*res)[127-i] = lbitset[i];
	}
	
	return res;
}

void testEmpAes(){
    block zero_key = makeBlock(0,0);
    block test_plaintext = makeBlock(0xfeffffffffffffff, 0xffffffffffffffff);
	cout << test_plaintext << " test_plaintext" << endl;


    AES_KEY k;
    AES_set_encrypt_key(zero_key, &k);
    AES_ecb_encrypt_blks(&test_plaintext, 1, &k);

	cout << test_plaintext << " Result of emp AES" << endl;

}

void executeAESGarbling(vector<bool>* output, const vector<bool>& input, const vector<bool>& key){
	vector<block> encoding_info;
	vector<bool> decoding_info;
	vector<block> encoded_input;
	vector<block> encoded_output;
	string gc_filename = "../emp-tool/garbled_aes_test.txt";
	string circuit_filename = "../emp-tool/emp-tool/circuits/files/bristol_format/AES-non-expanded.txt";
	FileIO* fio = new FileIO(gc_filename.c_str(), false);
	garble(fio, &encoding_info, &decoding_info, circuit_filename);
	fio->flush();
	vector<bool> joint_input = input;
	joint_input.insert(joint_input.end(), key.begin(), key.end());
	encode(&encoded_input, joint_input, encoding_info);
	evaluate(fio, &encoded_output, encoded_input, circuit_filename);
	fio->flush();
	decode(output, encoded_output, decoding_info);
}

/* Tests against the nist aes test file for aes in ecb mode with fixed key 0^128*/
void testAesNist(){
	// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
	string ecbVarTxt128 = "../ECBVarTxt128.rsp";
	ifstream f(ecbVarTxt128);
	string plaintext, ciphertext, skip;
	if(f.is_open()){
		vector<bool> key(128, false);
		
		//skip first lines
		for(int i = 0; i < 9; ++i){
			getline(f, skip);
		}
		for(int i = 0; i < 128; ++i){
			getline(f, skip);
			getline(f, skip);
			// discard everything up to '='
			getline(f, plaintext, '=');
			getline(f, plaintext);
			plaintext.erase(0,1);
			getline(f, ciphertext, '=');
			getline(f, ciphertext);
			ciphertext.erase(0,1);
			getline(f, skip);
			//cout << plaintext << " plaintext" << endl;
			//cout << ciphertext << " ciphertext" << endl;
			vector<bool>* cipher = toBitVector(ciphertext);
			vector<bool>* plain = toBitVector(plaintext);
			for(size_t i = 0; i < plain->size(); ++i){
				cout << (*plain)[i];
			}
			cout << "plaintext binary" << endl;
			vector<bool> output;
			executeAESGarbling(&output, (*plain), key);
			for(size_t i = 0; i < cipher->size(); ++i){
				cout << (*cipher)[i];
			}
			cout << " correct cipher" << endl;
			for(size_t i = 0; i< output.size(); ++i){
				cout << output[i];
			}
			cout << " garbled cipher" << endl;
			cout << ((output == (*cipher)) ? "Matched" : "Unequal");
			cout << endl;
			
		}
	}

	testEmpAes();

}





int main(int argc, char** argv) {
	vector<block> encoding_info;
	vector<bool> decoding_info;
	vector<block> encoded_input;
	vector<bool> input(64, false);
	vector<block> encoded_output;
	vector<bool> output;
	//string gc_filename = "circuits/garbled_adder_32bit";
	string gc_filename = "../emp-tool/garbled_adder_32bit.txt";
	string circuit_filename = "../emp-tool/emp-tool/circuits/files/bristol_format/adder_32bit.txt";
	FileIO* fio = new FileIO(gc_filename.c_str(), false);
	cout << "blabla";
	garble(fio, &encoding_info, &decoding_info, circuit_filename);
	fio->flush();
	encode(&encoded_input, input, encoding_info);
	evaluate(fio, &encoded_output, encoded_input, circuit_filename);
	fio->flush();
	decode(&output, encoded_output, decoding_info);
	
	for (size_t i=0; i<output.size(); i++) {
	    if (output[i] == true) {
	        cout << "1";
	    }
	    else {
	        cout << "0";
	    }
	}
	cout << endl;
	testAesNist();
}



