#ifndef OPRF_USER_HEADER
#define OPRF_USER_HEADER

#include "garbling-scheme.h"
#include "emp-tool/emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "oprf_utils.h"
#include <iomanip>
#include <string>

using namespace emp;
/*
 Class that represents an OPRF user that can query PRF values from a server.
 Note that only one execution at a time is possible with this implementation.
*/
template <class T>
class User{
   private:

   int sid;
   T* io;
    
    //Builds a string s from vector v.
    void toStringFromVector(string* s, const vector<bool>& v){
        for(size_t i = 0; i < v.size(); ++i){
        *s += std::to_string(v[i]);
        }
    }

    public:
    //Different hash functions are modeled by appending these constants
    const string h_1_suffix = "H_1";
    const string h_2_suffix = "H_2";

    //remeber the recent query
    string current_pwd;

    /*
    *Constructs new User with session id sid that connects to  T io. T is the type of the IO Channel.
    */
    User(int sid, T* io){
        this->sid = sid;
        this->io = io;
    } 

    // Calculates an array of 256 bools from an array of 32 bytes
    bool* toBoolArray32(uint8_t* a){
        bool* res = new bool[SHA3_OUTPUT_SIZE];
        for (int i = 0; i < 32; ++i){
            for (int j = 0; j < 8; ++j){
                //msb of bytes is left. lsb is right
                res[i*8+j] = (a[i]>>(7-j))%2;
            }

        }
        return res;
    }
    /*
    Initiates the evaluation of the oprf on password pwd with subession id ssid.
    Outputs to cout what the user would send on the network
    Returns the 256 bits of the hash of pwd, H_1(pwd) as array 
    */
    bool* eval(string pwd, int ssid){
        current_pwd = pwd;
        // Domain separation tag ensures each subsession has its own hash function
        pwd += std::to_string(sid) + std::to_string(ssid);
        pwd += h_1_suffix;
        //Hash the password using sha3
        uint8_t* input = (uint8_t*) (pwd.c_str()); //TODO better use reinterprete_cast<>
        uint8_t res[SHA3_OUTPUT_SIZE/8];
        emp::sha3_256(res, input, pwd.size());
        return toBoolArray32(res);
    }

    /* Function that lets the user receive the desired input */
    void receiveLabels(bool* choices, block* encoded_user_input){
        OTNP<T> np(io); // create a Naor Pinkas OT using the network io 
        np.recv(encoded_user_input, choices, AES_INPUT_SIZE);  
    }

    /* Function that lets the user receive the desired input without OT*/
    void receiveLabelsWithoutOT(bool* choices, block* encoded_user_input, const vector<block>& encoded_zeroes, const vector<block>& encoded_ones){
        //cout << "enc 0s and 1s sizes: " << encoded_zeroes.size() << " " << encoded_ones.size() << endl;
        //cout << "AES Input user:" << endl; 
        /*for(int i = 0; i < AES_INPUT_SIZE; ++i){
            cout << choices[i];
            encoded_user_input[i] = choices[i] ? encoded_ones[i] : encoded_zeroes[i];
        }  
        cout << endl;*/
    }
    /* Receives the the encoded key and the decoding information from NetIO io.*/ 
    void receiveKeyAndDecoding(block* encoded_key, bool* decoding_info){
        io->recv_block(encoded_key, AES_KEY_SIZE);
        io->recv_bool(decoding_info, AES_INPUT_SIZE);
    }

    /* Finishes the execution of the OPRF protocol when the user received all its inputs via the OT */
    uint8_t* onLabelsReceived(int ssid, const block* encoded_user_input, const block* encoded_key, const bool* decoding_info){
        vector<block> encoded_output;
        vector<block> encoded_input = vector<block>(encoded_user_input, encoded_user_input + AES_INPUT_SIZE);
        encoded_input.insert(encoded_input.end(), encoded_key, encoded_key + AES_KEY_SIZE);

        // garbled circuit is read from network
        evaluate(io, &encoded_output, encoded_input, circuit_filename);

        vector<bool> output;
        vector<bool> dec_info_vec = vector<bool>(decoding_info, decoding_info + AES_INPUT_SIZE);
        decode(&output, encoded_output, dec_info_vec);

        assert((output.size() == AES_INPUT_SIZE));

        // output is the result of AES. Now hash H_2(pw, output)
        string hash_in = "";
        toStringFromVector(&hash_in, output);
        
        hash_in += current_pwd;
        hash_in += std::to_string(sid)+std::to_string(ssid);
        hash_in += h_2_suffix;
        uint8_t* input = (uint8_t*) (hash_in.c_str()); //TODO better use reinterprete_cast<>
        uint8_t* res = new uint8_t[SHA3_OUTPUT_SIZE/8];
        emp::sha3_256(res, input, hash_in.size());
        return res;
    }
};


#endif
