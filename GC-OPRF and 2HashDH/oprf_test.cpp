#include "oprf_server.h"
#include "oprf_user.h"

using namespace emp;
using namespace std;



// Constructs a string that contains the bits of block b.
string* blockToString(const block& b){
    string* s = new string();
    uint8_t* data = (uint8_t*) &b; //get the content of block b as bytes 
    for(int j = 0; j < 16; ++j){
        for (int i = 0; i < 8; ++i){
            //msb of each byte is left. lsb is right.
            (*s) += to_string((data[j] >> (7-i)) % 2);
        }
    }
    return s;
}

//Construct a emp::block that contains the first 128 bits of the array pointed to by bytes.
block blockFromBytes(uint8_t* bytes){
    uint64_t high = *((uint64_t*) (bytes+8));
    uint64_t low = *((uint64_t*) bytes);
    //block nist_test = makeBlock(high, low); 
        
    block b = makeBlock(high, low);
    return b;
}

// This function was used to test the protocol against a "plain" execution of H_2(p,AES_k(H_1(p)))
int main(){
    FileIO* user_io = new FileIO(gc_filename.c_str(), false);
    FileIO* server_io = new FileIO(gc_filename.c_str(), false);
    User<FileIO> u(1, user_io);
    bool* current_h = u.eval("Test", 1);
    user_io->flush();

    //test server with key always 0
    vector<bool> key(AES_KEY_SIZE, false);
    Server<FileIO> s(key, 1, server_io);
    //These will be received by the user through the network
    block encoded_key[AES_KEY_SIZE];
    bool decoding_info[AES_INPUT_SIZE];

    //Only necessary as long as no OT is implemented
    vector<block> encoded_zeroes(AES_INPUT_SIZE);
    vector<block> encoded_ones(AES_INPUT_SIZE);
    s.onGarble(1, &encoded_ones, &encoded_zeroes);
    server_io->flush();
    
    u.receiveKeyAndDecoding(encoded_key, decoding_info);
    //This mimics the OT
    block encoded_user_input[AES_INPUT_SIZE];
    u.receiveLabelsWithoutOT(current_h, encoded_user_input, encoded_zeroes, encoded_ones);
    cout << "Receive labels without ot current h:" << endl;
    for(int i = 0; i < 128; i++){
        cout << current_h[i];
    }
    cout << endl;
    uint8_t* rho = u.onLabelsReceived(1, encoded_user_input, encoded_key, decoding_info);

    //--- Protocol is over here. test the result

    // construct the according strings, hash them with sha3, encrypt with aes and hash again with sha3
    string pwd = "Test";
    pwd += "11"; //sid + ssid
    pwd += u.h_1_suffix;
    uint8_t* input = (uint8_t*) (pwd.c_str()); //TODO better use reinterprete_cast<>
    uint8_t h_of_pwd[SHA3_OUTPUT_SIZE/8];
    emp::sha3_256(h_of_pwd, input, pwd.size());

    //emp aes takes blocks as input
    block b = blockFromBytes(h_of_pwd); 
    block zero_key = makeBlock(0,0);
    AES_KEY k;
    AES_set_encrypt_key(zero_key, &k);
    AES_ecb_encrypt_blks(&b, 1, &k);
    cout << "Offline AES value" << endl;
    cout << *blockToString(b) << endl;
    string hash_in = *blockToString(b);

    hash_in += "Test";
    hash_in += "11"; //sid + ssid
    hash_in += u.h_2_suffix;
    uint8_t* c_str_input = (uint8_t*) (hash_in.c_str()); //TODO better use reinterprete_cast<>
    uint8_t res_of_output_pwd[SHA3_OUTPUT_SIZE/8];
    emp::sha3_256(res_of_output_pwd, c_str_input, hash_in.size());

    //Compare results
    cout << std::hex;
    for(int i = 0; i < SHA3_OUTPUT_SIZE/8; ++i){
        cout << (unsigned int) res_of_output_pwd[i] << "\t" << (unsigned int) rho[i] << endl;
    }
}
