#include "emp-tool/emp-tool/emp-tool.h"
#include "emp-tool/emp-tool/utils/group_openssl.h"
#include "emp-tool/emp-tool/utils/group.h"

using namespace std;
using namespace emp;

const int ec_point_size_comp = 33;


int main(int argc, char* argv[]){
    //Parse command line argument
    if (argc < 1) {
        cerr << "Wrong number of arguments" << endl;
        return 1;
    }
    int port = atoi(argv[1]);
    // Create Server and OT objects
    int sid = 1;
    NetIO server_io(nullptr, port); // Server is the Sender. 
    
    
    for(int i = 0; i < 1000; ++i){
        // Create group object
        EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // emp uses NIST P-256 
        BN_CTX* bn_ctx = BN_CTX_new();
        EC_GROUP_precompute_mult(ec_group, bn_ctx);

        BIGNUM *field_order = BN_new();
        // Get order of the underlying field.
        int ret_vl = EC_GROUP_get_curve(ec_group, field_order, NULL, NULL, bn_ctx);

        // Choose random key
        BIGNUM* key = BN_new();
        BN_rand_range(key, field_order);
    
        // Receive point a from user
        uint8_t in_buf[ec_point_size_comp];
        server_io.recv_data(in_buf, ec_point_size_comp);
        EC_POINT* a = EC_POINT_new(ec_group);
        int res = EC_POINT_oct2point(ec_group, a, in_buf, ec_point_size_comp, bn_ctx);
        if(res != 1) cerr << "2HashDH Server: Error receiveing point a." << endl;

        // Multiply with key
        EC_POINT* b = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, b, NULL, a, key, bn_ctx); // b = a*key 

        // Convert point b to binary and send over network
        uint8_t out_buf[ec_point_size_comp];
        int written = EC_POINT_point2oct(ec_group, b, POINT_CONVERSION_COMPRESSED, out_buf, ec_point_size_comp, bn_ctx);
        if(written < ec_point_size_comp) cerr << "2HashDH Server: Error writing point b." << endl;
        server_io.send_data(out_buf, ec_point_size_comp);
    }
}
