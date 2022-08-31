/**
 * @file hash2Curve.cpp
 * @brief This class provides a c++ implementation of the hash-to-curve algorithm described by the IETF (https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.html#suites)
 *          We use the openSSL library for elliptic curve, finite field operations and sha256.
 * @version 0.1
 * @date 2021-12-29
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "hash2Curve.hpp"

#include <iomanip>

using namespace std;

void printByteInHex(uint8_t* x, int len){
    cout << internal << setfill('0') <<  hex;
    for(int i = 0; i < len; ++i){
        cout <<setw(2)<<  (int) x[i];
    }
    cout << endl;
}



EC_POINT* hash_to_curve(const string& msg, EC_GROUP* group, BN_CTX* ctx, const string& dst){
    BIGNUM *A = BN_new(); 
    BIGNUM *B = BN_new(); 
    BIGNUM *P = BN_new();
    int res = EC_GROUP_get_curve(group, P, A, B, ctx);
    if (res == 0) cerr << "map_to_curve: Error while getting group parameters" << endl;
    BIGNUM** u = new BIGNUM*[2];
    hash_to_field(u, msg, 2, P, dst, ctx);
    EC_POINT *Q0 = EC_POINT_new(group), *Q1 = EC_POINT_new(group);
    map_to_curve(Q0, u[0], group, A, B, P, ctx);
    map_to_curve(Q1, u[1], group, A, B, P, ctx);
    EC_POINT_add(group, Q0, Q0, Q1, ctx);
    //EC_POINT* PP = clear_cofactor(Q0); //Not needed for NIST P-256, as curve has prime order
    return Q0;
}



// Hashes a message to count many field elements by using sha3. 
void hash_to_field(BIGNUM** result, const string& msg, int count, BIGNUM* p, const string& dst, BN_CTX* ctx){
    //First, generate pseudo-random bytes, then generate numbers from that and then reduce mod order.

    // L is the number of pseudo-random bytes for one field element. Thus, bias is 2^-secpar
    //assert(L == ceil((ceil(log2(p)) + secpar) / 8));
    uint16_t len_in_bytes = count * L;
    uint8_t* pseudo_random_bytes = expand_message_xmd(msg, dst, len_in_bytes);

    for(int i = 0; i < count; i++){
        int elm_offset = L * i; 
        uint8_t* tv = pseudo_random_bytes+elm_offset;
        BIGNUM* e = BN_new();
        e = BN_bin2bn(tv, L, NULL); 
        BIGNUM* rem = BN_new();
        BN_mod(rem, e, p, ctx);
        result[i] = rem;
    }
}

// The expand_message_xmd function produces pseudorandom bytes using a cryptographic hash function H.
// Returns len_in_bytes many uint8_t values.
// As we have secpar = 128, we'll use sha256
uint8_t* expand_message_xmd(const string& msg, const string& domain_separation_tag, uint16_t len_in_bytes){
    int ell = ceil(len_in_bytes / 32);
    if (ell > 255) cerr << "expand_message_xmd: Too many blocks required" << endl;
    assert(domain_separation_tag.length() < 256);
     
    const int sha2_block_len_bytes = 64;
    
    //first_hash_msg = Z_pad + msg + len_string + 8*'0' + DST_prime ; 
    uint8_t first_hash_msg[sha2_block_len_bytes + msg.length() + 3 + domain_separation_tag.length() +1];
    int f_hash_msg_len = 0;
    //Z pad
    for (int i = 0; i < sha2_block_len_bytes; ++i){
        first_hash_msg[i] = 0;
    }
    f_hash_msg_len += sha2_block_len_bytes;
    copy(msg.c_str(), msg.c_str() + msg.length(), first_hash_msg + f_hash_msg_len);
    f_hash_msg_len += msg.length();
    
    first_hash_msg[f_hash_msg_len] = (uint8_t) (len_in_bytes >> 8); 
    first_hash_msg[f_hash_msg_len+1] = (uint8_t) len_in_bytes;
    first_hash_msg[f_hash_msg_len+2] = 0;
    f_hash_msg_len += 3;
    //first_hash_msg[f_hash_msg_len] = DST_prime;
    uint8_t* dst_c_str = (uint8_t*) domain_separation_tag.c_str();
    for(int i = 0; i < domain_separation_tag.length(); ++i){
        first_hash_msg[f_hash_msg_len + i] = dst_c_str[i];
    }
    f_hash_msg_len += domain_separation_tag.length();
    first_hash_msg[f_hash_msg_len] = domain_separation_tag.length();
    f_hash_msg_len++;

    uint8_t b_init[32]; 
    eval_SHA256(b_init, first_hash_msg, f_hash_msg_len);
    uint8_t *b = new uint8_t[len_in_bytes];
    
    int hash_msg_len = 33 + domain_separation_tag.length()+1; 
    uint8_t hash_msg[hash_msg_len];
    memcpy(hash_msg, b_init, 32);
    hash_msg[32] = 1;
    memcpy(hash_msg+33, domain_separation_tag.c_str(), domain_separation_tag.length()); 
    hash_msg[hash_msg_len-1] = domain_separation_tag.length();
    eval_SHA256(b, hash_msg, hash_msg_len); 
    for(int i = 1; i < ell; ++i){
        strxor(hash_msg, b_init, b+(i-1)*32, 32); 
        hash_msg[32] = (uint8_t) i+1;
        eval_SHA256(b + i*32, hash_msg, hash_msg_len);
    }
    return b;
}



// calculates the bitwise xor of dest[i] = a[i] and b[i] for i in {0,...,c}
void strxor(uint8_t* dest, uint8_t* a, uint8_t* b, int c){
    for(int i = 0; i < c; ++i){
        dest[i] = a[i] ^ b[i];    
    }
}

// Maps a field element u to a point on a curve using Simplified SWU. 
void map_to_curve(EC_POINT* result, const BIGNUM* u, EC_GROUP* group, BIGNUM* A, BIGNUM* B, BIGNUM* P, BN_CTX* ctx){
    BIGNUM* u_mod = BN_new();
    BN_mod(u_mod,u, P, ctx);

    BIGNUM* minus_one = BN_new(); BN_dec2bn(&minus_one, "-1");
    BIGNUM* Z = BN_new(); BN_dec2bn(&Z, "-10");

    BIGNUM* minus_B = BN_new();
    BN_mod_mul(minus_B, minus_one, B, P, ctx);
    BIGNUM* c1 = BN_new(); BIGNUM* c2 = BN_new();

    BIGNUM* one_over_A = BN_new(); 
    BIGNUM* one_over_Z = BN_new();
    BN_mod_inverse(one_over_A, A, P, ctx);
    BN_mod_inverse(one_over_Z, Z, P, ctx);
    BN_mod_mul(c1, minus_B, one_over_A, P, ctx);
    BN_mod_mul(c2, minus_one, one_over_Z, P, ctx);

    BIGNUM* tv1 = BN_new(); BIGNUM* tv2 = BN_new();
    BN_sqr(tv1, u, ctx);
    BN_mod(tv1, tv1, P, ctx);
    BN_mod_mul(tv1, tv1, Z, P, ctx);

    BN_sqr(tv2, tv1, ctx);
    
    BIGNUM* x1 = BN_new(); 
    BN_mod_add(x1, tv1, tv2, P, ctx);
    inv0(x1, x1, P, ctx);

    int e1 = BN_is_zero(x1);

    BIGNUM* one = BN_new();
    BN_one(one); 
    BN_mod_add(x1, x1, one, P, ctx);
    
    
    x1 = (e1 ? c2 : x1);    // If (tv1 + tv2) == 0, set x1 = -1 / Z
    BN_mod_mul(x1, x1, c1, P, ctx);      // x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    
    BIGNUM* gx1 = BN_new();
    BN_sqr(gx1, x1, ctx);
    BN_mod_add(gx1, gx1, A, P, ctx);
    BN_mod_mul(gx1, gx1, x1, P, ctx);
    BN_mod_add(gx1, gx1, B, P, ctx); // gx1 = g(x1) = x1^3 + A * x1 + B
    
    BIGNUM* x2 = BN_new();
    BN_mod_mul(x2, tv1, x1, P, ctx); // x2 = Z * u^2 * x1
    
    BN_mod_mul(tv2, tv1, tv2, P, ctx);
    
    BIGNUM* gx2 = BN_new();
    BN_mod_mul(gx2, gx1, tv2, P, ctx); // gx2 = (Z * u^2)^3 * gx1
    BIGNUM* e2 = BN_new();
    is_square(e2, gx1, P, ctx);
    BIGNUM* x = BN_new();
    x = CMOV(x2, x1, e2);    // If is_square(gx1), x = x1, else x = x2
    BIGNUM* y2 = BN_new();
    y2 = CMOV(gx2, gx1, e2);  // If is_square(gx1), y2 = gx1, else y2 = gx2
    BIGNUM* y = BN_new();
    sqrt(y, y2, P, ctx);

    // Fix sign of y
    BIGNUM* sign = BN_new();
    sgn0(sign, u, ctx);
    bool signU = (BN_is_zero(sign) ? 0 : 1);
    sgn0(sign, y, ctx);
    bool signY = (BN_is_zero(sign) ? 0 : 1);
    
    BIGNUM* minus_y = BN_new();
    BN_mod_mul(minus_y, y, minus_one, P, ctx);
    y = (signU == signY) ? y : minus_y;
    int ret = EC_POINT_set_affine_coordinates(group, result, x, y, ctx);
    if (ret != 1) cout << "map_to_curve: invalid points calculated." << endl;
}

// Inverts element and returns result in result.
void inv0(BIGNUM* result, BIGNUM* x, BIGNUM* p, BN_CTX* ctx){
    BIGNUM* q_minus_two = BN_new();
    BIGNUM* two = BN_new();
    BN_dec2bn(&two, "2");
    BN_sub(q_minus_two, p, two);
    BN_mod_exp(result, x, q_minus_two, p, ctx); //result and x may be the same pointer?
}

// TODO: THis must be constant time. Is it really?
BIGNUM* CMOV(BIGNUM* a, BIGNUM* b, BIGNUM* c){
    if(BN_is_zero(c)){
        return a;
    } else {
        return b;
    }
}

// Returns a BIGNUM* with value 1 if value of x is a square in the field underlying group. Else returns a BIGNUM* with value 0.
void is_square(BIGNUM* result, BIGNUM* x, BIGNUM* p, BN_CTX* ctx){
    BIGNUM* two = BN_new();
    BN_dec2bn(&two, "2");
    BIGNUM* one = BN_new();
    BN_one(one); 
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    BIGNUM* q_minus_one = BN_new();
    BN_sub(q_minus_one, p, one);
    BIGNUM* q_minus_one_half = BN_new();
    BN_div(q_minus_one_half, NULL, q_minus_one, two, ctx);
    //BN_div(q_minus_one_half, NULL, q_minus_one, two, ctx); 
    BIGNUM* exp = BN_new();
    BN_mod_exp(exp, x, q_minus_one_half, p, ctx);
    if(BN_is_zero(exp)){
        BN_one(result);
    } else if (BN_is_one(exp)){
        BN_one(result);
    } else {
        BN_zero(zero);
    }
}

// Calculates the square root of x in GF(p) if x is square. result must be initialized. Does only work for p = 3 mod 4 (which is the case for NIST P-256)
void sqrt(BIGNUM* result, BIGNUM* x, BIGNUM* P, BN_CTX* ctx){
    BIGNUM* c1 = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* P_plus_one = BN_new();
    BIGNUM* four = BN_new();
    BN_one(one);
    BN_dec2bn(&four, "4");
    BN_add(P_plus_one, P, one);
    BIGNUM* one_over_four = BN_new();
    BN_mod_inverse(one_over_four, four, P, ctx);
    BN_mod_mul(c1, P_plus_one, one_over_four, P, ctx);
    
    BN_mod_exp(result, x, c1, P, ctx);
}

//Caluclates the sign of x. (i.e. x mod 2, as we have m == 1)
void sgn0(BIGNUM* result, const BIGNUM* x, BN_CTX* ctx){
    BIGNUM* two = BN_new();
    BN_dec2bn(&two, "2");
    BN_mod(result, x, two, ctx);
}


void eval_SHA256(uint8_t* output, const uint8_t* msg, int length){
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned int md_len;

    int res = EVP_Digest(msg, length, output, &md_len, md, NULL);
    if (res != 1) cerr << "Error evalutating sha 256"<< endl;
}

