/**
 * @file hash2Curve.hpp
 * @brief This class provides a c++ implementation of the hash-to-curve algorithm described by the IETF (https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.html#suites)
 *          We use the openSSL library for elliptic curve, finite field operations and sha256.
 * @version 0.1
 * @date 2021-12-29
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <cmath>
#include <string>
#include <iostream>
#include <cassert>
#include <cstring>

using namespace std;

//const string domain_separation_tag = "HASH2CURVE-V1-CS1-HashToField";
const string domain_separation_tag = "2HashDH-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
//const string domain_separation_tag = "P256_XMD:SHA-256_SSWU_RO_TESTGEN";

// Constants as defined in ciphersuite for NIST P-256 defined in Section 8.2 of https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.html#suites
const int secpar = 128;
const int L = 48;

// Hashes a message msg to a point on the elliptic cureve group.
EC_POINT* hash_to_curve(const string& msg, EC_GROUP* group, BN_CTX* ctx, const string& dst = domain_separation_tag);

// Hashes a message to count many field elements by using sha3. 
void hash_to_field(BIGNUM** result, const string& msg, int count, BIGNUM* p, const string& dst, BN_CTX* ctx);

// The expand_message_xmd function produces pseudorandom bytes using a cryptographic hash function H.
// Returns len_in_bytes many uint8_t values.
// As we have secpar = 128, we'll use sha3-256
uint8_t* expand_message_xmd(const string& msg, const string& domain_separation_tag, uint16_t len_in_bytes);

// calculates the bitwise xor of dest[i] = a[i] and b[i] for i in {0,...,c}
void strxor(uint8_t* dest, uint8_t* a, uint8_t* b, int c);


// Maps a field element u to a point on a curve using Simplified SWU.
void map_to_curve(EC_POINT* result, const BIGNUM* u, EC_GROUP* group, BIGNUM* A, BIGNUM* B, BIGNUM* P, BN_CTX* ctx);
    
// Inverts element and returns result in result.
void inv0(BIGNUM* result, BIGNUM* x, BIGNUM* p, BN_CTX* ctx);


// TODO: THis must be constant time. Is it really?
BIGNUM* CMOV(BIGNUM* a, BIGNUM* b, BIGNUM* c);

// Returns a BIGNUM* with value 1 if value of x is a square in the field underlying group. Else returns a BIGNUM* with value 0.
void is_square(BIGNUM* result, BIGNUM* x, BIGNUM* p, BN_CTX* ctx);

// Calculates the square root of x in GF(p) if x is square. result must be initialized. Does only work for p = 3 mod 4 (which is the case for NIST P-256)
void sqrt(BIGNUM* result, BIGNUM* x, BIGNUM* p, BN_CTX* ctx);

//Caluclates the sign of x. (i.e. x mod 2, as we have m == 1)
void sgn0(BIGNUM* result, const BIGNUM* x, BN_CTX* ctx);

//Calculates the SHA256 digest of a message msg of len bytes and stores the result in ouput. Stores NULL if an error occurs.
void eval_SHA256(uint8_t* output, const uint8_t* msg, int length);