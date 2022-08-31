#include "hash2Curve.hpp"
#define BOOST_TEST_MODULE hash2Curve test
#include <boost/test/included/unit_test.hpp>

/*
 These test check automatically the test cases from https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.html#name-suites-for-nist-p-256
*/

EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // emp uses NIST P-256 ;
BN_CTX* bn_ctx = BN_CTX_new();
string dst ="P256_XMD:SHA-256_SSWU_RO_TESTGEN";
int i = EC_GROUP_precompute_mult(ec_group, bn_ctx);
BIGNUM *A = BN_new();
BIGNUM *B = BN_new();
BIGNUM *P = BN_new();
int res = EC_GROUP_get_curve(ec_group, P, A, B, bn_ctx);


BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_curve_empty ) {
    string msg = "";
    EC_POINT* g = hash_to_curve(msg, ec_group, bn_ctx, dst);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, g, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "8575F9B7010B101A3114486E51FC5B708F48EF7FA10AA00D834B157574E11074");
    BOOST_CHECK_EQUAL(y_hex, "E985633CE74378627E9A4295D2997C8ED959B67B6762FDEA72ACA99343F3A949");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_field_empty ) {
    string msg = "";
    BIGNUM *P = BN_new();
    int res = EC_GROUP_get_curve(ec_group, P, NULL, NULL, bn_ctx);
    if (res == 0) cerr << "map_to_curve: Error while getting group parameters" << endl;
    BIGNUM** u = new BIGNUM*[2];
    hash_to_field(u, msg, 2, P, dst, bn_ctx);

    char* u0_hex =  BN_bn2hex(u[0]);
    char* u1_hex =  BN_bn2hex(u[1]);
    BOOST_CHECK_EQUAL(u0_hex, "64D747D0CBE9E2C9EF0FF12BBEEAC4744F37D76A9146EE2219D3DF820E8452F8");
    BOOST_CHECK_EQUAL(u1_hex, "D27EE4C85602A83DC321B36A183872DC484256A53AE2DF3CF5E3561820A8685F");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_map_to_curve_empty ) {
    string msg = "";

    BIGNUM** u = new BIGNUM*[2];

    u[0] = BN_new(); u[1] = BN_new();
    BN_hex2bn(&u[0], "64D747D0CBE9E2C9EF0FF12BBEEAC4744F37D76A9146EE2219D3DF820E8452F8");
    BN_hex2bn(&u[1], "D27EE4C85602A83DC321B36A183872DC484256A53AE2DF3CF5E3561820A8685F");

    EC_POINT *Q0 = EC_POINT_new(ec_group);
    map_to_curve(Q0, u[0], ec_group, A, B, P, bn_ctx);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, Q0, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "2FF87ED27A17062AD0721F97CADD2D0E54901745CA9101E324F7460D05F0571B");
    BOOST_CHECK_EQUAL(y_hex, "8185395060BF793FAD9FBD39C264DA5DA111A86EC3CF3A116833C49719039022");

    EC_POINT *Q1 = EC_POINT_new(ec_group);
    map_to_curve(Q1, u[1], ec_group, A, B, P, bn_ctx);
    EC_POINT_get_affine_coordinates(ec_group, Q1, X, Y, bn_ctx);
    x_hex =  BN_bn2hex(X);
    y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "3C0ECDD0372E8E702BCA9EC05282A8A016C41E4B1AC65FF76B4A6166B5EBD514");
    BOOST_CHECK_EQUAL(y_hex, "4F6AF85BC6701E3A6B8C13BEC0CE517478EAE5ABF5370AC81CEC95D21DD588B3");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_curve_abc ) {
    string msg = "abc";
    EC_POINT* g = hash_to_curve(msg, ec_group, bn_ctx, dst);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, g, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "68D876B1F5F6419F73B94502A28C7AEF3F2E8619F4DCDFD7A91B34F6E3FD8FC8");
    BOOST_CHECK_EQUAL(y_hex, "79A4F8914923B6E202B07B96B53B5BFF92477CC5217DDDD86226B70610275059");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_field_abc ) {
    string msg = "abc";

    BIGNUM** u = new BIGNUM*[2];
    hash_to_field(u, msg, 2, P, dst, bn_ctx);

    char* u0_hex =  BN_bn2hex(u[0]);
    char* u1_hex =  BN_bn2hex(u[1]);
    BOOST_CHECK_EQUAL(u0_hex, "9807C1A5F0D51793429275EDB22CD301B360F9AE11C3374F0E61466165BF0B37");
    BOOST_CHECK_EQUAL(u1_hex, "D7C39C44030D3F3FE2AA49F76A5D5C9BC91B078589D43E2CEA8928DE7652CD7A");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_map_to_curve_abc ) {
    string msg = "abc";

    BIGNUM** u = new BIGNUM*[2];

    u[0] = BN_new(); u[1] = BN_new();
    BN_hex2bn(&u[0], "9807c1a5f0d51793429275edb22cd301b360f9ae11c3374f0e61466165bf0b37");
    BN_hex2bn(&u[1], "d7c39c44030d3f3fe2aa49f76a5d5c9bc91b078589d43e2cea8928de7652cd7a");

    EC_POINT *Q0 = EC_POINT_new(ec_group);
    map_to_curve(Q0, u[0], ec_group, A, B, P, bn_ctx);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, Q0, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "3F0D3A7EB427097AEBFC52EF7FA4250B6A6BFC581BEDF7775F6880E66587CC26");
    BOOST_CHECK_EQUAL(y_hex, "47235D010AEEA2C3E3D131577A3F3B3513E738790D03330DC88502C506E2D3ED");

    EC_POINT *Q1 = EC_POINT_new(ec_group);
    map_to_curve(Q1, u[1], ec_group, A, B, P, bn_ctx);
    EC_POINT_get_affine_coordinates(ec_group, Q1, X, Y, bn_ctx);
    x_hex =  BN_bn2hex(X);
    y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "FCDED73F3D1F12FEDA61A1E64E6C79E00C0DA1F1F164E290E34DC260E09D028A");
    BOOST_CHECK_EQUAL(y_hex, "D7D517E5E1EB3F813E0584D2D1D74F13AD44CF92F692B7021B1E0CEE9387B882");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_curve_abcdef0123456789 ) {
    string msg = "abcdef0123456789";
    EC_POINT* g = hash_to_curve(msg, ec_group, bn_ctx, dst);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, g, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "710ECFF129F51971437622B6C72A30D74D15894DF3641C46BF0B0ED70BCA7B6C");
    BOOST_CHECK_EQUAL(y_hex, "B3B1632EF6B34114AD4D8F5BB3F7F7E3513A0C4514F7177632F09789DB080B41");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_field_abcdef0123456789 ) {
    string msg = "abcdef0123456789";
    BIGNUM *P = BN_new();
    int res = EC_GROUP_get_curve(ec_group, P, NULL, NULL, bn_ctx);
    if (res == 0) cerr << "map_to_curve: Error while getting group parameters" << endl;
    BIGNUM** u = new BIGNUM*[2];
    hash_to_field(u, msg, 2, P, dst, bn_ctx);

    char* u0_hex =  BN_bn2hex(u[0]);
    char* u1_hex =  BN_bn2hex(u[1]);
    BOOST_CHECK_EQUAL(u0_hex, "F2C09AC7340A2BB6B89A2BE5868BC8FF8CD30375461426D46FF9D6BDB6245F99");
    BOOST_CHECK_EQUAL(u1_hex, "C255967A8BB4D17EDEBA2AFFBCE618B50CC8D77908657106C898F0DCE498CFC7");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_map_to_curve_abcdef0123456789 ) {
    string msg = "abcdef0123456789";

    BIGNUM** u = new BIGNUM*[2];

    u[0] = BN_new(); u[1] = BN_new();
    BN_hex2bn(&u[0], "F2C09AC7340A2BB6B89A2BE5868BC8FF8CD30375461426D46FF9D6BDB6245F99");
    BN_hex2bn(&u[1], "C255967A8BB4D17EDEBA2AFFBCE618B50CC8D77908657106C898F0DCE498CFC7");

    EC_POINT *Q0 = EC_POINT_new(ec_group);
    map_to_curve(Q0, u[0], ec_group, A, B, P, bn_ctx);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, Q0, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "2C295D2AE5520CCB41B441D5DDF3D8C39CED0140061E9C7D3058BE2B91A30E2F");
    BOOST_CHECK_EQUAL(y_hex, "38B2974D4B008B586AEB030013281A36C4CD2C50F31ECD48B2B251BE954B35BD");

    EC_POINT *Q1 = EC_POINT_new(ec_group);
    map_to_curve(Q1, u[1], ec_group, A, B, P, bn_ctx);
    EC_POINT_get_affine_coordinates(ec_group, Q1, X, Y, bn_ctx);
    x_hex =  BN_bn2hex(X);
    y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "648DCA4A2CDF36E139023937F826CFED14B5589F7176F0C19C6366D265AAA7FC");
    BOOST_CHECK_EQUAL(y_hex, "ACBF1559C9D8077B76F04A346CB512DACE28AC1E890913EA0F8395C3B3AAF4A3");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_curve_a512) {
    string msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    EC_POINT* g = hash_to_curve(msg, ec_group, bn_ctx, dst);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, g, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "A5DB1F4140A102D702214D59E05619DDDEEC05DB546D35B35D03A2F0D47A1898");
    BOOST_CHECK_EQUAL(y_hex, "27C7D0FA5EDAE824EFB39039205ACE6FA6FDC4BF3633155BF6DB01ECA243C4CA");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_hash_to_field_a512) {
    string msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    BIGNUM *P = BN_new();
    int res = EC_GROUP_get_curve(ec_group, P, NULL, NULL, bn_ctx);
    if (res == 0) cerr << "map_to_curve: Error while getting group parameters" << endl;
    BIGNUM** u = new BIGNUM*[2];
    hash_to_field(u, msg, 2, P, dst, bn_ctx);

    char* u0_hex =  BN_bn2hex(u[0]);
    char* u1_hex =  BN_bn2hex(u[1]);
    BOOST_CHECK_EQUAL(u0_hex, "62E9DD8C58BAC00646D654C96A8083C9062D0B6C8A02059BD0384AF0E52A855F");
    BOOST_CHECK_EQUAL(u1_hex, "B651DF8D40FBB5D2EF0C5887DD5C82A5CC04CE07579907C66AFB1CDE2993DA00");
}

BOOST_AUTO_TEST_CASE( IETF_Test_Case_map_to_curve_a512 ) {
    string msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    BIGNUM** u = new BIGNUM*[2];

    u[0] = BN_new(); u[1] = BN_new();
    BN_hex2bn(&u[0], "62E9DD8C58BAC00646D654C96A8083C9062D0B6C8A02059BD0384AF0E52A855F");
    BN_hex2bn(&u[1], "B651DF8D40FBB5D2EF0C5887DD5C82A5CC04CE07579907C66AFB1CDE2993DA00");

    EC_POINT *Q0 = EC_POINT_new(ec_group);
    map_to_curve(Q0, u[0], ec_group, A, B, P, bn_ctx);
    BIGNUM* X = BN_new(); BIGNUM* Y = BN_new();
    EC_POINT_get_affine_coordinates(ec_group, Q0, X, Y, bn_ctx);
    char* x_hex =  BN_bn2hex(X);
    char* y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "654B7B18A3EF2637585259D07C94391CC06048011EE07C8E0225B819216701ED");
    BOOST_CHECK_EQUAL(y_hex, "0658146B06A4BDFA543EE347BC51980E12BEE80A40EA22EAF0CBA134565F2F5B");

    EC_POINT *Q1 = EC_POINT_new(ec_group);
    map_to_curve(Q1, u[1], ec_group, A, B, P, bn_ctx);
    EC_POINT_get_affine_coordinates(ec_group, Q1, X, Y, bn_ctx);
    x_hex =  BN_bn2hex(X);
    y_hex =  BN_bn2hex(Y);
    BOOST_CHECK_EQUAL(x_hex, "2D148869FB30215E36D61D9ABAAC07E493EEA6F1DFEFFB89E326AC686DE77EFB");
    BOOST_CHECK_EQUAL(y_hex, "C590A7D337C2CDD5CAE6329F5EEA563EBAC10EA5DA7FCC7BEA9EF61FC8DD749C");
}
