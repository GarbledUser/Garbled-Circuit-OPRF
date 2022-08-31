#include "emp-tool/emp-tool/emp-tool.h"
#include "emp-tool/emp-tool/utils/group_openssl.h"
#include "emp-tool/emp-tool/utils/group.h"
#include "hash2Curve.hpp"

#include <chrono>

using namespace std;
using namespace emp;

const int ec_point_size_comp = 33; // 32 byte field element plus one encoding byte, according to https://www.secg.org/sec1-v2.pdf 2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion 

// appends a string representation of a to out. Array has to have length len. Functions is only needed to print the final results to a file
void appendArrayToString(string& out, double* a, int len) {
    out += "[";
    for(int i = 0; i < len-1; ++i){
        out += to_string(a[i]) + ", ";
    }
    if (len > 0)
        out += to_string(a[len-1]);
    out += "]\n";
}

int main(int argc, char* argv[]){
    //Parse command line argument
    if (argc < 3) {
        cerr << "Wrong number of arguments" << endl;
        return 1;
    }
    cout << "Paswort input : " <<argv[1] << endl;
    string password(argv[1]);
    const char* ip_addr = argv[2];
    int port = atoi(argv[3]);
   
    string pwd(argv[1]);

    NetIO user_io(ip_addr, port); // User is the Receiver. 

    int numIterations = 1000;
    double time_stamps[numIterations];

    for(int i = 0; i < numIterations; ++i){
        // Record start time
        auto start = std::chrono::steady_clock::now();        

        // Create group object
        EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // emp uses NIST P-256 
        BN_CTX* bn_ctx = BN_CTX_new();
        EC_GROUP_precompute_mult(ec_group, bn_ctx);

        BIGNUM* field_order = BN_new();
        // Order of the underlying field is important to invert blinding value r
        int res = EC_GROUP_get_curve(ec_group, field_order, NULL, NULL, bn_ctx);
        if (res == 0) cerr << "2HashDH_User: Error while getting group parameters" << endl;

        EC_POINT* g = hash_to_curve(pwd, ec_group, bn_ctx);

        // Choose random blinding value r
        BIGNUM* r = BN_new();
        BN_rand_range(r, field_order);
        EC_POINT* a = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, a, NULL, g, r, bn_ctx); // a = g*r 

        // Write point a to binary so it can be sent over network
        uint8_t buf[ec_point_size_comp];
        int written = EC_POINT_point2oct(ec_group, a, POINT_CONVERSION_COMPRESSED, buf, ec_point_size_comp, bn_ctx);
        if(written < ec_point_size_comp) cerr << "2HashDH User: Error writing point a." << endl;
                user_io.send_data(buf, ec_point_size_comp);

        //Receive point b from server
        EC_POINT* b = EC_POINT_new(ec_group);
        user_io.recv_data(buf, ec_point_size_comp);
        res = EC_POINT_oct2point(ec_group, b, buf, ec_point_size_comp, bn_ctx);
        if(res != 1) cerr << "2HashDH User: Error receiveing point b." << endl;

        // Invert r
        BIGNUM* oneOverR = BN_new();
        BN_mod_inverse(oneOverR, r, field_order, bn_ctx); 

        EC_POINT* y = EC_POINT_new(ec_group);
        int mul_res = EC_POINT_mul(ec_group, y, NULL, b, oneOverR, bn_ctx); // y = b*(1/r) 
        if(mul_res != 1) cerr << "2HashDH User: Error unblinding b." << endl;

        //Hash the resulting point
        written = EC_POINT_point2oct(ec_group, y, POINT_CONVERSION_COMPRESSED, buf, ec_point_size_comp, bn_ctx);
        if(written < ec_point_size_comp) cerr << "2HashDH User: Error writing point y." << endl;
        uint8_t hashTwo[32];

        emp::sha3_256(hashTwo, buf, ec_point_size_comp);

        // Record end time
        auto finish = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = finish - start;
        std::cout << "Elapsed time: " << elapsed.count() << " s\n";
        time_stamps[i] = elapsed.count()*1000; // milliseconds

        //Print result
        cout << "THIS IS ROUND " << (i+1) << endl;
        cout << std::hex;
        for(int i = 0; i < 32; ++i){
            cout << (unsigned int) hashTwo[i] << endl;
        }
    }

    // Write measurements to a file
    string output_text = "";
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t); 
    char today[11]; 
    char time_now[9];;
    strftime(today, 11, "%Y-%m-%d", &tm);
    strftime(time_now, 9, "%H:%M:%S", &tm);
    output_text = "2HashDH benchmark from " + string(today) + " at " + string(time_now) + " with n = " + to_string(numIterations) + " iterations:\n";
    output_text += "User input: " + pwd + "\n";
    output_text += "-------------------------\n";
    output_text += "Measured time for each run:\n";
    
    // Running time
    appendArrayToString(output_text, time_stamps, numIterations);
    double avg_time = accumulate(time_stamps, time_stamps+numIterations, 0.0) / numIterations;
    output_text += "Average Time [ms]: " + to_string(avg_time) +"\n";
    //standard deviation
    double variance = 0;
    for(int i = 0; i < numIterations; ++i){
        variance += (time_stamps[i] - avg_time)*(time_stamps[i] - avg_time);
    }
    variance /= numIterations;
    double standard_deviation = sqrt(variance);
    output_text += "Standard Deviation [ms]: " + to_string(standard_deviation) + "\n";

    string filename = "2HashDH_benchmark_results_";
    strftime(time_now, 9, "%H_%M", &tm);
    filename += string(today) + "_";
    filename += string(time_now);
    filename += ".txt";
    ofstream out(filename);
    out << output_text;
    out.close();
}