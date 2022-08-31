#include "oprf_user.h"
#include <chrono>

using namespace std;

int port;
const int portNetMeasure = 8890;
char* ip_addr;

//arbitrary values
int sid = 1;
int ssid = 1;

// appends a string representation of a to out. Array has to have lenght len. Functions is only needed to print the final results to a file
void appendArrayToString(string& out, double* a, int len) {
    out += "[";
    for(int i = 0; i < len-1; ++i){
        out += to_string(a[i]) + ", ";
    }
    if (len > 0)
        out += to_string(a[len-1]);
    out += "]\n";
}

//measure the runtime
void measureRuntime(const string& password, string& output_text, int numIterations){
    // Create User and OT objects
    NetIO user_io(ip_addr, port); // User is the OT-Receiver. 
    User<NetIO> u(sid, &user_io);
    double time_stamps[numIterations];

    for(int i = 0; i < numIterations; ++i){
        // Record start time
        auto start = std::chrono::high_resolution_clock::now();        
        bool* current_h = u.eval(password, ssid);
                
        // Receive garbled encoded key and decoding info
        block encoded_key[AES_KEY_SIZE];
        bool decoding_info[AES_INPUT_SIZE];
        u.receiveKeyAndDecoding(encoded_key, decoding_info);

        // Request labels via OT for H_1(password)
        block labels[AES_INPUT_SIZE];
        u.receiveLabels(current_h, labels);
        
        // Evaluate circuit and hash the output with sha3
        uint8_t* output = u.onLabelsReceived(ssid, labels, encoded_key, decoding_info);

        // Record end time
        auto finish = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = finish - start;
        std::cout << "Elapsed time: " << elapsed.count() << " s\n";
        time_stamps[i] = elapsed.count()*1000; // miliseconds

        //Print result
        cout << std::dec << "THIS IS ROUND " << (i+1) << endl;
        cout << std::hex;
        for(int i = 0; i < SHA3_OUTPUT_SIZE/8; ++i){
            cout << (unsigned int) output[i] << endl;
        }
    }
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

}

// This class is used to measure network traffic. It just calls NetIO's functions but keeps track of the amount of sent data.
// Simply inheriting from NetIO does not work because of IOChannel::derived() function
class MeasureNetIO : public IOChannel<MeasureNetIO>{
    public:
    NetIO* net_io;
    int bytes_sent = 0;
    int bytes_received = 0;

	MeasureNetIO(const char * address, int port, bool quiet = false) {
        net_io = new NetIO(address, port, quiet);
    }
    ~MeasureNetIO(){
        delete net_io;
    }

    void sync(){
        net_io->sync();
    }

	void set_nodelay() {
        net_io->set_nodelay();
    }

	void set_delay() {
        net_io->set_delay();
    }

    void flush(){
        net_io->flush();
    }

	void send_data_internal(const void * data, int len) {
        bytes_sent += len;
        net_io->send_data(data, len);
    }
    //override
	void recv_data_internal(void  * data, int len) {
        bytes_received += len;
        net_io->recv_data_internal(data, len);
    }
};

//measure how much data is sent
void measureNetTraffic(const string& password, string& output_text){
    // Create User and OT objects
    MeasureNetIO user_io(ip_addr, portNetMeasure); // User is the OT-Receiver. 
    User<MeasureNetIO> u(sid,  &user_io);

    bool* current_h = u.eval(password, ssid);
    // Receive garbled encoded key and decoding info
    block encoded_key[AES_KEY_SIZE];
    bool decoding_info[AES_INPUT_SIZE];
    u.receiveKeyAndDecoding(encoded_key, decoding_info);
    // Request labels via OT for H_1(password)
    block labels[AES_INPUT_SIZE];
    u.receiveLabels(current_h, labels);
    uint8_t* output = u.onLabelsReceived(ssid, labels, encoded_key, decoding_info);

    output_text += "Measured traffic for the run:\n";
    output_text += ("Measured Traffic sent [Bytes]: " + to_string(user_io.bytes_sent) + "\n"); 
    output_text += ("Measured Traffic received [Bytes]: " + to_string(user_io.bytes_received) + "\n");
    output_text += ("Measured Traffic total[Bytes]: " + to_string(user_io.bytes_sent + user_io.bytes_received) + "\n");
}

int main(int argc, char* argv[]){
    //Parse command line argument
    if (argc < 1) {
        cerr << "Wrong number of arguments" << endl;
        return 1;
    }
    cout << "Paswort input : " <<argv[1] << endl;
    string password(argv[1]);
    ip_addr = argv[2];
    port = atoi(argv[3]);

    int numIterations = 1000;
    // Write measurements to a file
    string output_text = "";
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t); 
    char today[11]; 
    char time_now[9];;
    strftime(today, 11, "%Y-%m-%d", &tm);
    strftime(time_now, 9, "%H:%M:%S", &tm);
    output_text = "GC-OPRF benchmark from " + string(today) + " at " + string(time_now) + " with n = " + to_string(numIterations) + " iterations:\n";
    output_text += "User input: " + password + "\n";
    output_text += "-------------------------\n";
    output_text += "Measured time for each run:\n";
    
    // Actual benchmarks
    measureRuntime(password, output_text, numIterations);
    measureNetTraffic(password, output_text);
    
    string filename = "gcoprf_benchmark_results_";
    strftime(time_now, 9, "%H_%M", &tm);
    filename += string(today) + "_";
    filename += string(time_now);
    filename += ".txt";
    ofstream out(filename);
    out << output_text;
    out.close();
}
