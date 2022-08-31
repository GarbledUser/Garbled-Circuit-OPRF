#ifndef OPRF_SERVER_HEADER
#define OPRF_SERVER_HEADER

#include "garbling-scheme.h"
#include "emp-tool/emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "oprf_utils.h"

#include<bitset>
#include <iomanip>

using namespace emp;
/*
 Class that represents an OPRF server that can answer queries for a user.
 Note that only one execution at a time is possible with this implementation.
 T is the IO Channel type with which the server will communicate.
*/
template <class T>
class Server{

    private:
    vector<bool> key;
    int sid;
    T* io;

    void sendKeyAndDecoding(const vector<block>& encoded_key, const vector<bool>& decoding_info){
        io->send_block(encoded_key.data(), AES_KEY_SIZE);

        //Cant't use vector<bool>::data(), behaves different than for usual types. 
        bool dec[AES_INPUT_SIZE];
        copy(decoding_info.begin(), decoding_info.end(), dec);
        io->send_bool(dec, AES_INPUT_SIZE);
    }

    void sendLabelsOverOT(const vector<block>& encoded_zeros, const vector<block>& encoded_ones){
        OTNP<T> np(io); // create a Naor Pinkas OT using the same network as for all communication
        np.send(encoded_zeros.data(), encoded_ones.data(), AES_INPUT_SIZE); 
    }


    void sendGarbledCircuitFromMem(MemIO* mem_io){
        block b; 
        //until everything is read
        while((mem_io->size - mem_io->read_pos ) > 0){
            mem_io->recv_block(&b, 1);
            io->send_block(&b, 1); 
        }
    }

    public:
    /*
    *Constructs a new server with session id sid and PRF key k (must be a AES_KEY_SIZE bit vector)
    *io is the NetIO to which Server communicates.
    */
    Server(vector<bool> k, int sid, T* io){
        //TODO key size prüfen
        key = k;
        this->sid = sid;
        this->io = io;
    }

    /* Server garbles the circuit and sends the encoded key, the decoding information an (via OT) the labels to the user
    *Finally sends circuit to the user.
    *Important: Rember to flush io after this function if io is of type FileIO
    */
    void onGarble(int ssid, vector<block>* encoded_ones, vector<block>* encoded_zeroes){
        //Write garbled circuit to memory first, so other stuff is sent first
        MemIO* mem_io = new MemIO();
        vector<block> encoding_info; 
        vector<bool> decoding_info;
        garble(mem_io, &encoding_info, &decoding_info, circuit_filename);
        // Server garbled circuit F

        vector<bool> input_zeros(AES_INPUT_SIZE, false);
        //append key
        input_zeros.insert(input_zeros.end(), key.begin(), key.end());
        // Produce labels K and X[0^n] 
        encode(encoded_zeroes, input_zeros, encoding_info);
        vector<block> encoded_key = vector<block>(encoded_zeroes->begin() + AES_INPUT_SIZE, encoded_zeroes->begin() + (AES_INPUT_SIZE+AES_KEY_SIZE));

        // Produce labels X[1^n]
        encoded_zeroes->resize(AES_INPUT_SIZE);
        vector<bool> input_ones(AES_INPUT_SIZE, true);
        encode(encoded_ones, input_ones, encoding_info);

        // Send K,d to User and X[0], X[1] to OT
        sendKeyAndDecoding(encoded_key, decoding_info);
        sendLabelsOverOT(*encoded_zeroes, *encoded_ones);

        // Send garbled circuit
        sendGarbledCircuitFromMem(mem_io);
    }

    void setKey(const vector<bool>& newKey){
        this->key = newKey;
    }
};

// If FileIO is used, the emp OT does not work. therefore, leave this method empty
template <>
void Server<FileIO>::sendLabelsOverOT(const vector<block>& encoded_zeroes, const vector<block>& encoded_ones){};

#endif
