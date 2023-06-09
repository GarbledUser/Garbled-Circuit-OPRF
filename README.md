# OPRF-Garbled-Circuits
Different implementations of oblivious pseudo-random functions using (amongst others) the emp-toolkit project. https://github.com/emp-toolkit

## Project Structure
The project is structured into three main folders. One for 2HashDH and the EMP-Toolkit based version of GCOPRF.
The second folder PQ-MPC is a fork of https://github.com/encryptogroup/PQ-MPC. Inside, there is the folder pq-oprf that contains an OPRF implementation based on the post-quantum
secure implementation of Garbled Circuits, provided by PQ-MPC.

## Prerequisits
You have to install cmake, OPENSSL, PKG-Config and Boost via

`sudo apt install cmake libssl-dev pkg-config libboost-all-dev`

Then run 
`git clone`
`cd OPRF-Garbled-Circuits/`
`git submodule init`
`git submodule update`


## Building the Projects

### Building PQ Version
`cd PQ-MPC`
`git submodule init`
`git submodule update`
`cd PQ-MPC`
`git checkout origin/master`
`cmake .`

Run the protocol by calling
`./bin/user_pq-oprf 1 abc 127.0.0.1 8888 & ./bin/server_pq-oprf 1 8888`

### Building Optimized Version and 2HashDH
Emp-toolkit and EMP-OT are inserted as git submodules. Therefore the submodules must be initiated before it can be built. Afterwards build the project with cmake. Apparanetly it is necessary to build emp-tool first separatly. There might be a solution to that.

`cd old_implementation`
`python3 install --tool --ot`
`cmake  .`
`make`

Run the GC protocol by calling
`./bin/test_user abc 127.0.0.1 8888 & ./bin/test_server 8888`

Run the 2HashDH protocol by calling
`./bin/2HashDH_user abc 127.0.0.1 8888 & ./bin/2HashDH_server 8888`

### Building Isogeny Protocol OPUS
`cd isogeny-oprf`
`make`
Run the protocol by calling 
`./client 127.0.0.1 8888 & ./server 8888`


## WAN Tests
To simulate a WAN test, type 
`sudo tc qdisc add dev lo root  netem  delay 100ms rate 50mbit`
in your linux terminal. This will set the local interface (127.0.0.1) to have rate limit 50mbit and latency 100ms.
To remove the rate limiting from your interface type
`sudo tc qdisc del dev lo root`

