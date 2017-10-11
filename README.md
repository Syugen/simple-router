# Simple Router
This README.md is written by Yuan Zhou
## Introduction
Write a simple router with a static routing table. The router receives raw Ethernet frames, processes the packets just like a real router, then forwards them to the correct outgoing interface.
## Get Started
First, clone this repository to the home directory of Mininet and `cd` into it.
### Prerequisites
You need `python-dev` to install `ltprotocol`, which is needed for our POX module. Run the following commands.
```
sudo apt-get install python-dev
git clone git://github.com/dound/ltprotocol.git
cd ltprotocol
sudo python setup.py install
```
You need to install the POX module by
```
./config.sh
```
### Start Mininet
Start Mininet emulation by using the following command
```
./run_mininet.sh
```
### Setup and Start POX
Start a new terminal, checkout the POX version that we use in this assignment
```
cd /home/mininet/pox
git checkout f95dd1a81584d716823bbf565fa68254416af603
```
Then start the POX
```
cd ~/simple-router
ln -s ../pox
./run_pox.sh
```
### Start the Router
Open yet another terminal (the third one). Run the binary file of the solution (correctly implemented router)
```
./sr_solution
```
## Develop
Edit files in the `router` directory, compile and run the router by:
```
cd router
make
./sr
```
