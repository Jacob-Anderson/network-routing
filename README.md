## Network Routing Project

This repository consists of a project, written in C, created for a Data Networks course (CS 5133) at the University of Oklahoma during the Fall 2016 semester. The code is a bit hacked together in spots, but it gets the job done.

#### Network Setup

Initialize a network given a set of [config files](../master/host-configs) (one for each network node/host) containing an abstract/fake ip address, a port number, and similar information about the host's neighbors.

Create a socket for each host and spawn sender and receiver threads for each host.

#### Sender Thread

Constructs a routing table for the network using an implementation of the [distance-vector routing protocol](https://en.wikipedia.org/wiki/Distance-vector_routing_protocol).

Parses a given [input file](../master/input.bin) containing IPv4 frames to be exchanged between network hosts. If a frame is found that has a sender address matching the host's abstract/fake ip address, use the constructed routing table to send the frame to its destination.

#### Receiver Thread

Accept incoming frames, passing them along to their next-hop destination if they haven't reached their final destination. If they have, print them.


### Run/Build Instructions

* gcc network-routing.c -lpthread -lm
* ./a.out "host-configs/A.txt" "input.bin"
* ^ The above command must be run for all config files (A - L) in a ~5 second window

