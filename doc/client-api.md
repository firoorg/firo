This document is to describe the architecture of the Client API project. For API call info, see `src/client-api/README.md`.

### Running
to run with API enabled:
    - start `zcoind` with `clientapi=1` flag, either by passing via CLI or by putting into `zcoin.conf`.

### Architecture 

`src/clientapi` and `src/zmqserver` contains the main body of code for the project.

## ZMQ-Server
`zmqserver` implements the transport mechanism, written in C ZMQ. 
There are two possible delivery mechanisms - A PUBlisher and a REPlier, respectively the "push" and "pull" architectures. Clients connect to the PUBlisher via a SUBscriber mechanism and the REPlier via a REQuester. The PUBlisher periodically sends out data based on various events occuring within `zcoind`. The REPlier responds to requests for data from the REQuester.

### ZMQ Abstract
Both architecture types are abstracted out in `zmqserver/zmqabstract.*`. Here a set of common values and functions are created. 

### ZMQ Interface
This module allows external events to interact with the ZMQ server. 
`src/validationinterface.*` defines a set of virtual functions, such that as certain events occur in `zcoind`, any class which implements the function under which the event occurred will be called. For example, `UpdatedBlockTip` is implemented by various modules in `zcoind`, including ZMQ-Server. Once the block tip is updated, the publisher is triggered and sends data to a listening subscriber.

### Events/Topics
The idea of an external event occuring has been discussed. There are situations where we want to trigger more than one Client-API function on an external event occuring. This is where the idea of `topics` comes from. Each ClientAPI function (that's triggered by the publisher) is considered as a single topic (see `zmqserver/zmqpublisher.h`).  Any topic that inherits from an event class is triggered on that event. Take for example, the `BlockInfo` topic, which publishes data about the blockchain state. If a new block is detected (`CZMQBlockEvent`), the number of connections changes (`CZMQConnectionsEvent`), or sync status changes (`CZMQStatusEvent`), the method `blockchain` in `client-api/blockchain.cpp` is triggered, and is sent to the listening subscriber.

### Topic ID
Each topic has a topic ID, which is simply a string identifying the topic. In order to receive data for a publisher, you must be subscribed to that topic ID. Each topic ID is defined in `zmqserver/zmqpublisher.h`.

Example
For an example of the publisher in action, see `client-api/examples/sub_example.py`.
