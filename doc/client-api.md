
This document is to describe the architecture of the Client API project. For API call info, see `src/client-api/README.md`.

### Running
You must first pass the `--enable-clientapi` flag to  `configure` when building.
Following that, to run with API enabled:
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

## Examples

For playing with the project It's recommended you run in regtest mode.
Your `zcoin.conf` file should be, at the least:
```
clientapi=1
regtest=1
dandelion=0
```

### Publisher
For an example of the publisher in action, see `client-api/examples/sub_example.py`.
- To run on MacOS: 
    `python sub_example.py regtest auth mac`
- To run on Linux (tested on Ubuntu only): 
    `python sub_example.py regtest auth ubuntu`
- can also run on Windows Subsysten for Linux (WSL):
    `python sub_example.py regtest auth windows_wsl`

You can then eg. generate blocks using `./zcoin-cli generate 10`, and you should see block updates being published in your terminal window.

### Replier

   To use the examples for the replier, please first download and setup the `zcoin-client` repo.
    You will need Node.js installed.
        `git clone https://github.com/zcoinofficial/zcoin-client`
        `npm install`

#### Using zcoin-client examples
   You will need to rebuild `zcoind` without ZMQ authentication, as this is currently not implemented in the Node examples.
   - Open `zmqserver/zmqabstract.h` and change `ZMQ_AUTH` to `false`.
    
   in `zcoin-client`: `cd examples/api`
     Then run an example, eg. `node apiStatus.js`

#### Using the GUI itself
   You can make calls from the `zcoin-client` GUI within Chrome Dev Tools. All methods are available but must be formatted correctly.
    - First run `zcoind`
    - then run `npm run dev` from `zcoin-client`
    - Open Chrome Dev Tools from the taskbar
    - Use the following command:
        `await $daemon.send(null, '{TYPE}', '{METHOD_NAME}', {JSON_ARGS})`

   refer to https://github.com/zcoinofficial/zcoin/tree/client-api/src/client-api for data formats.

### Settings
  As in Qt with `QSettings`, the client adds a level to the settings hierarchy in `zcoind`. The following is the current hierarchy, in descending order of importance:
  `CLI -> zcoin.conf -> QSettings`
  Where `CLI` is settings passed via the command line interface to `zcoind`, `zcoin.conf` is settings defined in the `zcoin.conf` file in your datadir, and ` QSettings` is Qt-specific settings. What this means is a setting passed via CLI will always override the same one set in either of the lower tiers.

  In `zcoin-client`, `QSettings` is replaced by the file `persistent/settings.json` in your datadir. Each setting here has the following format:
  ```
  "-settingname": {
      "data": STRING,
      "changed": BOOL,
      "disabled": BOOL
  },
  ```
  If a user changes a setting from within the client, the API function `setting` is used to modify it in `settings.json`.
  The following values are used to notify, on restart, what to do:
  `changed`: If the client requests to change a setting, this will be set to `True` in that setting. Following restart, The setting will be enabled.
  `disabled`: if the same setting is defined further up the hierarchy, this is set this to `True`.

  On `zcoind` start, this JSON file is parsed along with the CLI and conf selections, to produce the final list of settings.

