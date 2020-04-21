# The stablecoin demonstrator


The goal of this project is to implement a proof-of-concept where parties can
exchange stable-tokens that track the value of a real-world asset in a
decentralized enterprise-oriented payment network.

that
must:

- manage the ownership of real Euros in a permissioned network
- allow parties to deposit euros into a bank account, and get representative
tokens that can have all the technical properties of money, plus:
    * programmability,
    - transparency, and
    - accountability,

- be built on the TrustChain blockchain,

, should:

- facility multiple account holders to

- include random witness selection from an earlier project
- implement a rest API that enables Node owners to interact with their Node in a
programmable way.

, and could:

- be easily generalised to manage any asset

# Getting Started

These instructions will get you a copy of the project up and running on your
local machine for development and testing purposes.

## Prerequisites

- Docker
- A Rendezvous Point (see Running on local machine)

If you want to run without docker:

- pipenv
- python3.7

## Running

To get a working demo to play with, a rendezvous server and some clients are
needed.

-The client can be run both on the local machine as well as in docker (docker is
recommended)
-The rendezvous server can currently only be run on the local machine.

When these are running, interaction with the clients happens through a web
interface.

## Running in docker

The least troublesome way to run a Node is with docker.

1. Build the image with: `docker build -t stablecoin .`
2. The proof of concept can then be started by using the command:
``docker run -it --rm -p 80:80 -p 1963:1963 --name=demo stablecoin``
3. Now you can to to `localhost:80` in the browser to interact with the node.

Explanation of the docker flags:

- `-it`  tells docker to keep the console open, and send the image output to
the console, alternatively you can use `-d` to run it in detached mode instead.
- ` --rm`: Tells docker to automatically delete the container after it stops.
- `-p 80:80` forwards all traffic on host port 80 to the docker containers
port 80. This is the port the user interface runs on, when running multiple
clients you should map every client to a different port on the host
(eg, `-p 8080:80`).
- `-p 1963:1963` This is the port for Node to Node communication, if Nodes only
have to connect to other nodes on the docker network you don't need this option.
- ``--name=demo`` Gives the container a friendly name, which makes it easier to
reference it later on.
- ``stablecoin`` This is the name of the image we built in step 1

## Running on local machine

When running on your own machine, some more setup is required.

1. First make sure pipenv and python3.7 are installed.
2. From the root project root directory run `pipenv install`. This will create a
   virtual environment using the correct python version and all dependencies.
3. `cd stablecoin`
4. Run the Rendezvous server `python Rendezvous-service.py --IP [yourIp]
   --dummyNodes 10`
5. (optional )In a separate terminal, run the Client `python ./Client.py --guiPort 8080i
   --port 1963` (NOTE: on linux, if you are not root you cannot bind to ports
   below 1024)

## Using the client through the web interface

1. In your browser, go to localhost:port, with the gui port you set in earlier
   steps (eg, 80 or 8080)
2. Enter your a name for you account, and enter the connection details for the
   rendezvous point. After pressing save you'll be presented the home screen of
   the self-sovereign bank.
3. From here you can make transactions to any of the other nodes on the network.
   To demonstrate the power of the network, it is also allowed to make
   transactions with a higher value than your current balance. When doing so the
   interface will first inform you that your current value is insufficient, but
   can be forced by clicking the 'send anyway' button. while nothing seems to
   happen, the network actually receives, but refuses the transaction. This can
   be seen in the log which can be found in the right upper corner under 'extra->log'.

## Stopping the clients
Exiting the console is done by hitting ctrl-C twice, if you chose to run in
docker using the `-d` flag, stopping it can be done with: ``docker container
stop demo``

## Understanding the log files

A successful transaction will have a log resembling :
```
05/19/2019 14:00:28: INFO - Starting None at 1963 and will connect to (None,0)
05/19/2019 14:30:16: INFO - Sarted server at port 1963
05/19/2019 14:30:16: INFO - Received updated peer list
05/19/2019 14:30:22: INFO - Initiated transaction with Super smooth node no. 9, value: 12
05/19/2019 14:30:22: INFO - At least 5 witnesses are required before the transaction will pass
05/19/2019 14:30:22: INFO - Valid witness reply received.
05/19/2019 14:30:22: INFO - Valid witness reply received.
05/19/2019 14:30:22: INFO - Valid witness reply received.
05/19/2019 14:30:22: INFO - Valid witness reply received.
05/19/2019 14:30:22: INFO - Valid witness reply received.
05/19/2019 14:30:22: INFO - Transaction successful with 5/6 valid witness replies
```

An unsuccessful transaction will have a log similar to:
```
05/19/2019 14:30:29: INFO - Initiated transaction with Super smooth node no. 4, value: 43211
05/19/2019 14:30:29: INFO - At least 5 witnesses are required before the transaction will pass
05/19/2019 14:30:29: INFO - Received Nack on witness request.
05/19/2019 14:30:29: INFO - Received Nack on witness request.
05/19/2019 14:30:29: INFO - Received Nack on witness request.
05/19/2019 14:30:29: INFO - Received Nack on witness request.
05/19/2019 14:30:29: INFO - Received Nack on witness request.
05/19/2019 14:30:29: INFO - Received Nack on witness request.
05/19/2019 14:30:29: INFO - Max witnesses reached but not enough valid replies.
05/19/2019 14:30:29: ERROR - Transaction failed, not enough valid witnesses
```


For this proof-of-concept a homogeneous network is chosen, every node who
utilizes the network also contributes to this very network. This is not
necessary as it would also be possible to make a distinction between
'light-clients', which can only initiate but not witness transactions, and
'full-clients' which can both witness and initiate transactions.

# On the future of this project

This project could be extended with the following features:

Conceptual:

- A way to get stablecoins into the system by depositing euros (exchanging euros
for tokens)
- An verification/accountability model that tracks the origin of a stablecoin
and determines what valid spending is and who would liable in case of fraud.
- A way to get stablecoins out of the system by (exchanging tokens for euros)

Implementation:

- Node integration with a bank account for entry and exit
- Transfer/verification code
- An API to integrate these features


# Some notes regarding the previous incarnation of this project

The base code for this project is inherited from a previous incarnation of this
project, and some code, such as the testing scripts, are missing. This will
leave some dangling entry points into the code, that are not used. This may or
may not be trimmed in the future

## Inherited design choices

From the old project:

On the rendezvous point:
```
By design the is system peer-to-peer, this means that nodes make a direct
connection to other nodes. A side effect is that every node needs to know
their IP-address and share this with all the other nodes. Doing a demonstration
for 10 people, they each would have to enter 9 IP-addresses.

To circumvent this hassle with IP-addresses a simple python script was written,
which acts as a rendezvous point. Nodes announce their presence to this
rendezvous point, and the rendezvous point will record the used IP address and
will forward an updates list of addresses and nodes to all connected nodes.

While this takes away the beauty of decentralizing for peer discovery, it is an
easy and justifiable mechanism for a demonstration.
```

On the network parameters:
```
To demonstrate the fraud resistance of the network multiple barriers have been
taken away to prevent hem happen.

- First of all, every agreement is bilateral meaning that the counter party is
knowingly and willingly accepting a transaction that is bigger than the counter
party's balance. A normal (honest) client would directly refuse to partake in
this transaction, but for this demonstration this check is ignored.
- Secondly, the witness set is set to only 6. While this offers low security, it
eases the demonstration as this lowers the number of nodes needed for a working
example. while the rendezvous point could host a vast number of dummy nodes,
this would clutter the recipients list in the gui.
```
