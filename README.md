Welcome to wechat!

Setup:
We require the gin package.  Run the following command:
	go get github.com/gin-gonic/gin

src/util contains a go script with some of our defined functions that that both the client and discovery server scripts benefit from  

First start the discovery server by running:
	cd src/discovery
	go run discovery.go [port number eg. 8080]

To start a client:
    cd src/client
	go run cli.go [username] [channel] [channel_pw] [join] [server_addr] [client_port]

    [username]      -> The username you want use in chat (eg. Cen)
    [channel]       -> The unique id of your chat channel (eg. pizzapalace)
    [channel_pw]    -> The password required to enter the designated chat channel (eg. secret_sauce)
    [join]          -> Either T (for true) meaning you are joining the channel or F (for false) if you are creating a channel. When creating, [channel_pw] becomes the channels pw (eg T or F)
    [server_addr]   -> The ip address and port of the discover server (eg. 242.674.245:8080)
    [client_port]   -> The port you want to run your client on (eg. 8000)

The full chat history will be immediately retrieved from one of the other clients in your chat if you are joining and printed onto the terminal. Afterwards, start typing to chat!

To leave a chat, CTRL+C

We follow the API at https://github.com/jvilk/WeChat/blob/master/reference_client/api.txt except where specified in the ASSUMPTIONS below

PROTOCOL OVERVIEW:
------
* Messages are displayed as [username] _ [seqnum]: [msg] and are indented whereas messages being typed are not.
* Client joins chat by contacting discovery server.
* Discovery server responds with a list of IP addresses on network.  New client is added to the list.
* New client notifies all other clients of its existence.
* Other clients record that the new client is present and send it their current CHAT\_HISTORY. A vector clock piggybacks on this message.
* Client chooses the chat history with the longest length as the primary.
* After a short time period, the new client locks-in on what the CHAT\_HISTORY really is and may begin transmitting messages.

* If a client X wants to transmit, it first asks for permission from all other clients.  X tells the other clients the vector clock time associated with its message.  This is accompanied by X's current vector clock time, which might differ from the pending message's vector clock.  This is called the "mic check" in our naming conventions.
* A client Y that receives the request will update its vector clock based on it.  Y will not respond to a permission request if Y is trying to send a message with an earlier vector clock time than X's message.  IP address comparisons are used to break ties.  Otherwise, client Y responds.  A vector clock piggybacks on this response.
* If X does not receive permission from some client Y for a sufficiently long amount of time, Y is marked as dead.  This realization is conveyed to the other clients and the discovery server to conserve bandwidth.  A vector clock time piggybacks on this.
* Client X sends a message to all clients, telling them that the message was confirmed by everyone.  A vector clock time piggybacks on this.
* Upon being received, client X's message is finally recorded to the logs.  Receiving this also updates vector clocks.

ASSUMPTIONS:
------
* All peers with the proper password on the network comply with the protocol above.  Otherwise, they could wreak havoc by distributing long bogus CHAT\_HISTORies to newcomers.  They could always claim their message has a tiny vector clock value.  They could tell clients that some client was dead to get them to stop sending messages to them.  They could incorrectly claim to have gotten permission from all peers to write the message to the log to mess with ordering.
* Network connectivity is reasonable.  Otherwise, a client might mark a functioning client as dead.  Messages might also fail to clear in a reasonable amount of time and the log ordering could become inconsistant.
* The network has minimal noise.  Otherwise, the wrong text messages might be conveyed.  The wrong vector clock times could be advertised when asking for permission.  Clients might think that the wrong IPs are in the network.
* All clients and the discovery server are on different ip addresses or ports.  As the combination of these two is used for tiebreaking, there are cases when it is unclear which speaker has priority if two clients have the same IP address and port.
* There's always at least one client in a conversation.  If all clients in a conversation shut down, there will be no one for newcomers to fetch the log from.
* The messages are the only sensitive data.  Names and IP addresses are not encrypted.
* AES encryption is not easy to decode without a key.  Otherwise, our messages can be easily decoded without a key.
* We assume no one knows about the super-secret get\_history backdoor.  :)
* In the original centralized API, there were the following endpoints that we felt do not apply to our implementation:
    1.) Leave channel:
      PUT http://machine:8000/channels/[channel]/leave
        [request header field] session: <session key>

      200 -> OK
      401 -> UNAUTHORIZED (user not in channel)

    -> In our case, since it is distributed and the clients do not talk to the server after obtaining IP's then we felt this could be left out of the discovery server's list of endpoints

    2.) Ask the server for an event:
      GET http://machine:8000/channels/[channel]/events
        [request header field] session: <session key>
        [request header field] sequence: <sequence number>

      200 -> OK
        [HTTP response depends on type of event; see Event Objects below]
      401 -> UNAUTHORIZED
      404 -> NOT FOUND (no more events to fetch)
    -> In our case, the server has no recollection of messages (it's all handeled within each of the clients)

* For the endpoint:
    Fetch the most recent user list:
      GET http://machine:8000/channels/[channel]/directory
        [request header field] session: <session key>

      200 -> OK
        [request body] <message>
      401 -> UNAUTHORIZED

    we assume that the password for the channel is in the header "session" as <session key>

TESTS ATTEMPTS:
* Fault Tolerance ->
    1.) Created a channel with 3 clients
    2.) Each of them typed random things into the chat
    3.) We then disconnected one of the clients (CTRL+C)
    4.) We reconnected the client after a few seconds and checked if the full message log of the chat was retrieved and in proper order

* Consistency ->
    1.) Created a channel with 3 clients each piped with yes -> eg.) yes A| go run cli.go ...
    2.) Stopped all clients after they have spammed the channel for a while.
    3.) Manually checked to see if the message log was consistent between the three clients on their local terminals 
