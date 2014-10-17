Secure Echo
=======
An echo client and server that communicate securely using SSL.
Compatible with both OSX and Linux.

author
------
Aaron Davis

compiling
---------
Type 'make' in the project directory.

By default, the code will be compiled with logging enabled, which means that
some informational messages will be printed as well as just the echo service.
To disable logging, turn off the logging flag in ssl_util.h and recompile.

running the program
-------------------
Start the server with:

./echoServer [port]

The server will run on port 5004 by default if no port is specified.
If specified or default port is not available, the server will run on
a system selected port and print this port number to the terminal.

Run the client with:

./echoClient [host [port]]

By default the client will connect to localhost on port 5004

known issues
------------
No known issues. The program runs as expected on OSX and Linux.

acknowledgements
----------------
The code is based on the echo server and client provided to us.
The main examples for how to use the openssl libraries comes from
http://h71000.www7.hp.com/doc/83final/ba554_90007/ch05s04.html (server) and
http://h71000.www7.hp.com/doc/83final/ba554_90007/ch05s03.html?btnPrev=%AB%A0prev (client)
