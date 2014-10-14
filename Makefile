OUT=echoClient echoServer

FLAGS=-lssl -lcrypto -Wno-deprecated-declarations

# compiler
CC=g++

#  Main target
all: client server

client:
	$(CC) -o echoClient echoClient.cpp $(FLAGS)

server:
	$(CC) -o echoServer echoServer.cpp $(FLAGS)

clean:
	rm $(OUT)
