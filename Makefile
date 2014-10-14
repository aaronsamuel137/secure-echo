OUT=client server

FLAGS=-lssl -lcrypto -Wno-deprecated-declarations

# compiler
CC=gcc

#  Main target
all: client server

client:
	$(CC) -o echoClient echoClient.c $(FLAGS)

server:
	$(CC) -o echoServer echoServer.c $(FLAGS)

clean:
	rm $(OUT)
