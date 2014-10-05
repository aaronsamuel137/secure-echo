OUT=client server

DEPENDENCIES=verify.c

# compiler
CC=gcc

#  Main target
all: client server

client:
	$(CC) $(FLAGS) -o client echoClient.c $(DEPENDENCIES)

server:
	$(CC) $(FLAGS) -o server echoServer.c $(DEPENDENCIES)

clean:
	rm $(OUT)
