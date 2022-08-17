CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lcrypto -lstdc++fs -lmcheck
OPT = -ggdb3
TARGET = user server
DEPS = ./utils.h

all : start-server start-user

start-server: server/start-server.cpp
	$(CC) $(CFLAGS) $< -o server/$@ -I$(DEPS) $(LDFLAGS)

start-user: user/start-user.cpp
	$(CC) $(CFLAGS) $< -o user/$@ $(OPT) -I$(DEPS) $(LDFLAGS)

clean:
	rm server/start-server
	rm user/start-user

# valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./executable exampleParam1