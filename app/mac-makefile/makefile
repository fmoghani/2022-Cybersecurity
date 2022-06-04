C := /usr/local/bin/gcc-8
CXX := /usr/local/bin/g++-8

CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lcrypto -lstdc++fs
TARGET = user server
DEPS = ../utils.h

all : start-server start-user

start-server: ../server/start.cpp
	$(CC) $(CFLAGS) $< -o server/$@ -I$(DEPS) $(LDFLAGS)

start-user: ../user/start-user.cpp
	$(CC) $(CFLAGS) $< -o user/$@ -I$(DEPS) $(LDFLAGS)

clean:
	rm ../server/start-server
	rm ../user/start-user