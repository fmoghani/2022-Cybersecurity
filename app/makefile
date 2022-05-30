CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lcrypto -lstdc++fs
TARGET = user1 server
DEPS = utils.h

all : $(TARGET)

server:
	$(CC) $(CFLAGS) server/start.cpp -o server/start -I$(DEPS) $(LDFLAGS)

user1:
	$(CC) $(CFLAGS) user/start-user.cpp -o user/start-user -I$(DEPS) $(LDFLAGS)

clean:
	rm $(TARGET)