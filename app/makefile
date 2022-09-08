CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lcrypto -lstdc++fs # -lmcheck
OPT = -ggdb3
TARGET = user server
DEPS = ./utils.h

all : start-server start-user

start-server: server/start-server.cpp
	$(CC) $(CFLAGS) $< -o server/$@ -I$(DEPS) $(LDFLAGS)

start-user: user_khabib/start-user.cpp
	$(CC) $(CFLAGS) $< -o user_khabib/$@ $(OPT) -I$(DEPS) $(LDFLAGS)

start-user: user_alice/start-user.cpp
	$(CC) $(CFLAGS) $< -o user_alice/$@ $(OPT) -I$(DEPS) $(LDFLAGS)

clean:
	rm server/start-server
	rm user/start-user

# valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt --exit-on-first-error=yes --error-exitcode=1 ./executable exampleParam1