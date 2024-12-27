# define the c++ flags
CXXFLAGS = -Wall -Wno-sign-compare -Wfatal-errors -g -std=c++17 -fsanitize=address,undefined -lssl -lcrypto -pthread -lavcodec -lavformat -lavutil -lswscale

all: client server
client: ./src/client.cpp ./src/video.h ./src/client_util.h
	g++ ./src/client.cpp $(CXXFLAGS) -o ./build/client
server: ./src/server_multithread.cpp ./src/user_action.h ./src/thread_pool.h ./src/server_util.h
	g++ ./src/server_multithread.cpp $(CXXFLAGS) -o ./build/server