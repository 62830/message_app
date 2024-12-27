#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h> 
#include <unistd.h> 
#include <cstdlib> 
#include <fcntl.h> 
#include <vector>
#include <poll.h>
#include <sstream>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "thread_pool.h"
#include "user_action.h"
#include "server_util.h"

using namespace std;
using json = nlohmann::json;

#define GET(type) template get<type>()
#define N_WORKERS 16
#define MAX_CLIENTS 100
#define FILE_CHUNK_SIZE 1024
vector<user_session> user_sessions; // size should never exceed 3*MAX_CLIENTS+2
vector<struct pollfd> pfds; // size should never exceed 3*MAX_CLIENTS+2
// user_sessions[0] is for server_fd, user_sessions[1] is for pipefd[1]
// pfds[0] is for server_fd, pfds[1] is for pipefd[0]
int client_serial_num = 0;
string db_path = "/home/identity_element/Documents/113/CN/db.txt";
string cert_path = "/home/identity_element/Documents/113/CN/project/key/certificate.crt";
string key_path = "/home/identity_element/Documents/113/CN/project/key/private.key";
ThreadPool tp(N_WORKERS);
mutex m_user_session;// for pfds and user_sessions
SSL_CTX* ctx;

int init_server(int port){
	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_fd < 0){
		log_error("init_server", "Socket", "socket() failed");
		return -1;
	}
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);
	int opt = 1;
	// set server non blocking
	if(fcntl(server_fd, F_SETFL, O_NONBLOCK) < 0){
		log_error("init_server", "Socket", "fcntl() failed");
		return -1;
	}
	if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
		log_error("init_server", "Socket", "setsockopt() failed");
		return -1;
	}
	if(bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
		log_error("init_server", "Socket", "bind() failed");
		return -1;
	}
	if(listen(server_fd, 5) < 0){
		log_error("init_server", "Socket", "listen() failed");
		return -1;
	}

	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	user_sessions.reserve(3 * MAX_CLIENTS + 10);
	pfds.reserve(3 * MAX_CLIENTS + 10);

	// set cout to be unbuffered
	cout.setf(ios::unitbuf);
	create_session(server_fd);

	// create a pipe to wake up poll() in case of new connection
	int pipefd[2];
	if(pipe(pipefd) < 0){
		log_error("init_server", "Pipe", "pipe() failed");
		return -1;
	}
	struct pollfd pfd;
	pfd.fd = pipefd[0]; // read end
	pfd.events = POLLIN;
	pfds.push_back(pfd);
	user_session us;
	us.client_fd = pipefd[1];// write end
	us.user = "";
	user_sessions.push_back(us);

	
	return server_fd;
}

int init_ssl(){
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	ctx = SSL_CTX_new(TLS_server_method());
	if(!ctx){
		log_error("init_ssl", "SSL", "SSL_CTX_new() failed");
		return -1;
	}
	if(SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0){
		log_error("init_ssl", "SSL", "SSL_CTX_use_certificate_file() failed");
		return -1;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0){
		log_error("init_ssl", "SSL", "SSL_CTX_use_PrivateKey_file() failed");
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[]){
	if(argc != 5){
		log_error("main", "Argument", "Usage: " + string(argv[0]) + " <port> <db_path> <cert_path> <key_path>");
		return 1;
	}
	db_path = argv[2];
	cert_path = argv[3];
	key_path = argv[4];
	if(chdir(db_path.c_str()) < 0){
		log_error("main", "db", "chdir() failed");
		return 1;
	}

	int port = atoi(argv[1]);
	int server_fd = init_server(port);
	if (server_fd < 0) return 1;
	if (init_ssl() < 0) return 1;

	
	while(true){
		int ret = poll(pfds.data(), pfds.size(), -1);
		if(ret < 0){
			log_error("main", "Poll", "poll() failed");
			break;
		}
		if(pfds[0].revents & POLLIN){
			tp.add_task(new AcceptTask(pfds[0], user_sessions[0]));
		}
		if(pfds[1].revents & POLLIN){
			char buf[1024];
			read(pfds[1].fd, buf, 1024);
		}
		for(size_t i = 2; i < pfds.size(); i++){
			if(pfds[i].revents & POLLIN){
				tp.add_task(new ServerTask(pfds[i], user_sessions[i]));
			}
		}
	}
}
