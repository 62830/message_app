#ifndef SERVER_UTIL_H
#define SERVER_UTIL_H

#include <iostream>
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <string>
#include <arpa/inet.h>
using namespace std;
using json = nlohmann::json;

struct user_session{
	string user;
	int client_num;
	int client_fd;
	int type; // type 0 for c2s, 1 for s2c
	SSL* client_ssl;
	user_session() : user(""), client_num(-1), client_fd(-1), type(0), client_ssl(nullptr){ }
};
void log_error(const string& function, const string& component, const string& message) {
	cerr << "[" << function << "] " << component << " failed: " << message << endl;
}

int SSL_read_all(SSL* ssl, void* buf, int num) {
	int total = 0;
	while (total < num) {
		int n = SSL_read(ssl, (char*)buf + total, num - total);
		if (n > 0) {
			total += n;
		} else {
			int err = SSL_get_error(ssl, n);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return n;
			log_error("SSL_read_all", "SSL", "SSL_read() failed");
			return n;
		}
	}
	return total;
}

int SSL_write_all(SSL* ssl, const void* buf, int num) {
	int total = 0;
	int max_retry = 10;
	int exp = 1;
	while (total < num) {
		int n = SSL_write(ssl, (const char*)buf + total, num - total);
		if (n <= 0) {
			if (max_retry-- == 0) {
				log_error("SSL_write_all", "SSL", "max retry reached");
				return n;
			}
			log_error("SSL_write_all", "SSL", "SSL_write() failed, retrying");
			int mul = rand() % 10;
			usleep(exp*mul*10000);
			exp <<= 1;
			continue;
		}
		total += n;
	}
	return total;
}

void send_json(const json& j, SSL* ssl){
	string s = j.dump();
	s += '\n';
	int l = s.size();
	uint32_t net_len = htonl(l);
	int n = SSL_write_all(ssl, &net_len, sizeof(net_len));
	if(n < 0 || n != sizeof(net_len)){
		log_error("send_json", "SSL", "SSL_write_all() failed for length");
	}
	n = SSL_write_all(ssl, s.c_str(), s.size());
	if(n < 0 || n != s.size()){
		log_error("send_json", "SSL", "SSL_write_all() failed for data");
	}
}

#endif // SERVER_UTIL_H