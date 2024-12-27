#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <fstream>
using namespace std;
using json = nlohmann::json;

void log_error(const string& function, const string& component, const string& message) {
	cerr << "[" << function << "] " << component << " failed: " << message << endl;
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
			int mul = rand()%10;
			usleep(exp*mul*10000);
			exp <<= 1;
			continue;
		}
		total += n;
	}
	return total;
}

void send_msg(string s, SSL* ssl){
	int len = s.size();
	uint32_t net_len = htonl(len);
	int n = SSL_write_all(ssl, &net_len, sizeof(net_len));
	if(n < 0 || n != sizeof(net_len)){
		log_error("send_msg", "SSL", "SSL_write_all() failed for length");
	}
	n = SSL_write_all(ssl, s.c_str(), s.size());
	if(n < 0 || n != s.size()){
		log_error("send_msg", "SSL", "SSL_write_all() failed for data");
	}
}

void send_json(const json& j, SSL* ssl){
	send_msg(j.dump(), ssl);
} 

// blocking
int SSL_read_all(SSL* ssl, void* buf, int num) {
	int total = 0;
	while (total < num) {
		int n = SSL_read(ssl, (char*)buf + total, num - total);
		if (n > 0) {
			total += n;
		} else {
			int err = SSL_get_error(ssl, n);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
			log_error("SSL_read_all", "SSL", "SSL_read() failed");
			return n;
		}
	}
	return total;
}

//blocking if get the length
string read_msg(SSL* ssl){
	int len;
	int n = SSL_read(ssl, &len, sizeof(len));
	if(n <= 0){
		return "";
	}
	len = ntohl(len);
	string buf(len, '\0');
	n = SSL_read_all(ssl, buf.data(), len);
	if(n < 0){
		log_error("read_msg", "SSL", "SSL_read_all() failed for data");
		return "";
	}
	return buf;
}

//blocking 
string read_msg_blocking(SSL* ssl){
	int len;
	int n = SSL_read_all(ssl, &len, sizeof(len));
	if(n < 0){
		log_error("read_msg", "SSL", "SSL_read_all() failed for length");
		return "";
	}
	len = ntohl(len);
	string buf(len, '\0');
	n = SSL_read_all(ssl, buf.data(), len);
	if(n < 0){
		log_error("read_msg", "SSL", "SSL_read_all() failed for data");
		return "";
	}
	return buf;
}

json parse_json(const string& s){
	json j;
	try{
		j = json::parse(s);
	}
	catch(json::parse_error& e){
		log_error("parse_json", "JSON", string("parse error: ") + e.what());
	}
	catch(...){
		log_error("parse_json", "JSON", "unknown error");
	}
	return j;
}

json read_json(SSL* ssl){
	return parse_json(read_msg(ssl));
}

json read_json_blocking(SSL* ssl){
	return parse_json(read_msg_blocking(ssl));
}

#endif // UTIL_H