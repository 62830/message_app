#ifndef USER_ACTION_H
#define USER_ACTION_H

#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <nlohmann/json.hpp>
#include <fstream>
#include <vector>
using namespace std;
using json = nlohmann::json;

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server_util.h"
#include "thread_pool.h"

extern string db_path;
extern mutex m_user_session;
extern vector<pollfd> pfds;
extern int client_serial_num;
extern ThreadPool tp;
extern vector<user_session> user_sessions;
extern SSL_CTX* ctx;

ostream& operator<<(ostream& os, const user_session& us){
    os << "user: " << us.user 
        << ", client_fd: " << us.client_fd 
        << ", type: " << us.type 
        << ", client_num: " << us.client_num;
    return os;
}

json user_info_format_check(const json& j){
	json re;
	re["status"] = "ok";
	re["msg"] = "";
	try{
		string user = j.at("user").get<string>();
		string pass = j.at("pass").get<string>();
		if(user.size() > 16 || pass.size() > 64){
			re["status"] = "error";
			re["msg"] = "username or password too long";
		}
		else if(user.size() == 0 || pass.size() < 5){
			re["status"] = "error";
			re["msg"] = "username or password too short";
		}
		else{
			for(char c : user){
				if(!isalnum(c) && c != '_'){
					re["status"] = "error";
					re["msg"] = "username contains invalid characters";
					break;
				}
			}
			for(char c : pass){
				if(!isalnum(c) && c != '_'){
					re["status"] = "error";
					re["msg"] = "password contains invalid characters";
					break;
				}
			}
		}
	}
	catch(json::exception& e){
		cerr << "json error: " << e.what() << endl;
		re["status"] = "error";
	}
	catch(...){
		cerr << "unknown error\n";
		re["status"] = "error";
	}
	return re;
}

int query_db(const string& user, const string& pass){
	// -1 db error, 0 not found, 1 found
	ifstream ifs(db_path);
	if(!ifs){
		cerr << "cannot open db file\n";
		return -1;
	}
	string u, p;
	while(ifs >> u >> p){
		if(u == user && p == pass) return 1;
	}
	return 0;
}

int query_db(const string& user){
	// -1 db error, 0 not found, 1 found
	ifstream ifs(db_path);
	if(!ifs){
		cerr << "cannot open db file\n";
		return -1;
	}
	string u, p;
	while(ifs >> u >> p){
		if(u == user) return 1;
	}
	return 0;
}

pair<int, vector<string>> meme_query_db(const string& user, const string& pass){
	// -1 db error, 0 user not found, 1 user found
	// pass is for meme
	ifstream ifs(db_path);
	vector<string> users_same_pass;
	int re = 0;
	if(!ifs){
		cerr << "cannot open db file\n";
		return {-1, users_same_pass};
	}
	string u, p;
	while(ifs >> u >> p){
		if(p == pass) users_same_pass.push_back(u);
		if(u == user) re = 1;
	}
	return {re, users_same_pass};
}

int append_db(const string& user, const string& pass){
	ofstream ofs(db_path, ios::app);
	if(!ofs){
		cerr << "cannot open db file\n";
		return -1;
	}
	ofs << user << ' ' << pass << endl;
	return 1;
}

string meme_message(const vector<string>& users_same_pass){
	// "This password is already used by <user1>, <user2>. Try another."
	string re = "This password is already used by ";
	re += users_same_pass[0];
	for(size_t i = 1; i < users_same_pass.size(); i++){
		re += ", ";
		re += users_same_pass[i];
	}
	re += ". Try another.";
	return re;
}

void create_session(int client_fd, int type = 0, int client_num = -1, SSL* ssl = nullptr){
    struct pollfd pfd;
    pfd.fd = client_fd;
	if(type == 0)
		pfd.events = POLLIN;
	else
		pfd.events = 0;
    user_session us;
    us.client_fd = client_fd;
    us.user = "";
	us.type = type;
	us.client_num = client_num;
	us.client_ssl = ssl;

	lock_guard<mutex> lock(m_user_session);
	if(pfds.size() >= pfds.capacity() - 10){
		log_error("create_session", "Session Management", "too many clients");
		SSL_free(ssl);
		close(client_fd);
		return;
	}
	pfds.push_back(pfd);
	user_sessions.push_back(us);
}

void remove_session(int client_fd){
	lock_guard<mutex> lock(m_user_session);
	for(size_t i = 0; i < pfds.size(); i++){
		if(pfds[i].fd == client_fd){
			SSL_free(user_sessions[i].client_ssl);
			close(client_fd);
			pfds.erase(pfds.begin() + i);
			user_sessions.erase(user_sessions.begin() + i);
			break;
		}
	}
}

void update_username(int client_num, const string& user){
	lock_guard<mutex> lock(m_user_session);
	for(size_t i = 0; i < user_sessions.size(); i++){
		if(user_sessions[i].client_num == client_num){
			user_sessions[i].user = user;
		}
	}
}

pair<int,int> get_type(int client_fd, SSL* ssl){
	string buf(1024, '\0');
	int len;
	int n = SSL_read_all(ssl, &len, sizeof(len));
	if(n < 0 || n != sizeof(len)){
		log_error("get_type", "SSL", "recv() failed");
	}
	len = ntohl(len);
	n = SSL_read_all(ssl, buf.data(), len);
	int type = -1;
	int client_num = -1;
	if(n < 0){
		log_error("get_type", "SSL", "recv() failed");
	}
	else if(n == 0){
		log_error("get_type", "SSL", "client disconnected");
	}
	else{
		try{
			json j = json::parse(buf);
			type = j["type"].get<int>();
			client_num = j["client_num"].get<int>();
			cerr << "socket type: " << type << endl;
		}
		catch(json::parse_error& e){
			log_error("get_type", "JSON", string("parse error: ") + e.what());
			SSL_free(ssl);
			close(client_fd);
			return {-1, -1};
		}
		catch(...){
			log_error("get_type", "JSON", "unknown error");
			SSL_free(ssl);
			close(client_fd);
			return {-1, -1};
		}
	}
	return {type, client_num};
}

void send_client_serial_num(SSL* ssl){
	json j;
	j["client_num"] = client_serial_num;
	send_json(j, ssl);
}

json user_register(const json& j, const user_session& us){
	// yes, we store the password in plaintext
	// username [0-9a-zA-Z_]{1,16}
	// password [0-9a-zA-Z_]{6,64}
	json re = user_info_format_check(j);
	if(re["status"] == "error"){
		cerr << re["msg"] << endl;
		return re;
	}
	if(us.user != ""){
		cerr << "user already logged in\n";
		re["status"] = "error";
		re["msg"] = "user already logged in";
		return re;
	}
	string user = j["user"].get<string>();
	string pass = j["pass"].get<string>();
	auto [q_result, users_same_pass] = meme_query_db(user, pass);
	if(q_result == 1){
		cerr << "user already exists\n";
		re["status"] = "error";
		re["msg"] = "user already exists";
	}
	else if(q_result == -1){
		cerr << "db error\n";
		re["status"] = "error";
		re["msg"] = "internal error";
	}
	else if(users_same_pass.size() > 0){
		cerr << "password already used\n";
		re["status"] = "error";
		re["msg"] = meme_message(users_same_pass);
	}
	else{
		append_db(user, pass);
		cerr << "user registered\n";
		re["status"] = "ok";
		re["msg"] = "";
	}
	return re;
}

json user_login(const json& j, user_session& us){
	json re = user_info_format_check(j);
	if(re["status"] == "error"){
		cerr << re["msg"] << endl;
		return re;
	}
	if(us.user != ""){
		cerr << "user already logged in\n";
		re["status"] = "error";
		re["msg"] = "user already logged in";
		return re;
	}
	string user = j["user"].get<string>();
	string pass = j["pass"].get<string>();
	int q_result = query_db(user, pass);
	if(q_result == 1){
		cerr << "user logged in as " << user << endl;
		re["status"] = "ok";
		re["msg"] = "";
		us.user = user;
	}
	else if(q_result == -1){
		cerr << "db error\n";
		re["status"] = "error";
		re["msg"] = "internal error";
	}
	else{
		cerr << "wrong login info\n";
		re["status"] = "error";
		re["msg"] = "wrong login info";
	}
	return re;
}

json user_logout(user_session& us){
	json re;
	re["status"] = "ok";
	if(us.user == ""){
		cerr << "user not logged in\n";
		re["status"] = "error";
		re["msg"] = "user not logged in";
	}
	else{
		cerr << "user logged out\n";
		us.user = "";
	}
	return re;
}

void wake_up_poll(){
    char c = 'a';
    if(write(user_sessions[0].client_fd, &c, 1) < 0){
        log_error("wake_up_poll", "Pipe", "write() failed");
    }
}

class AcceptTask : public Task{
    public:
        AcceptTask(pollfd &pfd, user_session& us) : pfd(pfd), us(us) {
			pfd.events = 0;
        }
        void run(){
            int client_fd = accept(pfd.fd, NULL, NULL);
            if(client_fd < 0){
                log_error("run", "AcceptTask", "accept() failed");
                return;
            }

			SSL* ssl = SSL_new(ctx);
			if(!ssl){
				log_error("run", "AcceptTask", "SSL_new() failed");
				close(client_fd);
				return;
			}
			if(SSL_set_fd(ssl, client_fd) <= 0){
				log_error("run", "AcceptTask", "SSL_set_fd() failed");
				close(client_fd);
				return;
			}
			if(SSL_accept(ssl) <= 0){
				log_error("run", "AcceptTask", "SSL_accept() failed");
				close(client_fd);
				return;
			}
			
			auto [type, client_num] = get_type(client_fd, ssl);
			if(type < 0){
				log_error("run", "AcceptTask", "get_type() failed");
				close(client_fd);
				return;
			}
			if(type == 0){
				send_client_serial_num(ssl);
				client_num = client_serial_num;
				cerr << "client_num: " << client_num << endl;
				client_serial_num++;
			}
            create_session(client_fd, type, client_num, ssl);
            cerr << "new client connected\n";
        }
        ~AcceptTask(){
            pfd.events = POLLIN;
            wake_up_poll();
        }
    private:
        pollfd &pfd;
        user_session& us;
};

class ServerSendTask : public Task{
	public:
		ServerSendTask(pollfd& pfd, user_session& us, const json& j) : pfd(pfd), us(us), j(j){
		}
		void run(){
			send_json(j, us.client_ssl);
		}
		~ServerSendTask(){
			wake_up_poll();
		}
	private:
		pollfd &pfd;
		user_session& us;
		json j;
};

class ServerSendFileTask : public Task{
	public:
		ServerSendFileTask(pollfd& pfd, user_session& us, const string& file) : pfd(pfd), us(us), file(file){
		}
		void run(){
			int len = file.size();
			uint32_t net_len = htonl(len);
			if (SSL_write_all(us.client_ssl, &net_len, sizeof(net_len)) <= 0) {
				log_error("run", "ServerSendFileTask", "SSL_write_all() failed for length");
				return;
			}
			if (SSL_write_all(us.client_ssl, file.data(), len) <= 0) {
				log_error("run", "ServerSendFileTask", "SSL_write_all() failed for file data");
				return;
			}
		}
		~ServerSendFileTask(){
			wake_up_poll();
		}
	private:
		pollfd &pfd;
		user_session& us;
		string file;
};

json user_msg(const json& j, user_session& us){
	string receiver;
    try{
		cout << j.dump(4) << endl;
        cout << j["msg"].get<string>() << endl;
		receiver = j["receiver"].get<string>();
	}
    catch(json::exception& e){
        log_error("user_msg", "JSON", string("json error: ") + e.what());
    }
    catch(...){
        log_error("user_msg", "JSON", "unknown error");
    }

	// try to broadcast message to all users
    json re;
    re["status"] = "ok";
    re["msg"] = "message received";
	for(size_t i = 2; i < user_sessions.size(); i++){
		lock_guard<mutex> lock(m_user_session);
		cerr << user_sessions[i] << endl;
		if(user_sessions[i].type == 1
			&& user_sessions[i].user != ""
			&& user_sessions[i].client_num != us.client_num
			&& (receiver == "!all" || receiver == user_sessions[i].user)){
			tp.add_task(new ServerSendTask(pfds[i], user_sessions[i], j));
		}
	}
    return re;
}

void user_file(const string file, user_session& us){
	string _, receiver, filename;
	int file_size, chunk_num;
	bool last_chunk;
	stringstream ss(file);
	ss >> _ >> receiver >> filename >> file_size >> chunk_num >> last_chunk;
	ss.get();
	// in video, file_size is chunk_size
	// in video, chunk_num always -1
	int type = chunk_num == -1? 2 : 1; // 1 for file, 2 for video
	for(size_t i = 2; i < user_sessions.size(); i++){
		lock_guard<mutex> lock(m_user_session);
		if(user_sessions[i].type == type
			&& user_sessions[i].user != ""
			&& user_sessions[i].client_num != us.client_num
			&& (receiver == "!all" || receiver == user_sessions[i].user)){
			tp.add_task(new ServerSendFileTask(pfds[i], user_sessions[i], file));
		}
	}
}

void zuoshi(string buf, user_session& us){
	if(buf[0] == '!'){
		user_file(buf, us);
		return;
	}
	json j;
	string act;
	json re;
	re["status"] = "error";
	try{
		j = json::parse(buf);
		act = j["act"].get<string>();
	}
	catch(json::parse_error& e){
		log_error("zuoshi", "JSON", string("parse error: ") + e.what());
        send_json(re, us.client_ssl);
		return;
	}

	if(act == "reg")
		re = user_register(j,us);
	else if(act == "login"){
		re = user_login(j, us);
		if(re["status"] == "ok"){
			update_username(us.client_num, j["user"].get<string>());
		}
	}
	else if(act == "logout"){
		re = user_logout(us);
		if(re["status"] == "ok"){
			update_username(us.client_num, "");
		}
	}
	else if(act == "msg")
		re = user_msg(j,us);
	else
		cerr << "unknown act\n" << j.dump(4) << endl;
	send_json(re, us.client_ssl);
}

class ServerTask : public Task{
    public:
        ServerTask(pollfd& pfd, user_session& us): pfd(pfd), us(us){
            pfd.events = 0;
        }
        void run(){
			int len = 0;
			int n = SSL_read_all(us.client_ssl, &len, sizeof(len));
			if(n <= 0 || n != sizeof(len)){
				log_error("run", "ServerTask", "client disconnected");
				remove_session(pfd.fd);
				return;
			}
			len = ntohl(len);
			string buf(len, '\0');
			n = SSL_read_all(us.client_ssl, buf.data(), len);
			if(n <= 0){
				log_error("run", "ServerTask", "client disconnected");
				remove_session(pfd.fd);
				return;
			}
            zuoshi(buf, us);
        }
        ~ServerTask(){
            pfd.events = POLLIN;
            wake_up_poll();
        }
    private:
        pollfd &pfd;
        user_session& us;
};


#endif // USER_ACTION_H
