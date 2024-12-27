// run with ./client <server_ip> <server_port> 
// send messages from stdin to server
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

#include "client_util.h"
#include "video.h"
using namespace std;
using json = nlohmann::json;

struct user_session{
    string user;
    int client_num;
    int client_fd;
    int server_fd;
    int video_fd;
    SSL* client_ssl;
    SSL* server_ssl;
    SSL* video_ssl;
    user_session() : user(""), client_num(-1), client_fd(-1), server_fd(-1), video_fd(-1), client_ssl(nullptr), server_ssl(nullptr), video_ssl(nullptr){ }
};
user_session us;
struct pollfd pfds[4];
static SSL_CTX* ctx;
#define FILE_CHUNK_SIZE 1024
static string download_path = "/home/identity_element/Documents/113/CN/";
static FILE* video_pipe = nullptr;

void help_message(){
    cout << "Commands: help, exit, reg, login, logout, msg, file, video\n";
}

void set_type(SSL* ssl, int type, int client_num){
    // send type to server, 0 for c2s, 1 for s2c, json
    json j;
    j["act"] = "set_type";
    j["type"] = type;
    j["client_num"] = client_num;
    send_json(j, ssl);
}

int get_client_num(SSL* ssl){
    int re = -1;
    json j = read_json_blocking(ssl);
    try{
        re = j["client_num"].get<int>();
    }
    catch(json::exception& e){
        log_error("get_client_num", "JSON", e.what());
    }
    catch(...){
        log_error("get_client_num", "JSON", "unknown error");
    }
    return re;
}

bool user_info_format_check(string user, string pass){
    if(user.size() == 0 || user.size() > 16){
        cout << "username has to be 1-16 characters\n";
        return false;
    }
    if(pass.size() < 5 || pass.size() > 64){
        cout << "password has to be 5-64 characters\n";
        return false;
    }
    for(char c : user){
        if(!isalnum(c) && c != '_'){
            cout << "username should only contain letters, numbers, and underscores\n";
            return false;
        }
    }
    for(char c : pass){
        if(!isalnum(c) && c != '_'){
            cout << "password should only contain letters, numbers, and underscores\n";
            return false;
        }
    }
    return true;
}

bool logged_in(){
    return us.user != "";
}

void user_register(){
    if(logged_in()){
        cout << "You are already logged in as " << us.user << endl;
        return;
    }
    string user, pass;
    cout << "Enter username: ";
    cin >> user;
    cout << "Enter password: ";
    cin >> pass;

    if(!user_info_format_check(user, pass)) return;
    json j;
    j["act"] = "reg";
    j["user"] = user;
    j["pass"] = pass;
    send_json(j, us.client_ssl);

    j = read_json_blocking(us.client_ssl);
    if(j.empty()){
        cout << "failed to register\n";
    }
    else if(j["status"] == "ok"){
        cout << "registered as " << user << endl;
        cout << "You can now login\n";
    }
    else{
        cout << j["msg"] << endl;
    } 
}

void user_login(){
    if(logged_in()){
        cout << "You are already logged in as " << us.user << endl;
        return;
    }
    string user, pass;
    cout << "Enter username: ";
    cin >> user;
    cout << "Enter password: ";
    cin >> pass;

    if(!user_info_format_check(user, pass)) return;
    json j;
    j["act"] = "login";
    j["user"] = user;
    j["pass"] = pass;
    send_json(j, us.client_ssl);
    cout << "sent login request\n";

    j = read_json_blocking(us.client_ssl);
    if(j.empty()){
        cout << "failed to login\n";
    }
    else if(j["status"] == "ok"){
        cout << "logged in as " << user << endl;
        us.user = user;
    }
    else{
        cout << j["msg"] << endl;
    }
    
}

void user_logout(){
    if(!logged_in()){
        cout << "You are not logged in\n";
        return;
    }
    json j;
    j["act"] = "logout";
    send_json(j, us.client_ssl);

    j = read_json_blocking(us.client_ssl);
    if(j.empty()){
        cout << "failed to logout\n";
    }
    else if(j["status"] == "ok"){
        cout << "logged out\n";
        us.user = "";
    }
    else{
        cout << j["msg"] << endl;
    }
}

void user_send_msg(){
    if(!logged_in()){
        cout << "You are not logged in\n";
        return;
    }
    string msg, receiver;
    cout << "To (type !all for all users): ";
    cin >> receiver;
    cout << "Enter message: ";
    cin.ignore();
    getline(cin, msg);
    json j;
    j["act"] = "msg";
    j["sender"] = us.user;
    j["receiver"] = receiver;
    j["msg"] = msg;
    send_json(j, us.client_ssl);
    j = read_json_blocking(us.client_ssl);
    if(j.empty()){
        cout << "failed to send message\n";
    }
    else if(j["status"] == "ok"){
        cout << "message sent\n";
    }
    else{
        cout << j["msg"] << endl;
    }
}

void send_file(){
    if(!logged_in()){
        cout << "You are not logged in\n";
        return;
    }
    string receiver, file_path;
    cout << "To (type !all for all users): ";
    cin >> receiver;
    cout << "Enter file path: ";
    cin >> file_path;
    string filename = file_path.substr(file_path.find_last_of('/') + 1);
    fstream ifs(file_path, ios::in | ios::binary);
    if(!ifs){
        cout << "cannot open file\n";
        return;
    }
    ifs.seekg(0, ios::end);
    int file_size = ifs.tellg();
    ifs.seekg(0, ios::beg);
    // <receiver> <file_name> <file_size> <chunk_num> <last_chunk? 0/1> <file_data>
    char file_data[FILE_CHUNK_SIZE];
    bool last_chunk = false;
    for(int chunk_num = 0; chunk_num * FILE_CHUNK_SIZE < file_size; chunk_num++){
        int n = ifs.read(file_data, FILE_CHUNK_SIZE).gcount();
        if(n == 0){
            log_error("send_file", "file", "read() failed");
            return;
        }
        last_chunk = (chunk_num + 1) * FILE_CHUNK_SIZE >= file_size;
        string payload = "! " + receiver + " " + filename + " " + to_string(file_size) + " " + to_string(chunk_num) + " " + to_string(last_chunk) + " ";
        payload.append(file_data, n);
        send_msg(payload, us.client_ssl);

    }
}

void send_video(){
    if(!logged_in()){
        cout << "You are not logged in\n";
        return;
    }
    string receiver, file_path;
    cout << "To (type !all for all users): ";
    cin >> receiver;
    cout << "Enter file path: ";
    cin >> file_path;
    send_video_backend(file_path, us.client_ssl, receiver);
}

FILE* run_ffplay_command(){
    // ffplay input from pipe
    FILE* pipe = popen("ffplay -f h264 -i -", "w");
    if(!pipe){
        log_error("run_ffplay_command", "ffplay", "popen() failed");
        return nullptr;
    }
    return pipe;
}

void recv_video(const string& s){
    // <receiver> <file_name> <chunk_size> <chunk_num> <last_chunk? 0/1> <video_data>
	string _, receiver, filename;
	int chunk_size, chunk_num;
	bool last_chunk;
	//use string stream to parse the string
	stringstream ss(s);
	ss >> _ >> receiver >> filename >> chunk_size >> chunk_num >> last_chunk;
    if(last_chunk){
        if(video_pipe != nullptr){
            pclose(video_pipe);
            video_pipe = nullptr;
        }
        return;
    }

    if(video_pipe == nullptr){
        video_pipe = run_ffplay_command();
    }
    // write video data to pipe (last chunk_num bytes)
    //fwrite(, 1, chunk_size, video_pipe);
    int idx = s.size() - chunk_size;
    if(fwrite(s.data() + idx, 1, chunk_size, video_pipe) != chunk_size){
        log_error("recv_video", "video", "fwrite() failed");
    }
}

void recv_file(const string &s){
	string _, receiver, filename;
	int file_size, chunk_num;
	bool last_chunk;
	char file_data[FILE_CHUNK_SIZE+3];
	//use string stream to parse the string
	stringstream ss(s);
	ss >> _ >> receiver >> filename >> file_size >> chunk_num >> last_chunk;
    char c;
	ss.read(&c, 1);
    int sz = last_chunk? file_size - chunk_num * FILE_CHUNK_SIZE : FILE_CHUNK_SIZE;
	ss.read(file_data, sz);

    fstream ofs;
    if(chunk_num == 0)
        ofs.open(download_path + filename, ios::out | ios::binary);
    else
        ofs.open(download_path + filename, ios::app | ios::binary);
    if(!ofs){
        log_error("recv_file", "file", "cannot open file");
        return;
    }
    ofs.seekp(chunk_num * FILE_CHUNK_SIZE);
    if(ofs.write(file_data, sz).fail()){
        log_error("recv_file", "file", "write() failed");
    }
    ofs.close();
}

pair<int,int> create_socket(char *ip, int port, int type, SSL* &ssl){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int client_num = us.client_num;
    if(fd < 0){
        std::cerr << "socket() failed\n";
        return {-1, -1};
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);
    if(connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        std::cerr << "connect() failed\n";
        return {-1, -1};
    }

    
    ssl = SSL_new(ctx);
    if(!ssl){
        cerr << "SSL_new() failed\n";
        return {-1, -1};
    }
    if(SSL_set_fd(ssl, fd) <= 0){
        cerr << "SSL_set_fd() failed\n";
        return {-1, -1};
    }
    if(SSL_connect(ssl) <= 0){
        cerr << "SSL_connect() failed\n";
        return {-1, -1};
    }

    if(type == 0){
        set_type(ssl, type, -1);
        cerr << "finish type 0 set type\n";
        client_num = get_client_num(ssl);
        cerr << "finish type 0 setup\n";
    }
    else{
        set_type(ssl, type, client_num);
        cerr << "finish type 1 set type\n";
        cerr << "finish type 1 setup\n";
    }

    // set nonblocking
    int flags = fcntl(fd, F_GETFL, 0);
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0){
        cerr << "fcntl() failed\n";
        return {-1, -1};
    }
    return {fd, client_num};
}

int init(int argc, char *argv[]){
    if(argc != 4){
        cerr << "Usage: " << argv[0] << " <server_ip> <server_port> <download_path>\n";
        return 1;
    }
    if(chdir(argv[3]) < 0){
        cerr << "chdir() failed\n";
        return 1;
    }
    download_path = argv[3];

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(TLS_client_method());

    if(!ctx){
        cerr << "SSL_CTX_new() failed\n";
        return 1;
    }

    auto [client_fd, client_num] = create_socket(argv[1], atoi(argv[2]), 0, us.client_ssl);
    if(client_fd < 0) return 1;
    us.client_fd = client_fd;
    us.client_num = client_num;

    auto [server_fd, _] = create_socket(argv[1], atoi(argv[2]), 1, us.server_ssl);
    if(server_fd < 0) return 1;
    us.server_fd = server_fd;

    auto [video_fd, __] = create_socket(argv[1], atoi(argv[2]), 2, us.video_ssl);
    if(video_fd < 0) return 1;
    us.video_fd = video_fd;

    pfds[0].fd = us.client_fd;
    pfds[1].fd = 0;
    pfds[2].fd = us.server_fd;
    pfds[3].fd = us.video_fd;
    for(int i = 0; i < 4; i++){
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
    }

    // set cout to be unbuffered
    cout.setf(ios::unitbuf);
    return 0;
}

int main(int argc, char *argv[]){
    if(init(argc, argv) != 0) return 1;

    string act;// reg, login, logout, exit, help, file, msg
    cout << "Type command > ";

    while(1){
        int ret = poll(pfds, 4, -1);
        if(ret < 0){
            cerr << "poll() failed\n";
            break;
        }
        if(pfds[0].revents & POLLIN){
            cout << "received from server in the wrong channel\n";
            string s = read_msg(us.client_ssl);
            log_error("main", "poll 0", s);
        }
        if(pfds[1].revents & POLLIN){
            cin >> act;
            if(act == "exit") break;
            else if(act == "help")
                help_message();
            else if(act == "reg")
                user_register();
            else if(act == "login")
                user_login();
            else if(act == "logout")
                user_logout();
            else if(act == "msg")
                user_send_msg();
            else if(act == "file")
                send_file();
            else if(act == "video")
                send_video();
            else
                std::cerr << "unknown command\n";
            cout << "Type command > ";
        }
        if(pfds[2].revents & POLLIN){
            string s = read_msg(us.server_ssl);
            if(s[0] == '!'){
                cout << "receiving file\n";
                recv_file(s);
            }
            else if(s.size()){
				json j = parse_json(s);
				if(!j.empty()){
					cout << j.dump(4) << endl;
				}
            }
        }
        if(pfds[3].revents & POLLIN){
            string s = read_msg(us.video_ssl);
            if(s[0] == '!'){
                cout << "receiving video\n";
                recv_video(s);
            }
            else if(s.size()){
				json j = parse_json(s);
				if(!j.empty()){
					cout << j.dump(4) << endl;
				}
            }
        }
    }
}
