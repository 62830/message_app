# B11902021 張嘉崴

## Introduction

A command line real time chat room, supporting unsafe user authetication, messaging, file transfering and real time video streaming.

The server utilizes a fixed size worker pool and thread safe task queue to support hundreds of clients.

The client is single threaded with CLI.

## Clone & Build

Install the dependency on Ubuntu
```
apt install nlohmann-json3-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libssl-dev
```

```
git clone git@github.com:62830/message_app.git
mkdir build
make
```

## Run Server

First, generate a self-signed certificate for the server, store the private key and certificate in the key directory.

```
mkdir key
openssl genpkey -algorithm RSA -out key/private.key
openssl req -new -x509 -key key/private.key -out key/certificate.crt -days 365
```

Run the server
```
./build/server <port> <db_path> <cert_path> <priv_key_path>
```
`db_path` is the user database path.

## Run Client

```
./build/client <server_IP> <server_port> <download_path>
```

`download_path` is the path to store the files sent by other clients.

## Client Commands
```
help, reg, login, logout, msg, file, video
```