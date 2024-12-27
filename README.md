# B11902021 張嘉崴

## Introduction

A command line real time chat room, supporting unsafe user authetication, messaging, file transfering and real time video streaming.

The server utilizes a fixed size worker pool and thread safe task queue to support hundreds of clients.

The client is single threaded with CLI.



## Clone & Build

```
clone
mkdir build
```

## Run Server
```
./server <port> <db_path> <cert_path> <priv_key_path>
```

## Run Client

```
./client <server_IP> <server_port> <download_path>
```

## Client Commands
```
help, reg, login, logout, msg, file, video
```