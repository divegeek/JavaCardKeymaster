/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <android-base/logging.h>
#include <vector>
#include "Transport.h"

/* TODO How to get these two values */
#define PORT    8080
#define IPADDR  "10.9.40.24"
#define MAX_RECV_BUFFER_SIZE 2048

namespace se_transport {

bool SocketTransport::openConnection(connectionCallback cb) {
	struct sockaddr_in serv_addr; 

	if ((mSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
        LOG(ERROR) << "Socket creation failed";
		return false; 
	} 

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(PORT); 
	
	// Convert IPv4 and IPv6 addresses from text to binary form 
	if(inet_pton(AF_INET, IPADDR, &serv_addr.sin_addr)<=0) 
	{ 
        LOG(ERROR) << "Invalid address/ Address not supported.";
        return false;
	}

	if (connect(mSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
	{ 
        LOG(ERROR) << "Connection failed.";
        return false;
	}
    cb(true);// This can be used for Asynchronous calls.
    return true;
}

bool SocketTransport::sendData(const char* data, uint32_t dataSize, responseCallback cb) {
    uint8_t buffer[MAX_RECV_BUFFER_SIZE];
	if (0 > send(mSocket, data ,dataSize , 0 )) {
        LOG(ERROR) << "Failed to send data over socket.";
        return false;
    }
	ssize_t valRead = read( mSocket , buffer, MAX_RECV_BUFFER_SIZE);
    if(0 > valRead) {
        LOG(ERROR) << "Failed to read data from socket.";
    }
    std::vector<uint8_t> output(buffer, buffer+valRead);
    cb(output);
    return true;
}

bool SocketTransport::sendData(const char* inData, const uint32_t inLen, std::vector<uint8_t>& output) {
    uint8_t buffer[MAX_RECV_BUFFER_SIZE];
	if (0 > send(mSocket, inData, inLen , 0 )) {
        LOG(ERROR) << "Failed to send data over socket.";
        return false;
    }
	ssize_t valRead = read( mSocket , buffer, MAX_RECV_BUFFER_SIZE);
    if(0 > valRead) {
        LOG(ERROR) << "Failed to read data from socket.";
    }
    for(size_t i = 0; i < valRead; i++) {
        output.push_back(buffer[i]);
    }
    return true;

}

bool SocketTransport::closeConnection() {
    close(mSocket);
    return true;
}

bool SocketTransport::isConnected() {
    //TODO
    return true;
}

}
