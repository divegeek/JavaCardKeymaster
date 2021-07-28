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
#include "SocketTransport.h"
#include "ITransport.h"
#include <android-base/logging.h>
#include <arpa/inet.h>
#include <errno.h>
#include <memory>
#include <sys/socket.h>
#include <vector>

#define PORT 8080
#define IPADDR  "192.168.7.239"
#define MAX_RECV_BUFFER_SIZE 2500

namespace keymint::javacard {
using std::shared_ptr;
using std::vector;

bool SocketTransport::openConnection() {
    struct sockaddr_in serv_addr;
    if ((mSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOG(ERROR) << "Socket creation failed"
                   << " Error: " << strerror(errno);
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, IPADDR, &serv_addr.sin_addr) <= 0) {
        LOG(ERROR) << "Invalid address/ Address not supported.";
        return false;
    }

    if (connect(mSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(mSocket);
        LOG(ERROR) << "Connection failed. Error: " << strerror(errno);
        return false;
    }
    socketStatus = true;
    return true;
}

bool SocketTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) {
    uint8_t buffer[MAX_RECV_BUFFER_SIZE];
    int count = 1;
    while (!socketStatus && count++ < 5) {
        sleep(1);
        LOG(ERROR) << "Trying to open socket connection... count: " << count;
        openConnection();
    }

    if (count >= 5) {
        LOG(ERROR) << "Failed to open socket connection";
        return false;
    }

    if (0 > send(mSocket, inData.data(), inData.size(), 0)) {
        static int connectionResetCnt = 0; /* To avoid loop */
        if (ECONNRESET == errno && connectionResetCnt == 0) {
            // Connection reset. Try open socket and then sendData.
            socketStatus = false;
            connectionResetCnt++;
            return sendData(inData, output);
        }
        LOG(ERROR) << "Failed to send data over socket err: " << errno;
        connectionResetCnt = 0;
        return false;
    }

    ssize_t valRead = read(mSocket, buffer, MAX_RECV_BUFFER_SIZE);
    if (0 > valRead) {
        LOG(ERROR) << "Failed to read data from socket.";
    }
    for (size_t i = 0; i < valRead; i++) {
        output.push_back(buffer[i]);
    }
    return true;
}

bool SocketTransport::closeConnection() {
    close(mSocket);
    socketStatus = false;
    return true;
}

bool SocketTransport::isConnected() {
    return socketStatus;
}

}  // namespace keymint::javacard
