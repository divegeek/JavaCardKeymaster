/*
 **
 ** Copyright 2021, The Android Open Source Project
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
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <memory>
#include <sys/socket.h>
#include <vector>
#include "socket.h"

#define PORT 8080
#define IPADDR "127.0.0.1"
#define MAX_RECV_BUFFER_SIZE 2500

using namespace std;

SocketTransport::~SocketTransport() {
    if (closeConnection())
        std::cout << "Socket is closed";
}

bool SocketTransport::openConnection() {
    struct sockaddr_in serv_addr;
    if ((mSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket ");
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, IPADDR, &serv_addr.sin_addr) <= 0) {
        std::cout << "Invalid address/ Address not supported.";
        return false;
    }

    if (connect(mSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(mSocket);
        perror("Socket ");
        return false;
    }
    socketStatus = true;
    return true;
}

bool SocketTransport::sendData(const std::vector<uint8_t>& inData, std::vector<uint8_t>& output) {
    uint8_t buffer[MAX_RECV_BUFFER_SIZE];
    int count = 1;
    while (!socketStatus && count++ < 5) {
        sleep(1);
        std::cout << "Trying to open socket connection... count: " << count;
        openConnection();
    }

    if (count >= 5) {
        std::cout << "Failed to open socket connection";
        return false;
    }
    // Prepend the input length to the inputData before sending.
    vector<uint8_t> inDataPrependedLength;
    inDataPrependedLength.push_back(static_cast<uint8_t>(inData.size() >> 8));
    inDataPrependedLength.push_back(static_cast<uint8_t>(inData.size() & 0xFF));
    inDataPrependedLength.insert(inDataPrependedLength.end(), inData.begin(), inData.end());

    if (0 > send(mSocket, inDataPrependedLength.data(), inDataPrependedLength.size(), 0)) {
        static int connectionResetCnt = 0; /* To avoid loop */
        if (ECONNRESET == errno && connectionResetCnt == 0) {
            // Connection reset. Try open socket and then sendData.
            socketStatus = false;
            connectionResetCnt++;
            return sendData(inData, output);
        }
        std::cout << "Failed to send data over socket err: " << errno;
        connectionResetCnt = 0;
        return false;
    }
    return readData(output);
}

bool SocketTransport::readData(vector<uint8_t>& output) {
    uint8_t buffer[MAX_RECV_BUFFER_SIZE];
    ssize_t expectedResponseLen = 0;
    ssize_t totalBytesRead = 0;
    // The first 2 bytes in the response contains the expected response length.
    do {
      size_t i = 0;
      ssize_t numBytes = read(mSocket, buffer, MAX_RECV_BUFFER_SIZE);
      if (0 > numBytes) {
        std::cout << "Failed to read data from socket.";
        return false;
      }
      totalBytesRead += numBytes;
      if (expectedResponseLen == 0) {
        // First two bytes in the response contains the expected response length.
        expectedResponseLen |=  static_cast<ssize_t>(buffer[1] & 0xFF);
        expectedResponseLen |=  static_cast<ssize_t>((buffer[0] << 8) & 0xFF00);
        // 2 bytes for storing the length.
        expectedResponseLen += 2;
        i = 2;
      }
      for (; i < numBytes; i++) {
        output.push_back(buffer[i]);
      }
    } while(totalBytesRead < expectedResponseLen);

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
