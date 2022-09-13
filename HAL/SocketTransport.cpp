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

#include <arpa/inet.h>
#include <errno.h>

#include <memory>
#include <vector>

#include <android-base/logging.h>
#include <sys/socket.h>

#include "ITransport.h"

#define PORT 8080
#define IPADDR  "192.168.7.239"
#define MAX_RECV_BUFFER_SIZE 2500

namespace keymint::javacard {
using std::shared_ptr;
using std::vector;

keymaster_error_t SocketTransport::openConnection() {
    struct sockaddr_in serv_addr;
    if ((mSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOG(ERROR) << "Socket creation failed"
                   << " Error: " << strerror(errno);
        return static_cast<keymaster_error_t>(KM_ERROR_HARDWARE_TYPE_UNAVAILABLE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, IPADDR, &serv_addr.sin_addr) <= 0) {
        LOG(ERROR) << "Invalid address/ Address not supported.";
        return static_cast<keymaster_error_t>(KM_ERROR_HARDWARE_TYPE_UNAVAILABLE);
    }

    if (connect(mSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(mSocket);
        LOG(ERROR) << "Connection failed. Error: " << strerror(errno);
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    socketStatus = true;
    return KM_ERROR_OK;
}

keymaster_error_t SocketTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) {
    int count = 1;
    while (!socketStatus && count++ < 5) {
        sleep(1);
        LOG(ERROR) << "Trying to open socket connection... count: " << count;
        openConnection();
    }

    if (count >= 5) {
        LOG(ERROR) << "Failed to open socket connection";
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    // Prepend the input length to the inputData before sending.
    vector<uint8_t> inDataPrependedLength;
    inDataPrependedLength.push_back(static_cast<uint8_t>(inData.size() >> 8));
    inDataPrependedLength.push_back(static_cast<uint8_t>(inData.size() & 0xFF));
    inDataPrependedLength.insert(inDataPrependedLength.end(), inData.begin(), inData.end());

    if (0 > send(mSocket, inDataPrependedLength.data(), inDataPrependedLength.size(), MSG_NOSIGNAL)) {
        static int connectionResetCnt = 0; /* To avoid loop */
        if ((ECONNRESET == errno || EPIPE == errno) && connectionResetCnt == 0) {
            // Connection reset. Try open socket and then sendData.
            socketStatus = false;
            connectionResetCnt++;
            return sendData(inData, output);
        }
        LOG(ERROR) << "Failed to send data over socket err: " << errno;
        connectionResetCnt = 0;
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    
    if (!readData(output)) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    return KM_ERROR_OK;
}

keymaster_error_t SocketTransport::closeConnection() {
    close(mSocket);
    socketStatus = false;
    return KM_ERROR_OK;
}

bool SocketTransport::isConnected() {
    return socketStatus;
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
        LOG(ERROR) << "Failed to read data from socket.";
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

}  // namespace keymint::javacard
