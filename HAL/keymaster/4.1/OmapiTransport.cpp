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
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <vector>
#include "Transport.h"

#define PORT    8080
#define IPADDR  "10.9.40.24"
#define UNUSED_V(a) a=a

namespace se_transport {

bool OmapiTransport::openConnection() {
    return true;
}

bool OmapiTransport::sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) {
    std::vector<uint8_t> test(inData, inData+inLen);
    output = std::move(test);
    return true;
}

bool OmapiTransport::closeConnection() {
    return true;
}

bool OmapiTransport::isConnected() {
    return true;
}

}
