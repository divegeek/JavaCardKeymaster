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
#pragma once
#include "ITransport.h"
#include <memory>
#include <vector>

namespace keymint::javacard {
using std::shared_ptr;
using std::vector;

class SocketTransport : public ITransport {

  public:
    SocketTransport() : mSocket(-1), socketStatus(false) {}
    /**
     * Creates a socket instance and connects to the provided server IP and port.
     */
    bool openConnection() override;
    /**
     * Sends data over socket and receives data back.
     */
    bool sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) override;
    /**
     * Closes the connection.
     */
    bool closeConnection() override;
    /**
     * Returns the state of the connection status. Returns true if the connection is active,
     * false if connection is broken.
     */
    bool isConnected() override;

  private:
    /**
     * Socket instance.
     */
    int mSocket;
    bool socketStatus;
};
}  // namespace keymint::javacard
