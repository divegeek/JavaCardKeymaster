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

#include <memory>
#include <vector>

#include <hardware/keymaster_defs.h>

namespace keymint::javacard {
using std::shared_ptr;
using std::vector;
constexpr int KM_ERROR_HARDWARE_TYPE_UNAVAILABLE = -68;
constexpr int KM_ERROR_HARDWARE_NOT_YET_AVAILABLE = -85;
/**
 * ITransport is an interface with a set of virtual methods that allow communication between the
 * HAL and the applet on the secure element.
 */
class ITransport {
  public:
    virtual ~ITransport() {}

    /**
     * Opens connection.
     */
    virtual keymaster_error_t openConnection() = 0;
    /**
     * Send data over communication channel and receives data back from the remote end.
     */
    virtual keymaster_error_t sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) = 0;
    /**
     * Closes the connection.
     */
    virtual keymaster_error_t closeConnection() = 0;
    /**
     * Returns the state of the connection status. Returns true if the connection is active, false
     * if connection is broken.
     */
    virtual bool isConnected() = 0;
};
}  // namespace keymint::javacard
