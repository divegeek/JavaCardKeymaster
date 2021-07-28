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
#ifndef __SE_TRANSPORT_FACTORY__
#define __SE_TRANSPORT_FACTORY__

#include "Transport.h"

namespace se_transport {

/**
 * TransportFactory class decides which transport mechanism to be used to send data to secure element. In case of
 * emulator the communication channel is socket and in case of device the communication channel is via OMAPI.
 */
class TransportFactory {
    public:
    TransportFactory(bool isEmulator) {
        if (!isEmulator)
            mTransport = std::unique_ptr<OmapiTransport>(new OmapiTransport());
        else
            mTransport = std::unique_ptr<SocketTransport>(new SocketTransport());
    }

    ~TransportFactory() {}

    /**
     * Establishes a communication channel with the secure element.
     */
    inline bool openConnection() {
        return mTransport->openConnection();
    }

    /**
     * Sends the data to the secure element and also receives back the data.
     * This is a blocking call.
     */
    inline bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) {
        return mTransport->sendData(inData, inLen, output);
    }

    /**
     * Close the connection.
     */
    inline bool closeConnection() {
        return mTransport->closeConnection();
    }

    /**
     * Returns the connection status of the communication channel.
     */
    inline bool isConnected() {
        return mTransport->isConnected();
    }

    private:
    /**
     * Holds the instance of either OmapiTransport class or SocketTransport class.
     */
    std::unique_ptr<ITransport> mTransport;

};
}
#endif /* __SE_TRANSPORT_FACTORY__ */
