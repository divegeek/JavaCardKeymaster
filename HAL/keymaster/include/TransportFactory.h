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

class TransportFactory {
    public:
    TransportFactory(bool isEmulator) {
        if (!isEmulator)
            mTransport = std::unique_ptr<OmapiTransport>(new OmapiTransport());
        else
            mTransport = std::unique_ptr<SocketTransport>(new SocketTransport());
    }

    ~TransportFactory() {}

    inline bool openConnection() {
        return mTransport->openConnection();
    }

    inline bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) {
        return mTransport->sendData(inData, inLen, output);
    }

    inline bool closeConnection() {
        return mTransport->closeConnection();
    }

    inline bool isConnected() {
        return mTransport->isConnected();
    }

    private:
    std::unique_ptr<ITransport> mTransport;

};
}
#endif /* __SE_TRANSPORT_FACTORY__ */
