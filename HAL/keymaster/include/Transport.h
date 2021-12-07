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
#ifndef __SE_TRANSPORT__
#define __SE_TRANSPORT__

#include <aidl/android/se/omapi/BnSecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementChannel.h>
#include <aidl/android/se/omapi/ISecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementReader.h>
#include <aidl/android/se/omapi/ISecureElementService.h>
#include <aidl/android/se/omapi/ISecureElementSession.h>
#include <android/binder_manager.h>

#include <map>

namespace se_transport {

/**
 * ITransport is an abstract interface with a set of virtual methods that allow communication between the keymaster
 * HAL and the secure element.
 */
class ITransport {
    public:
    virtual ~ITransport(){}

    /**
     * Opens connection.
     */
      virtual bool openConnection() = 0;
    /**
     * Send data over communication channel and receives data back from the remote end.
     */
    virtual bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) = 0;
    /**
     * Closes the connection.
     */
    virtual bool closeConnection() = 0;
    /**
     * Returns the state of the connection status. Returns true if the connection is active, false if connection is
     * broken.
     */
    virtual bool isConnected() = 0;

};

/**
 * OmapiTransport is derived from ITransport. This class gets the OMAPI service binder instance and uses IPC to
 * communicate with OMAPI service. OMAPI inturn communicates with hardware via ISecureElement.
 */
class OmapiTransport : public ITransport {

public:

    /**
     * Gets the binder instance of ISEService, gets the reader corresponding to secure element, establishes a session
     * and opens a basic channel.
     */
      bool openConnection() override;
    /**
     * Transmists the data over the opened basic channel and receives the data back.
     */
    bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) override;

    /**
     * Closes the connection.
     */
    bool closeConnection() override;
    /**
     * Returns the state of the connection status. Returns true if the connection is active, false if connection is
     * broken.
     */
    bool isConnected() override;

private:
    std::shared_ptr<aidl::android::se::omapi::ISecureElementService> omapiSeService = nullptr;
    std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> eSEReader = nullptr;
    std::map<std::string, std::shared_ptr<aidl::android::se::omapi::ISecureElementReader>>
            mVSReaders = {};
    std::string const ESE_READER_PREFIX = "eSE";
    constexpr static const char omapiServiceName[] =
            "android.system.omapi.ISecureElementService/default";

    bool initialize();
    bool internalTransmitApdu(
            std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> reader,
            std::vector<uint8_t> apdu, std::vector<uint8_t>& transmitResponse);
};

class SocketTransport : public ITransport {

public:
    SocketTransport() : mSocket(-1), mSocketStatus(false){
    }
    /**
     * Creates a socket instance and connects to the provided server IP and port.
     */
      bool openConnection() override;
    /**
     * Sends data over socket and receives data back.
     */
    bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) override;

    /**
     * Closes the connection.
     */
    bool closeConnection() override;
    /**
     * Returns the state of the connection status. Returns true if the connection is active, false if connection is
     * broken.
     */
    bool isConnected() override;
private:
    /**
     * Socket instance.
     */
    int mSocket;
    bool mSocketStatus;
};

}
#endif /* __SE_TRANSPORT__ */
