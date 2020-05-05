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

namespace se_transport {

typedef void (*connectionCallback)(bool connected);
typedef void (*responseCallback)(std::vector<uint8_t> output);

class ITransport {
    public:
    virtual ~ITransport(){}
    virtual bool openConnection(connectionCallback cb) = 0;
	virtual bool openConnection() = 0;
    virtual bool sendData(const uint8_t* inData, const size_t inLen, responseCallback cb) = 0;
    virtual bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) = 0;
    virtual bool closeConnection() = 0;
    virtual bool isConnected() = 0;

};

class OmapiTransport : public ITransport {

public:

    bool openConnection(connectionCallback cb) override;
	bool openConnection() override;
    bool sendData(const uint8_t* inData, const size_t inLen, responseCallback cb) override;
    virtual bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) override;
    bool closeConnection() override;
    bool isConnected() override;

};

class SocketTransport : public ITransport {

public:
    bool openConnection(connectionCallback cb) override;
	bool openConnection() override;
    bool sendData(const uint8_t* inData, const size_t inLen, responseCallback cb) override;
    virtual bool sendData(const uint8_t* inData, const size_t inLen, std::vector<uint8_t>& output) override;
    bool closeConnection() override;
    bool isConnected() override;
private:
    int mSocket;

};

}
#endif /* __SE_TRANSPORT__ */
