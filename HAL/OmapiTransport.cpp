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
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <android-base/logging.h>

#include "OmapiTransport.h"

namespace javacard_keymaster {

class SEListener : public ::aidl::android::se::omapi::BnSecureElementListener {};

bool OmapiTransport::initialize() {
    std::vector<std::string> readers = {};

    LOG(DEBUG) << "Initialize the secure element connection";

    // Get OMAPI vendor stable service handler
    ::ndk::SpAIBinder ks2Binder(AServiceManager_getService(omapiServiceName));
    omapiSeService = aidl::android::se::omapi::ISecureElementService::fromBinder(ks2Binder);

    if (omapiSeService == nullptr) {
        LOG(ERROR) << "Failed to start omapiSeService null";
        return false;
    }

    // reset readers, clear readers if already existing
    if (mVSReaders.size() > 0) {
        closeConnection();
    }

    // Get available readers
    auto status = omapiSeService->getReaders(&readers);
    if (!status.isOk()) {
        LOG(ERROR) << "getReaders failed to get available readers: " << status.getMessage();
        return false;
    }

    // Get SE readers handlers
    for (auto readerName : readers) {
        std::shared_ptr<::aidl::android::se::omapi::ISecureElementReader> reader;
        status = omapiSeService->getReader(readerName, &reader);
        if (!status.isOk()) {
            LOG(ERROR) << "getReader for " << readerName.c_str()
                       << " Failed: " << status.getMessage();
            return false;
        }

        mVSReaders[readerName] = reader;
    }

    // Find eSE reader, as of now assumption is only eSE available on device
    LOG(DEBUG) << "Finding eSE reader";
    eSEReader = nullptr;
    if (mVSReaders.size() > 0) {
        for (const auto& [name, reader] : mVSReaders) {
            if (name.find(ESE_READER_PREFIX, 0) != std::string::npos) {
                LOG(DEBUG) << "eSE reader found: " << name;
                eSEReader = reader;
            }
        }
    }

    if (eSEReader == nullptr) {
        LOG(ERROR) << "secure element reader " << ESE_READER_PREFIX << " not found";
        return false;
    }

    return true;
}

bool OmapiTransport::internalTransmitApdu(
    std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> reader,
    std::vector<uint8_t> apdu, std::vector<uint8_t>& transmitResponse) {
    std::shared_ptr<aidl::android::se::omapi::ISecureElementSession> session;
    std::shared_ptr<aidl::android::se::omapi::ISecureElementChannel> channel;
    auto mSEListener = ndk::SharedRefBase::make<SEListener>();
    std::vector<uint8_t> selectResponse = {};
    std::vector<uint8_t> SELECTABLE_AID = {0xA0, 0x00, 0x00, 0x04, 0x76, 0x41, 0x6E, 0x64,
                                           0x72, 0x6F, 0x69, 0x64, 0x43, 0x54, 0x53, 0x31};

    LOG(DEBUG) << "internalTransmitApdu: trasmitting data to secure element";

    if (reader == nullptr) {
        LOG(ERROR) << "eSE reader is null";
        return false;
    }

    bool status = false;
    auto res = reader->isSecureElementPresent(&status);
    if (!res.isOk()) {
        LOG(ERROR) << "isSecureElementPresent error: " << res.getMessage();
        return false;
    }
    if (!status) {
        LOG(ERROR) << "secure element not found";
        return false;
    }

    res = reader->openSession(&session);
    if (!res.isOk()) {
        LOG(ERROR) << "openSession error: " << res.getMessage();
        return false;
    }
    if (session == nullptr) {
        LOG(ERROR) << "Could not open session null";
        return false;
    }

    res = session->openLogicalChannel(SELECTABLE_AID, 0x00, mSEListener, &channel);
    if (!res.isOk()) {
        LOG(ERROR) << "openLogicalChannel error: " << res.getMessage();
        return false;
    }
    if (channel == nullptr) {
        LOG(ERROR) << "Could not open channel null";
        return false;
    }

    res = channel->getSelectResponse(&selectResponse);
    if (!res.isOk()) {
        LOG(ERROR) << "getSelectResponse error: " << res.getMessage();
        return false;
    }
    if (selectResponse.size() < 2) {
        LOG(ERROR) << "getSelectResponse size error";
        return false;
    }

    res = channel->transmit(apdu, &transmitResponse);
    if (channel != nullptr) channel->close();
    if (session != nullptr) session->close();

    LOG(INFO) << "STATUS OF TRNSMIT: " << res.getExceptionCode()
              << " Message: " << res.getMessage();
    if (!res.isOk()) {
        LOG(ERROR) << "transmit error: " << res.getMessage();
        return false;
    }

    return true;
}

bool OmapiTransport::openConnection() {

    // if already conection setup done, no need to initialise it again.
    if (isConnected()) {
        return true;
    }

    return initialize();
}

bool OmapiTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) {

    if (!isConnected()) {
        // Try to initialize connection to eSE
        LOG(INFO) << "Failed to send data, try to initialize connection SE connection";
        if (!initialize()) {
            LOG(ERROR) << "Failed to send data, initialization not completed";
            closeConnection();
            return false;
        }
    }

    if (eSEReader != nullptr) {
        LOG(DEBUG) << "Sending apdu data to secure element: " << ESE_READER_PREFIX;
        return internalTransmitApdu(eSEReader, inData, output);
    } else {
        LOG(ERROR) << "secure element reader " << ESE_READER_PREFIX << " not found";
        return false;
    }
}

bool OmapiTransport::closeConnection() {
    LOG(DEBUG) << "Closing all connections";
    if (omapiSeService != nullptr) {
        if (mVSReaders.size() > 0) {
            for (const auto& [name, reader] : mVSReaders) {
                reader->closeSessions();
            }
            mVSReaders.clear();
        }
    }
    return true;
}

bool OmapiTransport::isConnected() {
    // Check already initialization completed or not
    if (omapiSeService != nullptr && eSEReader != nullptr) {
        LOG(DEBUG) << "Connection initialization already completed";
        return true;
    }

    LOG(DEBUG) << "Connection initialization not completed";
    return false;
}

}  // namespace javacard_keymaster
