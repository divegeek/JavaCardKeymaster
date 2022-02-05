#pragma once

#include "ITransport.h"
#include <aidl/android/se/omapi/BnSecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementChannel.h>
#include <aidl/android/se/omapi/ISecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementReader.h>
#include <aidl/android/se/omapi/ISecureElementService.h>
#include <aidl/android/se/omapi/ISecureElementSession.h>
#include <android/binder_manager.h>
#include <map>
#include <memory>
#include <vector>

namespace javacard_keymaster {
using std::vector;

/**
 * OmapiTransport is derived from ITransport. This class gets the OMAPI service binder instance and
 * uses IPC to communicate with OMAPI service. OMAPI inturn communicates with hardware via
 * ISecureElement.
 */
class OmapiTransport : public ITransport {

  public:
    /**
     * Gets the binder instance of ISEService, gets the reader corresponding to secure element,
     * establishes a session and opens a basic channel.
     */
    bool openConnection() override;
    /**
     * Transmists the data over the opened basic channel and receives the data back.
     */
    bool sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) override;

    /**
     * Closes the connection.
     */
    bool closeConnection() override;
    /**
     * Returns the state of the connection status. Returns true if the connection is active, false
     * if connection is broken.
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
    bool
    internalTransmitApdu(std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> reader,
                         std::vector<uint8_t> apdu, std::vector<uint8_t>& transmitResponse);
};

}  // namespace javacard_keymaster
