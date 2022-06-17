#pragma once

#include <map>
#include <memory>
#include <vector>


#include <aidl/android/se/omapi/BnSecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementChannel.h>
#include <aidl/android/se/omapi/ISecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementReader.h>
#include <aidl/android/se/omapi/ISecureElementService.h>
#include <aidl/android/se/omapi/ISecureElementSession.h>

#include <android/binder_manager.h>

#include "ITransport.h"

namespace keymint::javacard {
using std::vector;

/**
 * OmapiTransport is derived from ITransport. This class gets the OMAPI service binder instance and
 * uses IPC to communicate with OMAPI service. OMAPI inturn communicates with hardware via
 * ISecureElement.
 */
class OmapiTransport : public ITransport {

  public:
    OmapiTransport() : omapiSeService(nullptr), eSEReader(nullptr), session(nullptr),
        channel(nullptr), mVSReaders({}) {
    }
    /**
     * Gets the binder instance of ISEService, gets te reader corresponding to secure element,
     * establishes a session and opens a basic channel.
     */
    keymaster_error_t openConnection() override;
    /**
     * Transmists the data over the opened basic channel and receives the data back.
     */
    keymaster_error_t sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) override;

    /**
     * Closes the connection.
     */
    keymaster_error_t closeConnection() override;
    /**
     * Returns the state of the connection status. Returns true if the connection is active, false
     * if connection is broken.
     */
    bool isConnected() override;

  private:
    std::shared_ptr<aidl::android::se::omapi::ISecureElementService> omapiSeService;
    std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> eSEReader;
    std::shared_ptr<aidl::android::se::omapi::ISecureElementSession> session;
    std::shared_ptr<aidl::android::se::omapi::ISecureElementChannel> channel;
    std::map<std::string, std::shared_ptr<aidl::android::se::omapi::ISecureElementReader>>
        mVSReaders;
    keymaster_error_t initialize();
    bool
    internalTransmitApdu(std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> reader,
                         std::vector<uint8_t> apdu, std::vector<uint8_t>& transmitResponse);
};

}
