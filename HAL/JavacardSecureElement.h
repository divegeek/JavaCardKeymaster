/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include "CborConverter.h"
#include <ITransport.h>
#include <iostream>
#include <keymaster/km_version.h>
#include <optional>

#define APDU_CLS 0x80
#define APDU_KEYMINT_P1 0x50
#define APDU_KEYMASTER_P1 0x40
#define APDU_P2 0x00
#define APDU_RESP_STATUS_OK 0x9000

#define SE_POWER_RESET_STATUS_FLAG (1 << 30)

#define KEYMINT_CMD_APDU_START 0x20

namespace javacard_keymaster {
using keymaster::KmVersion;
using std::optional;
using std::shared_ptr;
using std::vector;

enum class Instruction {
    // Keymaster commands
    INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1,
    INS_IMPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 2,
    INS_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 3,
    INS_EXPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 4,
    INS_ATTEST_KEY_CMD = KEYMINT_CMD_APDU_START + 5,
    INS_UPGRADE_KEY_CMD = KEYMINT_CMD_APDU_START + 6,
    INS_DELETE_KEY_CMD = KEYMINT_CMD_APDU_START + 7,
    INS_DELETE_ALL_KEYS_CMD = KEYMINT_CMD_APDU_START + 8,
    INS_ADD_RNG_ENTROPY_CMD = KEYMINT_CMD_APDU_START + 9,
    INS_COMPUTE_SHARED_SECRET_CMD = KEYMINT_CMD_APDU_START + 10,
    INS_DESTROY_ATT_IDS_CMD = KEYMINT_CMD_APDU_START + 11,
    INS_VERIFY_AUTHORIZATION_CMD = KEYMINT_CMD_APDU_START + 12,
    INS_GET_SHARED_SECRET_PARAM_CMD = KEYMINT_CMD_APDU_START + 13,
    INS_GET_KEY_CHARACTERISTICS_CMD = KEYMINT_CMD_APDU_START + 14,
    INS_GET_HW_INFO_CMD = KEYMINT_CMD_APDU_START + 15,
    INS_BEGIN_OPERATION_CMD = KEYMINT_CMD_APDU_START + 16,
    INS_UPDATE_OPERATION_CMD = KEYMINT_CMD_APDU_START + 17,
    INS_FINISH_OPERATION_CMD = KEYMINT_CMD_APDU_START + 18,
    INS_ABORT_OPERATION_CMD = KEYMINT_CMD_APDU_START + 19,
    INS_DEVICE_LOCKED_CMD = KEYMINT_CMD_APDU_START + 20,
    INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21,
    INS_GET_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 22,
    INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23,
    INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24,
    INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25,
    INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26,
    // RKP Commands
    INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27,
    INS_GENERATE_RKP_KEY_CMD = KEYMINT_CMD_APDU_START + 28,
    INS_BEGIN_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 29,
    INS_UPDATE_KEY_CMD = KEYMINT_CMD_APDU_START + 30,
    INS_UPDATE_EEK_CHAIN_CMD = KEYMINT_CMD_APDU_START + 31,
    INS_UPDATE_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 32,
    INS_FINISH_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 33,
    INS_GET_RESPONSE_CMD = KEYMINT_CMD_APDU_START + 34,
};

class IJavacardSeResetListener {
  public:
    virtual ~IJavacardSeResetListener(){};
    virtual void seResetEvent() = 0;
};

class JavacardSecureElement {
  public:
    explicit JavacardSecureElement(KmVersion version, shared_ptr<ITransport> transport,
                                   uint32_t osVersion, uint32_t osPatchLevel,
                                   uint32_t vendorPatchLevel)
        : version_(version), transport_(transport), osVersion_(osVersion),
          osPatchLevel_(osPatchLevel), vendorPatchLevel_(vendorPatchLevel),
          cardInitialized_(false) {
        transport_->openConnection();
    }
    virtual ~JavacardSecureElement() { transport_->closeConnection(); }

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
                                                                     Array& request);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
                                                                     std::vector<uint8_t>& command);

    keymaster_error_t sendData(Instruction ins, std::vector<uint8_t>& inData,
                               std::vector<uint8_t>& response);

    keymaster_error_t constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData,
                                           std::vector<uint8_t>& apduOut);
    keymaster_error_t initializeJavacard();
    inline uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
        // Last two bytes are the status SW0SW1
        uint8_t SW0 = inputData.at(inputData.size() - 2);
        uint8_t SW1 = inputData.at(inputData.size() - 1);
        return (SW0 << 8 | SW1);
    }

  private:
    keymaster_error_t getP1(uint8_t* p1);

    KmVersion version_;
    shared_ptr<ITransport> transport_;
    uint32_t osVersion_;
    uint32_t osPatchLevel_;
    uint32_t vendorPatchLevel_;
    bool cardInitialized_;
    CborConverter cbor_;
};
}  // namespace javacard_keymaster
