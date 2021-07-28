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
#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>

#define APDU_CLS 0x80
#define APDU_P1 0x50
#define APDU_P2 0x00
#define APDU_RESP_STATUS_OK 0x9000

#define KEYMINT_CMD_APDU_START 0x20
#define SW_KM_OPR 0UL
#define SB_KM_OPR 1UL
#define JAVACARD_KEYMINT_VERSION 1

namespace aidl::android::hardware::security::keymint {
using namespace ::keymint::javacard;
using namespace aidl::android::hardware::security::sharedsecret;
using namespace aidl::android::hardware::security::secureclock;
using ndk::ScopedAStatus;
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
    INS_SET_BOOT_PARAMS_CMD = KEYMINT_CMD_APDU_START + 26,
};

class JavacardKeyMintDevice : public BnKeyMintDevice {
  public:
    explicit JavacardKeyMintDevice(shared_ptr<ITransport> transport, uint32_t osVersion,
                                   uint32_t osPatchlevel, uint32_t vednorPatchLevel);
    virtual ~JavacardKeyMintDevice();

    ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) override;

    ScopedAStatus addRngEntropy(const vector<uint8_t>& data) override;

    ScopedAStatus generateKey(const vector<KeyParameter>& keyParams,
                              const optional<AttestationKey>& attestationKey,
                              KeyCreationResult* creationResult) override;

    ScopedAStatus importKey(const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                            const vector<uint8_t>& keyData,
                            const optional<AttestationKey>& attestationKey,
                            KeyCreationResult* creationResult) override;

    ScopedAStatus importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                   const vector<uint8_t>& wrappingKeyBlob,
                                   const vector<uint8_t>& maskingKey,
                                   const vector<KeyParameter>& unwrappingParams,
                                   int64_t passwordSid, int64_t biometricSid,
                                   KeyCreationResult* creationResult) override;

    ScopedAStatus upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                             const vector<KeyParameter>& upgradeParams,
                             vector<uint8_t>* keyBlob) override;

    ScopedAStatus deleteKey(const vector<uint8_t>& keyBlob) override;
    ScopedAStatus deleteAllKeys() override;
    ScopedAStatus destroyAttestationIds() override;

    virtual ScopedAStatus begin(KeyPurpose in_purpose, const std::vector<uint8_t>& in_keyBlob,
                                const std::vector<KeyParameter>& in_params,
                                const std::optional<HardwareAuthToken>& in_authToken,
                                BeginResult* _aidl_return) override;

    ScopedAStatus deviceLocked(bool passwordOnly,
                               const optional<TimeStampToken>& timestampToken) override;
    ScopedAStatus earlyBootEnded() override;

    ScopedAStatus getSharedSecretParameters(SharedSecretParameters* params);

    ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                      std::vector<uint8_t>* secret);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
                                                                     Array& request);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins);

    keymaster_error_t sendData(Instruction ins, std::vector<uint8_t>& inData,
                               std::vector<uint8_t>& response);
    keymaster_error_t initializeJavacard();
    ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& in_keyBlob,
                                        const std::vector<uint8_t>& in_appId,
                                        const std::vector<uint8_t>& in_appData,
                                        std::vector<KeyCharacteristics>* _aidl_return) override;

    ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& storageKeyBlob,
                                               std::vector<uint8_t>* ephemeralKeyBlob) override;

  private:
    keymaster_error_t parseWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                      std::vector<uint8_t>& iv, std::vector<uint8_t>& transitKey,
                                      std::vector<uint8_t>& secureKey, std::vector<uint8_t>& tag,
                                      vector<KeyParameter>& authList, KeyFormat& keyFormat,
                                      std::vector<uint8_t>& wrappedKeyDescription);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendBeginImportWrappedKeyCmd(
        const std::vector<uint8_t>& transitKey, const std::vector<uint8_t>& wrappingKeyBlob,
        const std::vector<uint8_t>& maskingKey, const vector<KeyParameter>& unwrappingParams);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t>
    sendFinishImportWrappedKeyCmd(const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                                  const std::vector<uint8_t>& secureKey,
                                  const std::vector<uint8_t>& tag, const std::vector<uint8_t>& iv,
                                  const std::vector<uint8_t>& wrappedKeyDescription,
                                  int64_t passwordSid, int64_t biometricSid);
    ScopedAStatus defaultHwInfo(KeyMintHardwareInfo* info);

    keymaster_error_t constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData,
                                           std::vector<uint8_t>& apduOut);
    inline uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
        // Last two bytes are the status SW0SW1
        uint8_t SW0 = inputData.at(inputData.size() - 2);
        uint8_t SW1 = inputData.at(inputData.size() - 1);
        return (SW0 << 8 | SW1);
    }

    SecurityLevel securitylevel_;
    shared_ptr<ITransport> transport_;
    CborConverter cbor_;
    uint32_t osVersion_;
    uint32_t osPatchLevel_;
    uint32_t vendorPatchLevel_;
    bool javacardInitialized_;
};
}  // namespace aidl::android::hardware::security::keymint
