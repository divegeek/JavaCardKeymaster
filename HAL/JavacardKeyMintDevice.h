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
#include "JavacardSecureElement.h"
#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>

namespace aidl::android::hardware::security::keymint {
using namespace ::keymint::javacard;
using namespace aidl::android::hardware::security::sharedsecret;
using namespace aidl::android::hardware::security::secureclock;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;

class JavacardKeyMintDevice : public BnKeyMintDevice {
  public:
    explicit JavacardKeyMintDevice(shared_ptr<JavacardSecureElement> card)
        : securitylevel_(SecurityLevel::STRONGBOX), card_(card) {
        card_->initializeJavacard();
    }
    virtual ~JavacardKeyMintDevice() {}

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

    const SecurityLevel securitylevel_;
    const shared_ptr<JavacardSecureElement> card_;
    CborConverter cbor_;
};

}  // namespace aidl::android::hardware::security::keymint
