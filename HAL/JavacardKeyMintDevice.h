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
#include <JavacardKeymaster.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>

namespace aidl::android::hardware::security::keymint {
using namespace aidl::android::hardware::security::sharedsecret;
using namespace aidl::android::hardware::security::secureclock;
using namespace ::keymaster;
using namespace ::javacard_keymaster;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;
using JCKMAttestationKey = ::javacard_keymaster::AttestationKey;

class JavacardKeyMintDevice : public BnKeyMintDevice {
  public:
    explicit JavacardKeyMintDevice(shared_ptr<JavacardKeymaster> jcImpl)
        : securitylevel_(SecurityLevel::STRONGBOX), jcImpl_(jcImpl),
          isEarlyBootEventPending(false) {}
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
    keymaster_error_t attestKey(const vector<uint8_t>& keyblob, const AuthorizationSet& keyParams,
                                const optional<JCKMAttestationKey>& attestationKey,
                                vector<Certificate>* certificateChain);

    ScopedAStatus defaultHwInfo(KeyMintHardwareInfo* info);

    void handleSendEarlyBootEndedEvent();

    const SecurityLevel securitylevel_;
    const shared_ptr<JavacardKeymaster> jcImpl_;
    CborConverter cbor_;
    bool isEarlyBootEventPending;
};

}  // namespace aidl::android::hardware::security::keymint
