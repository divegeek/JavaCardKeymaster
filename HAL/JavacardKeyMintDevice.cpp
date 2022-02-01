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

#define LOG_TAG "javacard.keymint.device.strongbox-impl"
#include "JavacardKeyMintDevice.h"
#include "JavacardKeyMintOperation.h"
#include <JavacardKeyMintUtils.h>
#include <JavacardKeymaster.h>
#include <KMUtils.h>
#include <KeyMintUtils.h>
#include <algorithm>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <hardware/hw_auth_token.h>
#include <iostream>
#include <iterator>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/wrapped_key.h>
#include <memory>
#include <regex.h>
#include <string>
#include <vector>

namespace aidl::android::hardware::security::keymint {
using km_utils::KmParamSet;
using km_utils::kmParamSet2Aidl;
using std::nullopt;

namespace {

Certificate convertCertificate(const keymaster_blob_t& cert) {
    return {std::vector<uint8_t>(cert.data, cert.data + cert.data_length)};
}

vector<Certificate> convertCertificateChain(const CertificateChain& chain) {
    vector<Certificate> retval;
    retval.reserve(chain.entry_count);
    std::transform(chain.begin(), chain.end(), std::back_inserter(retval), convertCertificate);
    return retval;
}

vector<KeyCharacteristics> convertKeyCharacteristics(AuthorizationSet& keystoreEnforced,
                                                     AuthorizationSet& sbEnforced,
                                                     AuthorizationSet& teeEnforced) {
    vector<KeyCharacteristics> retval;
    // VTS will fail if the authorizations list is empty.
    if (!sbEnforced.empty())
        retval.push_back({SecurityLevel::STRONGBOX, kmParamSet2Aidl(sbEnforced)});
    if (!teeEnforced.empty())
        retval.push_back({SecurityLevel::TRUSTED_ENVIRONMENT, kmParamSet2Aidl(teeEnforced)});
    if (!keystoreEnforced.empty())
        retval.push_back({SecurityLevel::KEYSTORE, kmParamSet2Aidl(keystoreEnforced)});
    return retval;
}

std::optional<JCKMAttestationKey>
convertAttestationKey(const std::optional<AttestationKey>& attestationKey) {
    JCKMAttestationKey key;
    if (attestationKey.has_value()) {
        key.params.Reinitialize(KmParamSet(attestationKey->attestKeyParams));
        key.keyBlob = attestationKey->keyBlob;
        key.issuerSubject = attestationKey->issuerSubjectName;
    }
    return std::move(key);
}
#if 0
inline void Vec2KmBlob(const vector<uint8_t>& input, KeymasterBlob* blob) {
    blob->Reset(input.size());
    memcpy(blob->writable_data(), input.data(), input.size());
}

void legacyHardwareAuthToken(const std::optional<HardwareAuthToken>& aidlToken, ::keymaster::HardwareAuthToken* legacyToken) {
    if (aidlToken.has_value()) {
        legacyToken->challenge = aidlToken->challenge;
        legacyToken->user_id = aidlToken->userId;
        legacyToken->authenticator_id = aidlToken->authenticatorId;
        legacyToken->authenticator_type = static_cast<hw_authenticator_type_t>(aidlToken->authenticatorType);
        legacyToken->timestamp = aidlToken->timestamp.milliSeconds;
        Vec2KmBlob(aidlToken->mac, &legacyToken->mac);
    }
}
#endif
}  // anonymous namespace

ScopedAStatus JavacardKeyMintDevice::defaultHwInfo(KeyMintHardwareInfo* info) {
    info->versionNumber = 1;
    info->keyMintAuthorName = "Google";
    info->keyMintName = "JavacardKeymintDevice";
    info->securityLevel = securitylevel_;
    info->timestampTokenRequired = true;
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info) {
    uint64_t tsRequired = 1;
    auto [item, err] = jcImpl_->getHardwareInfo();
    uint32_t secLevel;
    uint32_t version;
    if (err != KM_ERROR_OK || !cbor_.getUint64<uint32_t>(item, 1, version) ||
        !cbor_.getUint64<uint32_t>(item, 2, secLevel) ||
        !cbor_.getBinaryArray(item, 3, info->keyMintName) ||
        !cbor_.getBinaryArray(item, 4, info->keyMintAuthorName) ||
        !cbor_.getUint64<uint64_t>(item, 5, tsRequired)) {
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        return defaultHwInfo(info);
    }
    info->timestampTokenRequired = (tsRequired == 1);
    info->securityLevel = static_cast<SecurityLevel>(secLevel);
    info->versionNumber = static_cast<int32_t>(version);
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::generateKey(const vector<KeyParameter>& keyParams,
                                                 const optional<AttestationKey>& attestationKey,
                                                 KeyCreationResult* creationResult) {
    AuthorizationSet paramSet;
    std::optional<JCKMAttestationKey> jcAttestationKey = nullopt;
    AuthorizationSet swEnforced;
    AuthorizationSet sbEnforced;
    AuthorizationSet teeEnforced;
    paramSet.Reinitialize(KmParamSet(keyParams));

    auto err = jcImpl_->generateKey(paramSet, &creationResult->keyBlob, &swEnforced, &sbEnforced,
                                    &teeEnforced);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Failed in generateKey err: " << (int32_t)err;
        return km_utils::kmError2ScopedAStatus(err);
    }
    // Call attestKey only Asymmetric algorithms.
    keymaster_algorithm_t algorithm;
    paramSet.GetTagValue(TAG_ALGORITHM, &algorithm);
    if (algorithm == KM_ALGORITHM_RSA || algorithm == KM_ALGORITHM_EC) {
        err = attestKey(creationResult->keyBlob, paramSet, convertAttestationKey(attestationKey),
                        &creationResult->certificateChain);
        if (err != KM_ERROR_OK) {
            LOG(ERROR) << "Failed in attestKey err: " << (int32_t)err;
            return km_utils::kmError2ScopedAStatus(err);
        }
    }
    creationResult->keyCharacteristics =
        convertKeyCharacteristics(swEnforced, sbEnforced, teeEnforced);
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::addRngEntropy(const vector<uint8_t>& data) {
    auto err = jcImpl_->addRngEntropy(data);
    return km_utils::kmError2ScopedAStatus(err);
}

keymaster_error_t
JavacardKeyMintDevice::attestKey(const vector<uint8_t>& keyblob, const AuthorizationSet& keyParams,
                                 const optional<JCKMAttestationKey>& attestationKey,
                                 vector<Certificate>* certificateChain) {
    ::keymaster::CertificateChain certChain;
    auto err = jcImpl_->attestKey(keyblob, keyParams, attestationKey, &certChain);
    if (err != KM_ERROR_OK) {
        return err;
    }
    *certificateChain = convertCertificateChain(certChain);
    return KM_ERROR_OK;
}

ScopedAStatus JavacardKeyMintDevice::importKey(const vector<KeyParameter>& keyParams,
                                               KeyFormat keyFormat, const vector<uint8_t>& keyData,
                                               const optional<AttestationKey>& attestationKey,
                                               KeyCreationResult* creationResult) {
    AuthorizationSet paramSet;
    std::optional<JCKMAttestationKey> jcAttestationKey = nullopt;
    AuthorizationSet swEnforced;
    AuthorizationSet sbEnforced;
    AuthorizationSet teeEnforced;
    paramSet.Reinitialize(KmParamSet(keyParams));
    // Add CREATION_DATETIME if required, as secure element is not having clock.
    addCreationTime(paramSet);
    auto err = jcImpl_->importKey(paramSet, static_cast<keymaster_key_format_t>(keyFormat), keyData,
                                  &creationResult->keyBlob, &swEnforced, &sbEnforced, &teeEnforced);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Failed in importKey" << (int32_t)err;
        return km_utils::kmError2ScopedAStatus(err);
    }
    // Call attestKey only Asymmetric algorithms.
    keymaster_algorithm_t algorithm;
    paramSet.GetTagValue(TAG_ALGORITHM, &algorithm);
    if (algorithm == KM_ALGORITHM_RSA || algorithm == KM_ALGORITHM_EC) {
        err = attestKey(creationResult->keyBlob, paramSet, convertAttestationKey(attestationKey),
                        &creationResult->certificateChain);
        if (err != KM_ERROR_OK) {
            LOG(ERROR) << "Failed in attestKey" << (int32_t)err;
            return km_utils::kmError2ScopedAStatus(err);
        }
    }
    creationResult->keyCharacteristics =
        convertKeyCharacteristics(swEnforced, sbEnforced, teeEnforced);
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                                      const vector<uint8_t>& wrappingKeyBlob,
                                                      const vector<uint8_t>& maskingKey,
                                                      const vector<KeyParameter>& unwrappingParams,
                                                      int64_t passwordSid, int64_t biometricSid,
                                                      KeyCreationResult* creationResult) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet sbEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(unwrappingParams));
    auto err = jcImpl_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey, paramSet,
                                         passwordSid, biometricSid, &creationResult->keyBlob,
                                         &swEnforced, &sbEnforced, &teeEnforced);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Failed in attestKey" << (int32_t)err;
        return km_utils::kmError2ScopedAStatus(err);
    }
    creationResult->keyCharacteristics =
        convertKeyCharacteristics(swEnforced, sbEnforced, teeEnforced);
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                const vector<KeyParameter>& upgradeParams,
                                                vector<uint8_t>* keyBlob) {
    AuthorizationSet paramSet;
    paramSet.Reinitialize(KmParamSet(upgradeParams));
    auto err = jcImpl_->upgradeKey(keyBlobToUpgrade, paramSet, keyBlob);
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintDevice::deleteKey(const vector<uint8_t>& keyBlob) {
    auto err = jcImpl_->deleteKey(keyBlob);
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintDevice::deleteAllKeys() {
    auto err = jcImpl_->deleteAllKeys();
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintDevice::destroyAttestationIds() {
    auto err = jcImpl_->destroyAttestationIds();
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintDevice::begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                                           const std::vector<KeyParameter>& params,
                                           const std::optional<HardwareAuthToken>& authToken,
                                           BeginResult* result) {
    HardwareAuthToken aToken = authToken.value_or(HardwareAuthToken());
    AuthorizationSet paramSet;
    AuthorizationSet outParams;
    paramSet.Reinitialize(KmParamSet(params));
    ::keymaster::HardwareAuthToken legacyToken;
    std::unique_ptr<JavacardKeymasterOperation> operation;
    legacyHardwareAuthToken(aToken, &legacyToken);
    auto err = jcImpl_->begin(static_cast<keymaster_purpose_t>(purpose), keyBlob, paramSet,
                              legacyToken, &outParams, operation);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Failed in begin" << (int32_t)err;
        return km_utils::kmError2ScopedAStatus(err);
    }
    result->challenge = operation->getOpertionHandle();
    result->operation = ndk::SharedRefBase::make<JavacardKeyMintOperation>(std::move(operation));
    result->params = kmParamSet2Aidl(outParams);
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardKeyMintDevice::deviceLocked(bool passwordOnly,
                                    const std::optional<TimeStampToken>& timestampToken) {
    TimeStampToken tToken = timestampToken.value_or(TimeStampToken());
    vector<uint8_t> encodedTimestampToken;
    auto err = encodeTimestampToken(tToken, &encodedTimestampToken);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "In deviceLocked failed to encode TimeStampToken" << (int32_t)err;
        return km_utils::kmError2ScopedAStatus(err);
    }
    err = jcImpl_->deviceLocked(passwordOnly, encodedTimestampToken);
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintDevice::earlyBootEnded() {
    auto err = jcImpl_->earlyBootEnded();
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintDevice::getKeyCharacteristics(
    const std::vector<uint8_t>& keyBlob, const std::vector<uint8_t>& appId,
    const std::vector<uint8_t>& appData, std::vector<KeyCharacteristics>* result) {

    AuthorizationSet swEnforced;
    AuthorizationSet sbEnforced;
    AuthorizationSet teeEnforced;
    auto err = jcImpl_->getKeyCharacteristics(keyBlob, appId, appData, &swEnforced, &sbEnforced,
                                              &teeEnforced);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in getKeyCharacteristics.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    *result = convertKeyCharacteristics(swEnforced, sbEnforced, teeEnforced);
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::convertStorageKeyToEphemeral(
    const std::vector<uint8_t>& /* storageKeyBlob */,
    std::vector<uint8_t>* /* ephemeralKeyBlob */) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}
}  // namespace aidl::android::hardware::security::keymint
