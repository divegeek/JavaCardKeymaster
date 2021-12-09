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
#include "JavacardSharedSecret.h"
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
using namespace ::keymaster;
using namespace ::keymint::javacard;

ScopedAStatus JavacardKeyMintDevice::defaultHwInfo(KeyMintHardwareInfo* info) {
    info->versionNumber = 1;
    info->keyMintAuthorName = "Google";
    info->keyMintName = "JavacardKeymintDevice";
    info->securityLevel = securitylevel_;
    info->timestampTokenRequired = true;
    return ScopedAStatus::ok();
}

static inline bool findTag(const vector<KeyParameter>& params, Tag tag) {
    size_t size = params.size();
    for (size_t i = 0; i < size; ++i) {
        if (tag == params[i].tag) return true;
    }
    return false;
}

ScopedAStatus JavacardKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info) {
    uint64_t tsRequired = 1;
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_HW_INFO_CMD);
    uint32_t secLevel;
    uint32_t version;
    if (err != KM_ERROR_OK || !cbor_.getUint64<uint32_t>(item, 1, version) ||
        !cbor_.getUint64<uint32_t>(item, 2, secLevel) ||
        !cbor_.getBinaryArray(item, 3, info->keyMintName) ||
        !cbor_.getBinaryArray(item, 4, info->keyMintAuthorName) ||
        !cbor_.getUint64<uint64_t>(item, 5, tsRequired)) {
        // TODO should we return HARDWARE_NOT_YET_AVAILABLE instead of default Hardware Info.
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        return defaultHwInfo(info);
    }
    card_->initializeJavacard();
    info->timestampTokenRequired = (tsRequired == 1);
    info->securityLevel = static_cast<SecurityLevel>(secLevel);
    info->versionNumber = static_cast<int32_t>(version);
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::generateKey(const vector<KeyParameter>& keyParams,
                                                 const optional<AttestationKey>& attestationKey,
                                                 KeyCreationResult* creationResult) {
    cppbor::Array array;
    // add key params
    cbor_.addKeyparameters(array, keyParams);
    // add attestation key if any
    cbor_.addAttestationKey(array, attestationKey);
    auto [item, err] = card_->sendRequest(Instruction::INS_GENERATE_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending generateKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!cbor_.getBinaryArray(item, 1, creationResult->keyBlob) ||
        !cbor_.getKeyCharacteristics(item, 2, creationResult->keyCharacteristics) ||
        !cbor_.getCertificateChain(item, 3, creationResult->certificateChain)) {
        LOG(ERROR) << "Error in decoding og response in generateKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::addRngEntropy(const vector<uint8_t>& data) {
    cppbor::Array request;
    // add key data
    request.add(Bstr(data));
    auto [item, err] = card_->sendRequest(Instruction::INS_ADD_RNG_ENTROPY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending addRngEntropy.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::importKey(const vector<KeyParameter>& keyParams,
                                               KeyFormat keyFormat, const vector<uint8_t>& keyData,
                                               const optional<AttestationKey>& attestationKey,
                                               KeyCreationResult* creationResult) {

    cppbor::Array request;
    vector<KeyParameter> updatedParams(keyParams);

    // Add CREATION_DATETIME if required, as secure element is not having clock.
    if (!findTag(keyParams, Tag::CREATION_DATETIME) && !findTag(keyParams, Tag::ACTIVE_DATETIME)) {
        updatedParams.push_back(km_utils::kmParam2Aidl(
            keymaster_param_date(KM_TAG_CREATION_DATETIME, java_time(time(nullptr)))));
    }
    // add key params
    cbor_.addKeyparameters(request, updatedParams);
    // add key format
    request.add(Uint(static_cast<uint8_t>(keyFormat)));
    // add key data
    request.add(Bstr(keyData));
    // add attestation key if any
    cbor_.addAttestationKey(request, attestationKey);

    auto [item, err] = card_->sendRequest(Instruction::INS_IMPORT_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending data in importKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!cbor_.getBinaryArray(item, 1, creationResult->keyBlob) ||
        !cbor_.getKeyCharacteristics(item, 2, creationResult->keyCharacteristics) ||
        !cbor_.getCertificateChain(item, 3, creationResult->certificateChain)) {
        LOG(ERROR) << "Error in decoding response in importKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

// import wrapped key is divided into 2 stage operation.
ScopedAStatus JavacardKeyMintDevice::importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                                      const vector<uint8_t>& wrappingKeyBlob,
                                                      const vector<uint8_t>& maskingKey,
                                                      const vector<KeyParameter>& unwrappingParams,
                                                      int64_t passwordSid, int64_t biometricSid,
                                                      KeyCreationResult* creationResult) {
    cppbor::Array request;
    std::unique_ptr<Item> item;
    vector<uint8_t> keyBlob;
    std::vector<uint8_t> response;
    vector<KeyCharacteristics> keyCharacteristics;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> transitKey;
    std::vector<uint8_t> secureKey;
    std::vector<uint8_t> tag;
    vector<KeyParameter> authList;
    KeyFormat keyFormat;
    std::vector<uint8_t> wrappedKeyDescription;

    keymaster_error_t errorCode = parseWrappedKey(wrappedKeyData, iv, transitKey, secureKey, tag,
                                                  authList, keyFormat, wrappedKeyDescription);
    if (errorCode != KM_ERROR_OK) {
        LOG(ERROR) << "Error in parse wrapped key in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(errorCode);
    }

    // begin import
    std::tie(item, errorCode) =
        sendBeginImportWrappedKeyCmd(transitKey, wrappingKeyBlob, maskingKey, unwrappingParams);
    if (errorCode != KM_ERROR_OK) {
        LOG(ERROR) << "Error in send begin import wrapped key in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(errorCode);
    }
    // Finish the import
    std::tie(item, errorCode) = sendFinishImportWrappedKeyCmd(
        authList, keyFormat, secureKey, tag, iv, wrappedKeyDescription, passwordSid, biometricSid);
    if (errorCode != KM_ERROR_OK) {
        LOG(ERROR) << "Error in send finish import wrapped key in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(errorCode);
    }
    if (!cbor_.getBinaryArray(item, 1, creationResult->keyBlob) ||
        !cbor_.getKeyCharacteristics(item, 2, creationResult->keyCharacteristics) ||
        !cbor_.getCertificateChain(item, 3, creationResult->certificateChain)) {
        LOG(ERROR) << "Error in decoding the response in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeyMintDevice::sendBeginImportWrappedKeyCmd(const std::vector<uint8_t>& transitKey,
                                                    const std::vector<uint8_t>& wrappingKeyBlob,
                                                    const std::vector<uint8_t>& maskingKey,
                                                    const vector<KeyParameter>& unwrappingParams) {
    Array request;
    request.add(std::vector<uint8_t>(transitKey));
    request.add(std::vector<uint8_t>(wrappingKeyBlob));
    request.add(std::vector<uint8_t>(maskingKey));
    cbor_.addKeyparameters(request, unwrappingParams);
    return card_->sendRequest(Instruction::INS_BEGIN_IMPORT_WRAPPED_KEY_CMD, request);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeyMintDevice::sendFinishImportWrappedKeyCmd(
    const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
    const std::vector<uint8_t>& secureKey, const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& iv, const std::vector<uint8_t>& wrappedKeyDescription,
    int64_t passwordSid, int64_t biometricSid) {
    Array request;
    cbor_.addKeyparameters(request, keyParams);
    request.add(static_cast<uint64_t>(keyFormat));
    request.add(std::vector<uint8_t>(secureKey));
    request.add(std::vector<uint8_t>(tag));
    request.add(std::vector<uint8_t>(iv));
    request.add(std::vector<uint8_t>(wrappedKeyDescription));
    request.add(Uint(passwordSid));
    request.add(Uint(biometricSid));
    return card_->sendRequest(Instruction::INS_FINISH_IMPORT_WRAPPED_KEY_CMD, request);
}

ScopedAStatus JavacardKeyMintDevice::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                const vector<KeyParameter>& upgradeParams,
                                                vector<uint8_t>* keyBlob) {
    cppbor::Array request;
    // add key blob
    request.add(Bstr(keyBlobToUpgrade));
    // add key params
    cbor_.addKeyparameters(request, upgradeParams);
    auto [item, err] = card_->sendRequest(Instruction::INS_UPGRADE_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!cbor_.getBinaryArray(item, 1, *keyBlob)) {
        LOG(ERROR) << "Error in decoding the response in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::deleteKey(const vector<uint8_t>& keyBlob) {
    Array request;
    request.add(Bstr(keyBlob));
    auto [item, err] = card_->sendRequest(Instruction::INS_DELETE_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in deleteKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::deleteAllKeys() {
    auto [item, err] = card_->sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in deleteAllKeys.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::destroyAttestationIds() {
    auto [item, err] = card_->sendRequest(Instruction::INS_DESTROY_ATT_IDS_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in destroyAttestationIds.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                                           const std::vector<KeyParameter>& params,
                                           const std::optional<HardwareAuthToken>& authToken,
                                           BeginResult* result) {

    cppbor::Array array;
    std::vector<uint8_t> response;
    // make request
    array.add(Uint(static_cast<uint64_t>(purpose)));
    array.add(Bstr(keyBlob));
    cbor_.addKeyparameters(array, params);
    HardwareAuthToken token = authToken.value_or(HardwareAuthToken());
    cbor_.addHardwareAuthToken(array, token);
    auto [item, err] = card_->sendRequest(Instruction::INS_BEGIN_OPERATION_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in begin.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    // return the result
    uint64_t opHandle;
    uint8_t bufMode;
    uint16_t macLength;
    if (!cbor_.getKeyParameters(item, 1, result->params) ||
        !cbor_.getUint64<uint64_t>(item, 2, opHandle) ||
        !cbor_.getUint64<uint8_t>(item, 3, bufMode) ||
        !cbor_.getUint64<uint16_t>(item, 4, macLength)) {
        LOG(ERROR) << "Error in decoding the response in begin.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    result->challenge = opHandle;
    result->operation = ndk::SharedRefBase::make<JavacardKeyMintOperation>(
        static_cast<keymaster_operation_handle_t>(opHandle), static_cast<BufferingMode>(bufMode),
        macLength, card_);
    return ScopedAStatus::ok();
}

// TODO
ScopedAStatus
JavacardKeyMintDevice::deviceLocked(bool passwordOnly,
                                    const std::optional<TimeStampToken>& timestampToken) {
    Array request;
    int8_t password = 1;
    if (!passwordOnly) {
        password = 0;
    }
    request.add(Uint(password));
    cbor_.addTimeStampToken(request, timestampToken.value_or(TimeStampToken()));
    auto [item, err] = card_->sendRequest(Instruction::INS_DEVICE_LOCKED_CMD, request);
    if (err != KM_ERROR_OK) {
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::earlyBootEnded() {
    auto [item, err] = card_->sendRequest(Instruction::INS_EARLY_BOOT_ENDED_CMD);
    if (err != KM_ERROR_OK) {
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::getKeyCharacteristics(
    const std::vector<uint8_t>& keyBlob, const std::vector<uint8_t>& appId,
    const std::vector<uint8_t>& appData, std::vector<KeyCharacteristics>* result) {
    cppbor::Array request;
    request.add(vector<uint8_t>(keyBlob));
    request.add(vector<uint8_t>(appId));
    request.add(vector<uint8_t>(appData));
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_KEY_CHARACTERISTICS_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in getKeyCharacteristics.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!cbor_.getKeyCharacteristics(item, 1, *result)) {
        LOG(ERROR) << "Error in sending in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

keymaster_error_t
JavacardKeyMintDevice::parseWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                       std::vector<uint8_t>& iv, std::vector<uint8_t>& transitKey,
                                       std::vector<uint8_t>& secureKey, std::vector<uint8_t>& tag,
                                       vector<KeyParameter>& authList, KeyFormat& keyFormat,
                                       std::vector<uint8_t>& wrappedKeyDescription) {
    KeymasterBlob kmIv;
    KeymasterKeyBlob kmTransitKey;
    KeymasterKeyBlob kmSecureKey;
    KeymasterBlob kmTag;
    AuthorizationSet authSet;
    keymaster_key_format_t kmKeyFormat;
    KeymasterBlob kmWrappedKeyDescription;

    size_t keyDataLen = wrappedKeyData.size();
    uint8_t* keyData = dup_buffer(wrappedKeyData.data(), keyDataLen);
    keymaster_key_blob_t keyMaterial = {keyData, keyDataLen};
    keymaster_error_t error =
        parse_wrapped_key(KeymasterKeyBlob(keyMaterial), &kmIv, &kmTransitKey, &kmSecureKey, &kmTag,
                          &authSet, &kmKeyFormat, &kmWrappedKeyDescription);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "Error parsing wrapped key.";
        return error;
    }
    iv = km_utils::kmBlob2vector(kmIv);
    transitKey = km_utils::kmBlob2vector(kmTransitKey);
    secureKey = km_utils::kmBlob2vector(kmSecureKey);
    tag = km_utils::kmBlob2vector(kmTag);
    authList = km_utils::kmParamSet2Aidl(authSet);
    keyFormat = static_cast<KeyFormat>(kmKeyFormat);
    wrappedKeyDescription = km_utils::kmBlob2vector(kmWrappedKeyDescription);
    return KM_ERROR_OK;
}

ScopedAStatus JavacardKeyMintDevice::convertStorageKeyToEphemeral(
    const std::vector<uint8_t>& /* storageKeyBlob */,
    std::vector<uint8_t>* /* ephemeralKeyBlob */) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}
}  // namespace aidl::android::hardware::security::keymint
