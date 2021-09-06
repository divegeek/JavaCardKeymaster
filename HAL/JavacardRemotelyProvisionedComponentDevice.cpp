/*
 * Copyright 2021, The Android Open Source Project
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

#define LOG_TAG "javacard.keymint.device.rkp.strongbox-impl"
#include <JavacardRemotelyProvisionedComponentDevice.h>
#include <android-base/logging.h>
#include <KeyMintUtils.h>
#include <aidl/android/hardware/security/keymint/MacedPublicKey.h>
#include <keymaster/cppcose/cppcose.h>
#include <keymaster/remote_provisioning_utils.h>

namespace aidl::android::hardware::security::keymint {
using namespace cppcose;
using namespace keymaster;
using namespace cppbor;
// RKP error codes defined in keymint applet.
constexpr keymaster_error_t kStatusFailed = static_cast<keymaster_error_t>(32000);
constexpr keymaster_error_t kStatusInvalidMac = static_cast<keymaster_error_t>(32001);
constexpr keymaster_error_t kStatusProductionKeyInTestRequest = static_cast<keymaster_error_t>(32002);
constexpr keymaster_error_t kStatusTestKeyInProductionRequest = static_cast<keymaster_error_t>(32003);
constexpr keymaster_error_t kStatusInvalidEek = static_cast<keymaster_error_t>(32004);
constexpr keymaster_error_t kStatusInvalidState = static_cast<keymaster_error_t>(32005);

namespace {

keymaster_error_t translateRkpErrorCode(keymaster_error_t error) {
    switch(static_cast<int32_t>(-error)) {
        case kStatusFailed:
        case kStatusInvalidState:
            return static_cast<keymaster_error_t>(BnRemotelyProvisionedComponent::STATUS_FAILED);
        case kStatusInvalidMac:
            return static_cast<keymaster_error_t>(BnRemotelyProvisionedComponent::STATUS_INVALID_MAC);
        case kStatusProductionKeyInTestRequest:
            return static_cast<keymaster_error_t>(BnRemotelyProvisionedComponent::STATUS_PRODUCTION_KEY_IN_TEST_REQUEST);
        case kStatusTestKeyInProductionRequest:
            return static_cast<keymaster_error_t>(BnRemotelyProvisionedComponent::STATUS_TEST_KEY_IN_PRODUCTION_REQUEST);
        case kStatusInvalidEek:
            return static_cast<keymaster_error_t>(BnRemotelyProvisionedComponent::STATUS_INVALID_EEK);
    }
    return error;
}

ScopedAStatus defaultHwInfo(RpcHardwareInfo* info) {
    info->versionNumber = 1;
    info->rpcAuthorName = "Google";
    info->supportedEekCurve = RpcHardwareInfo::CURVE_P256;
    return ScopedAStatus::ok();
}

uint32_t coseKeyEncodedSize(const std::vector<MacedPublicKey>& keysToSign) {
    uint32_t size = 0;
    for(auto& macKey : keysToSign) {
        auto [macedKeyItem, _, coseMacErrMsg] =
            cppbor::parse(macKey.macedKey);
        if (!macedKeyItem || !macedKeyItem->asArray() ||
            macedKeyItem->asArray()->size() != kCoseMac0EntryCount) {
            LOG(ERROR) << "Invalid COSE_Mac0 structure";
            return 0;
        }
        auto payload = macedKeyItem->asArray()->get(kCoseMac0Payload)->asBstr();
        if (!payload) return 0;
        size += payload->value().size();
    }
    return size;
}

} // namespace

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::getHardwareInfo(RpcHardwareInfo* info) {
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_RKP_HARDWARE_INFO);
    uint32_t versionNumber;
    uint32_t supportedEekCurve;
    if (err != KM_ERROR_OK ||
        !cbor_.getUint64<uint32_t>(item, 1, versionNumber) ||
        !cbor_.getBinaryArray(item, 2, info->rpcAuthorName ) ||
        !cbor_.getUint64<uint32_t>(item, 3, supportedEekCurve)) {
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        return defaultHwInfo(info);
    }
    info->versionNumber = static_cast<int32_t>(versionNumber);
    info->supportedEekCurve = static_cast<int32_t>(supportedEekCurve);
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateEcdsaP256KeyPair(bool testMode,
                                                MacedPublicKey* macedPublicKey,
                                                std::vector<uint8_t>* privateKeyHandle) {
    cppbor::Array array;
    array.add(testMode);
    auto [item, err] = card_->sendRequest(Instruction::INS_GENERATE_RKP_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending generateEcdsaP256KeyPair.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    if (!cbor_.getBinaryArray(item, 1, macedPublicKey->macedKey) ||
        !cbor_.getBinaryArray(item, 2, *privateKeyHandle)) {
         LOG(ERROR) << "Error in decoding og response in generateEcdsaP256KeyPair.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::beginSendData(
    bool testMode, const std::vector<MacedPublicKey>& keysToSign) {
    uint32_t totalEncodedSize = coseKeyEncodedSize(keysToSign);
    cppbor::Array array;
    array.add(keysToSign.size());
    array.add(totalEncodedSize);
    array.add(testMode);
    auto [_, err] = card_->sendRequest(Instruction::INS_BEGIN_SEND_DATA_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in beginSendData.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::updateMacedKey(
    const std::vector<MacedPublicKey>& keysToSign) {
    for(auto& macedPublicKey : keysToSign) {
        cppbor::Array array;
        array.add(EncodedItem(macedPublicKey.macedKey));
        auto [_, err] = card_->sendRequest(Instruction::INS_UPDATE_KEY_CMD, array);
        if (err != KM_ERROR_OK) {
            LOG(ERROR) << "Error in updateMacedKey.";
            return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
        }
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::updateChallenge(
    const std::vector<uint8_t>& challenge) {
    Array array;
    array.add(challenge);
    auto [_, err] = card_->sendRequest(Instruction::INS_UPDATE_CHALLENGE_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in updateChallenge.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::updateEEK(
    const std::vector<uint8_t>& endpointEncCertChain) {
    std::vector<uint8_t> eekChain = endpointEncCertChain;
    auto [_, err] = card_->sendRequest(Instruction::INS_UPDATE_EEK_CHAIN_CMD, eekChain);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in updateEEK.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::finishSendData(
    std::vector<uint8_t>* keysToSignMac, DeviceInfo* deviceInfo,
    std::vector<uint8_t>& coseEncryptProtectedHeader, cppbor::Map& coseEncryptUnProtectedHeader,
    std::vector<uint8_t>& partialCipheredData, uint32_t& respFlag) {

    std::vector<uint8_t> decodedKeysToSignMac;
    std::vector<uint8_t> decodedDeviceInfo;
    auto [item, err] = card_->sendRequest(Instruction::INS_FINISH_SEND_DATA_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in finishSendData.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    if (!cbor_.getBinaryArray(item, 1, decodedKeysToSignMac) ||
        !cbor_.getBinaryArray(item, 2, decodedDeviceInfo) ||
        !cbor_.getBinaryArray(item, 3, coseEncryptProtectedHeader) ||
        !cbor_.getMapItem(item, 4, coseEncryptUnProtectedHeader) ||
        !cbor_.getBinaryArray(item, 5, partialCipheredData) ||
        !cbor_.getUint64(item, 6, respFlag)) {
         LOG(ERROR) << "Error in decoding og response in finishSendData.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    *keysToSignMac = decodedKeysToSignMac;
    deviceInfo->deviceInfo = decodedDeviceInfo;
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::getResponse(
    std::vector<uint8_t>& partialCipheredData, cppbor::Array& recepientStructure,
    uint32_t& respFlag) {
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_RESPONSE_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in getResponse.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    if (!cbor_.getBinaryArray(item, 1, partialCipheredData) ||
        !cbor_.getArrayItem(item, 2, recepientStructure) ||
        !cbor_.getUint64(item, 3, respFlag)) {
         LOG(ERROR) << "Error in decoding og response in getResponse.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateCertificateRequest(bool testMode,
                                        const std::vector<MacedPublicKey>& keysToSign,
                                        const std::vector<uint8_t>& endpointEncCertChain,
                                        const std::vector<uint8_t>& challenge,
                                        DeviceInfo* deviceInfo, ProtectedData* protectedData,
                                        std::vector<uint8_t>* keysToSignMac) {
    std::vector<uint8_t> coseEncryptProtectedHeader;
    cppbor::Map coseEncryptUnProtectedHeader;
    cppbor::Array recipients;
    std::vector<uint8_t> cipheredData;
    uint32_t respFlag;
    auto ret = beginSendData(testMode, keysToSign);
    if (!ret.isOk()) return ret;

    ret = updateMacedKey(keysToSign);
    if (!ret.isOk()) return ret;

    ret = updateChallenge(challenge);
    if (!ret.isOk()) return ret;

    ret = updateEEK(endpointEncCertChain);
    if (!ret.isOk()) return ret;

    ret = finishSendData(keysToSignMac, deviceInfo, coseEncryptProtectedHeader,
                         coseEncryptUnProtectedHeader, cipheredData,
                         respFlag);
    if (!ret.isOk()) return ret;

    while (respFlag != 0) { // more data is pending to receive
        ret = getResponse(cipheredData, recipients, respFlag);
        if (!ret.isOk()) return ret;
    }
    // Create ConseEncrypt structure.
    protectedData->protectedData =
        cppbor::Array()
            .add(coseEncryptProtectedHeader)    // Protected
            .add(std::move(coseEncryptUnProtectedHeader))  // Unprotected
            .add(cipheredData)           // Payload
            .add(std::move(recipients))
            .encode();
    return ScopedAStatus::ok();
}

} // namespace aidl::android::hardware::security::keymint
