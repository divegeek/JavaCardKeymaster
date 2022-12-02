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

#include "JavacardRemotelyProvisionedComponentDevice.h"

#include <aidl/android/hardware/security/keymint/MacedPublicKey.h>

#include <android-base/logging.h>
#include <keymaster/cppcose/cppcose.h>
#include <keymaster/remote_provisioning_utils.h>

#include "JavacardKeyMintUtils.h"

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
    info->versionNumber = 3;
    info->rpcAuthorName = "Google";
    info->supportedEekCurve = RpcHardwareInfo::CURVE_P256;
    info->uniqueId = "strongbox keymint";
    info->supportedNumKeysInCsr = RpcHardwareInfo::MIN_SUPPORTED_NUM_KEYS_IN_CSR;
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
    std::optional<uint32_t> optVersionNumber;
    std::optional<uint32_t> optSupportedEekCurve;
    std::optional<string> optRpcAuthorName;
    std::optional<string> optUniqueId;
    std::optional<uint32_t> optMinSupportedKeysInCsr;
    if (err != KM_ERROR_OK ||
        !(optVersionNumber = cbor_.getUint64<uint32_t>(item, 1)) ||
        !(optRpcAuthorName = cbor_.getByteArrayStr(item, 2)) ||
        !(optSupportedEekCurve = cbor_.getUint64<uint32_t>(item, 3)) ||
        !(optUniqueId = cbor_.getByteArrayStr(item, 4)) ||
        !(optMinSupportedKeysInCsr = cbor_.getUint64<uint32_t>(item, 5))) {
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        return defaultHwInfo(info);
    }
    info->rpcAuthorName = std::move(optRpcAuthorName.value());
    info->versionNumber = static_cast<int32_t>(std::move(optVersionNumber.value()));
    info->supportedEekCurve = static_cast<int32_t>(std::move(optSupportedEekCurve.value()));
    info->uniqueId = std::move(optUniqueId.value());
    info->supportedNumKeysInCsr = static_cast<int32_t>(std::move(optMinSupportedKeysInCsr.value()));
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateEcdsaP256KeyPair(bool,
                                                MacedPublicKey* macedPublicKey,
                                                std::vector<uint8_t>* privateKeyHandle) {
    auto [item, err] = card_->sendRequest(Instruction::INS_GENERATE_RKP_KEY_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending generateEcdsaP256KeyPair.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    std::optional<std::vector<uint8_t>> optMacedKey;
    std::optional<std::vector<uint8_t>> optPKeyHandle;
    if (!(optMacedKey = cbor_.getByteArrayVec(item, 1)) ||
        !(optPKeyHandle = cbor_.getByteArrayVec(item, 2))) {
         LOG(ERROR) << "Error in decoding og response in generateEcdsaP256KeyPair.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    *privateKeyHandle = std::move(optPKeyHandle.value());
    macedPublicKey->macedKey = std::move(optMacedKey.value());
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::beginSendData(const std::vector<MacedPublicKey>& keysToSign, 
    const std::vector<uint8_t>& challenge, DeviceInfo* deviceInfo, uint32_t* version,
    std::string* certificateType) {
    uint32_t totalEncodedSize = coseKeyEncodedSize(keysToSign);
    cppbor::Array array;
    array.add(keysToSign.size());
    array.add(totalEncodedSize);
    array.add(challenge);
    auto [item, err] = card_->sendRequest(Instruction::INS_BEGIN_SEND_DATA_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in beginSendData.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    auto optDecodedDeviceInfo = cbor_.getByteArrayVec(item, 1);
    if (!optDecodedDeviceInfo) {
         LOG(ERROR) << "Error in decoding deviceInfo response in beginSendData.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    deviceInfo->deviceInfo = std::move(optDecodedDeviceInfo.value());
    auto optVersion = cbor_.getUint64<uint32_t>(item, 2);
    if (!optVersion) {
         LOG(ERROR) << "Error in decoding version in beginSendData.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    *version = optVersion.value();
    auto optCertType = cbor_.getTextStr(item, 3);
    if (!optCertType) {
         LOG(ERROR) << "Error in decoding cert type in beginSendData.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    *certificateType = std::move(optCertType.value());
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::updateMacedKey(
    const std::vector<MacedPublicKey>& keysToSign, Array& coseKeys) {
    for(auto& macedPublicKey : keysToSign) {
        cppbor::Array array;
        array.add(EncodedItem(macedPublicKey.macedKey));
        auto [item, err] = card_->sendRequest(Instruction::INS_UPDATE_KEY_CMD, array);
        if (err != KM_ERROR_OK) {
            LOG(ERROR) << "Error in updateMacedKey.";
            return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
        }
        auto coseKeyData = cbor_.getByteArrayVec(item, 1);
        coseKeys.add(EncodedItem(coseKeyData.value()));
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::finishSendData(
    std::vector<uint8_t>& coseEncryptProtectedHeader, std::vector<uint8_t>& signature, uint32_t& version, uint32_t& respFlag) {

    auto [item, err] = card_->sendRequest(Instruction::INS_FINISH_SEND_DATA_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in finishSendData.";
        return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
    }
    auto optCEncryptProtectedHeader = cbor_.getByteArrayVec(item, 1);
    auto optSignature = cbor_.getByteArrayVec(item, 2);
    auto optVersion = cbor_.getUint64<uint32_t>(item, 3);
    auto optRespFlag = cbor_.getUint64<uint32_t>(item, 4);
    if (!optCEncryptProtectedHeader || !optSignature ||
        !optVersion || !optRespFlag) {
         LOG(ERROR) << "Error in decoding response in finishSendData.";
         return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }

    coseEncryptProtectedHeader = std::move(optCEncryptProtectedHeader.value());
    signature.insert(signature.end(), optSignature->begin(), optSignature->end());
    version = std::move(optVersion.value());
    respFlag = std::move(optRespFlag.value());
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::getDiceCertChain(
    std::vector<uint8_t>& diceCertChain) {
    uint32_t respFlag = 0;
    do {
        auto [item, err] = card_->sendRequest(Instruction::INS_GET_DICE_CERT_CHAIN_CMD);
        if (err != KM_ERROR_OK) {
            LOG(ERROR) << "Error in getDiceCertChain.";
            return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
        }
        auto optDiceCertChain = cbor_.getByteArrayVec(item, 1);
        auto optRespFlag = cbor_.getUint64<uint32_t>(item, 2);
        if (!optDiceCertChain || !optRespFlag) {
            LOG(ERROR) << "Error in decoding response in getDiceCertChain.";
            return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
        }
        respFlag = optRespFlag.value();
        diceCertChain.insert(diceCertChain.end(), optDiceCertChain->begin(), optDiceCertChain->end());
    } while (respFlag != 0);
    return ScopedAStatus::ok();    
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::getUdsCertsChain(
    std::vector<uint8_t>& udsCertsChain) {
    uint32_t respFlag = 0;
    do {
        auto [item, err] = card_->sendRequest(Instruction::INS_GET_UDS_CERTS_CMD);
        if (err != KM_ERROR_OK) {
            LOG(ERROR) << "Error in getUdsCertsChain.";
            return km_utils::kmError2ScopedAStatus(translateRkpErrorCode(err));
        }
        auto optUdsCertData = cbor_.getByteArrayVec(item, 1);
        auto optRespFlag = cbor_.getUint64<uint32_t>(item, 2);
        if (!optUdsCertData || !optRespFlag) {
            LOG(ERROR) << "Error in decoding og response in getUdsCertsChain.";
            return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
        }
        respFlag = optRespFlag.value();
        udsCertsChain.insert(udsCertsChain.end(), optUdsCertData->begin(), optUdsCertData->end());
    } while (respFlag != 0);
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateCertificateRequest(bool,
                                        const std::vector<MacedPublicKey>&,
                                        const std::vector<uint8_t>&,
                                        const std::vector<uint8_t>&,
                                        DeviceInfo*, ProtectedData*,
                                        std::vector<uint8_t>*) {
    return km_utils::kmError2ScopedAStatus(static_cast<keymaster_error_t>(STATUS_REMOVED));    
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateCertificateRequestV2(
                                        const std::vector<MacedPublicKey>& keysToSign,
                                        const std::vector<uint8_t>& challenge,
                                        std::vector<uint8_t>* csr) {
    uint32_t version;
    uint32_t csrPayloadSchemaVersion;
    std::string certificateType;
    uint32_t respFlag;
    DeviceInfo deviceInfo;
    Array coseKeys;
    std::vector<uint8_t> coseEncryptProtectedHeader;
    cppbor::Map coseEncryptUnProtectedHeader;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> diceCertChain;
    std::vector<uint8_t> udsCertChain;
    cppbor::Array payLoad;

    auto ret = beginSendData(keysToSign, challenge, &deviceInfo, &csrPayloadSchemaVersion, &certificateType);
    if (!ret.isOk()) return ret;

    ret = updateMacedKey(keysToSign, coseKeys);
    if (!ret.isOk()) return ret;

    ret = finishSendData(coseEncryptProtectedHeader, signature,
                         version, respFlag);
    if (!ret.isOk()) return ret;

    ret = getUdsCertsChain(udsCertChain);
    if (!ret.isOk()) return ret;

    ret = getDiceCertChain(diceCertChain);
    if (!ret.isOk()) return ret;

    auto payload = cppbor::Array()
            .add(csrPayloadSchemaVersion)
            .add(certificateType)
            .add(EncodedItem(deviceInfo.deviceInfo)) // deviceinfo
            .add(std::move(coseKeys))  // KeysToSign
            .encode();

    auto signDataPayload = cppbor::Array()
            .add(challenge)  // Challenge
            .add(std::move(payload))
            .encode();

    auto signedData = cppbor::Array()
        .add(std::move(coseEncryptProtectedHeader))
        .add(cppbor::Map() /* unprotected parameters */)
        .add(std::move(signDataPayload))
        .add(std::move(signature));

    *csr = cppbor::Array()
        .add(version)
        .add(EncodedItem(udsCertChain))
        .add(EncodedItem(diceCertChain))
        .add(std::move(signedData))
        .encode();

    return ScopedAStatus::ok();
}

} // namespace aidl::android::hardware::security::keymint
