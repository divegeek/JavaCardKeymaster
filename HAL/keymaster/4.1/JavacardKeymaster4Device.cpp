/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include <iostream>
#include <climits>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <Transport.h>
#include <JavacardKeymaster4Device.h>

//#define JAVACARD_KEYMASTER_NAME      "JavacardKeymaster4.1Device v0.1"
//#define JAVACARD_KEYMASTER_AUTHOR    "Android Open Source Project"
#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

namespace keymaster {
namespace V4_1 {
namespace javacard {


enum class Instruction {
     INS_GENERATE_KEY_CMD = 0x10,
     INS_IMPORT_KEY_CMD = 0x11,
     INS_IMPORT_WRAPPED_KEY_CMD = 0x12,
     INS_EXPORT_KEY_CMD = 0x13,
     INS_ATTEST_KEY_CMD = 0x14,
     INS_UPGRADE_KEY_CMD = 0x15,
     INS_DELETE_KEY_CMD = 0x16,
     INS_DELETE_ALL_KEYS_CMD = 0x17,
     INS_ADD_RNG_ENTROPY_CMD = 0x18,
     INS_COMPUTE_SHARED_HMAC_CMD = 0x19,
     INS_DESTROY_ATT_IDS_CMD = 0x1A,
     INS_VERIFY_AUTHORIZATION_CMD = 0x1B,
     INS_GET_HMAC_SHARING_PARAM_CMD = 0x1C,
     INS_GET_KEY_CHARACTERISTICS_CMD = 0x1D,
     INS_GET_HW_INFO_CMD = 0x1E,
     INS_BEGIN_OPERATION_CMD = 0x1F,
     INS_UPDATE_OPERATION_CMD = 0x20,
     INS_FINISH_OPERATION_CMD = 0x21,
     INS_ABORT_OPERATION_CMD = 0x22,
     INS_PROVISION_CMD = 0x23,
     INS_DEVICE_LOCKED_CMD = 0x24,
     INS_EARLY_BOOT_ENDED_CMD = 0x25
};

ErrorCode constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut) {
    apduOut.push_back(static_cast<uint8_t>(APDU_CLS)); //CLS
    apduOut.push_back(static_cast<uint8_t>(ins)); //INS
    apduOut.push_back(static_cast<uint8_t>(APDU_P1)); //P1
    apduOut.push_back(static_cast<uint8_t>(APDU_P2)); //P2

    if(UCHAR_MAX < inputData.size() && USHRT_MAX >= inputData.size()) {
        //Extended length 3 bytes, starts with 0x00
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(inputData.size() >> 8));
        apduOut.push_back(static_cast<uint8_t>(inputData.size() & 0xFF));
        //Data
        apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        //Expected length of output
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));//Accepting complete length of output at a time
    } else if(0 <= inputData.size() && UCHAR_MAX >= inputData.size()) {
        //Short length
        apduOut.push_back(static_cast<uint8_t>(inputData.size()));
        //Data
        if(inputData.size() > 0)
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        //Expected length of output
        apduOut.push_back(static_cast<uint8_t>(0x00));//Accepting complete length of output at a time

    } else {
        return (ErrorCode::INSUFFICIENT_BUFFER_SPACE);
    }

    return (ErrorCode::OK);//success
}

uint16_t getStatus(std::vector<uint8_t>& inputData) {
	//Last two bytes are the status SW0SW1
    return (inputData.at(inputData.size()-2) << 8) | (inputData.at(inputData.size()-1));
}

inline ErrorCode sendData(std::unique_ptr<se_transport::TransportFactory>& transport, Instruction ins, std::vector<uint8_t>& inData,
std::vector<uint8_t>& response) {
    std::vector<uint8_t> apdu;
    ErrorCode ret = constructApduMessage(ins, inData, apdu);
    if(ret != ErrorCode::OK) return ret;

    //if(!transport->openConnection()) {
    //    return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    //}

    if(!transport->sendData(apdu.data(), apdu.size(), response)) {
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    if((response.size() < 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return (ErrorCode::UNKNOWN_ERROR);
    }
    return (ErrorCode::OK);//success
}

// Methods from IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    //_hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
	std::vector<uint8_t> resp;
	std::vector<uint8_t> input;
    const uint8_t* pos;
	std::unique_ptr<Item> item;
    std::string message;
	uint64_t securityLevel = static_cast<uint64_t>(SecurityLevel::STRONGBOX);
	hidl_string jcKeymasterName;
	hidl_string jcKeymasterAuthor;

    ErrorCode ret = sendData(pTransportFactory, Instruction::INS_GET_HW_INFO_CMD, input, resp);

    if((ret == ErrorCode::OK) && (resp.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(resp.begin(), resp.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            std::vector<uint8_t> temp;
            cborConverter_.getUint64(item, 0, securityLevel); //SecurityLevel
            cborConverter_.getBinaryArray(item, 1, temp);
            jcKeymasterName = std::string(temp.begin(), temp.end());
            temp.clear();
            cborConverter_.getBinaryArray(item, 2, temp);
            jcKeymasterAuthor = std::string(temp.begin(), temp.end());
        }
    }
    _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
    return Void();
}

Return<void> JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    std::vector<uint8_t> cborData;
    const uint8_t* pos;
	std::vector<uint8_t> input;
    std::unique_ptr<Item> item;
    std::string message;
    HmacSharingParameters hmacSharingParameters;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(pTransportFactory, Instruction::INS_GET_HMAC_SHARING_PARAM_CMD, input, cborData);

    if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborData.begin(), cborData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Error Code
            cborConverter_.getHmacSharingParameters(item, 1, hmacSharingParameters); //HmacSharingParameters.
        }
    }
    _hidl_cb(errorCode, hmacSharingParameters);
    return Void();
}

Return<void> JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
	std::vector<uint8_t> cborOutData;
    std::string message;
    hidl_vec<uint8_t> sharingCheck;

    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> tempVec;
    cppbor::Array innerArray;
    for(size_t i = 0; i < params.size(); ++i) {
        innerArray.add(static_cast<std::vector<uint8_t>>(params[i].seed));
        for(size_t j = 0; i < params[j].nonce.size(); j++) {
            tempVec.push_back(params[i].nonce[j]);
        }
        innerArray.add(tempVec);
        tempVec.clear();
    }
    array.add(std::move(innerArray));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_COMPUTE_SHARED_HMAC_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Error Code
            cborConverter_.getBinaryArray(item, 1, bstr);
            sharingCheck.setToExternal(bstr.data(), bstr.size());
        }
    }
    _hidl_cb(errorCode, sharingCheck);
    return Void();
}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t operationHandle, const hidl_vec<KeyParameter>& parametersToVerify, const HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    std::string message;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    VerificationToken verificationToken;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, parametersToVerify);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_VERIFY_AUTHORIZATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getVerificationToken(item, 1, verificationToken);
        }
    }
    _hidl_cb(errorCode, verificationToken);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    const uint8_t* pos;
    cppbor::Array array;
    std::vector<uint8_t> cborOutData;
    std::unique_ptr<Item> item;
    std::string message;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(std::vector<uint8_t>(data));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_ADD_RNG_ENTROPY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::generateKey(const hidl_vec<KeyParameter>& keyParams, generateKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;

    cborConverter_.addKeyparameters(array, keyParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_GENERATE_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            /* TODO keyBlob is BSTR <ARRAY> */
            cborConverter_.getBinaryArray(item, 1, bstr);
            keyBlob.setToExternal(bstr.data(), bstr.size());
            cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importKey(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;

    cborConverter_.addKeyparameters(array, keyParams);
    array.add(static_cast<uint64_t>(keyFormat));
    array.add(std::vector<uint8_t>(keyData));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_IMPORT_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            /* TODO keyBlob is BSTR <ARRAY> */
            cborConverter_.getBinaryArray(item, 1, bstr);
            keyBlob.setToExternal(bstr.data(), bstr.size());
            cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob, const hidl_vec<uint8_t>& maskingKey, const hidl_vec<KeyParameter>& unwrappingParams, uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;

    array.add(std::vector<uint8_t>(wrappedKeyData));
    array.add(std::vector<uint8_t>(wrappingKeyBlob));
    array.add(std::vector<uint8_t>(maskingKey));
    cborConverter_.addKeyparameters(array, unwrappingParams);
    array.add(passwordSid);
    array.add(biometricSid); /* TODO if biometricSid optional if user not sent this don't encode this cbor format */
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_IMPORT_WRAPPED_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            /* TODO keyBlob is BSTR <ARRAY> */
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getBinaryArray(item, 1, bstr);
            keyBlob.setToExternal(bstr.data(), bstr.size());
            cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);

    return Void();
}

Return<void> JavacardKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;

    array.add(std::vector<uint8_t>(keyBlob));
    array.add(std::vector<uint8_t>(clientId));
    array.add(std::vector<uint8_t>(appData));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_GET_KEY_CHARACTERISTICS_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getKeyCharacteristics(item, 1, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::exportKey(KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyMaterial;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(static_cast<uint64_t>(keyFormat));
    array.add(std::vector<uint8_t>(keyBlob));
    array.add(std::vector<uint8_t>(clientId));
    array.add(std::vector<uint8_t>(appData));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_EXPORT_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            /* TODO Keyblobc - BSTR(<ARRAY>)*/
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getBinaryArray(item, 1, bstr);
            keyMaterial.setToExternal(bstr.data(), bstr.size());
        }
    }
    _hidl_cb(errorCode, keyMaterial);
    return Void();
}

Return<void> JavacardKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<KeyParameter>& attestParams, attestKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    hidl_vec<hidl_vec<uint8_t>> certChain;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyToAttest));
    cborConverter_.addKeyparameters(array, attestParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_ATTEST_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getMultiBinaryArray(item, 1, certChain);
        }
    }
    _hidl_cb(errorCode, certChain);
    return Void();
}

Return<void> JavacardKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> upgradedKeyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyBlobToUpgrade));
    cborConverter_.addKeyparameters(array, upgradeParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_UPGRADE_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            /* TODO Keyblob BSTR(ARRAY) */
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getBinaryArray(item, 1, bstr);
            upgradedKeyBlob.setToExternal(bstr.data(), bstr.size());
        }
    }
    _hidl_cb(errorCode, upgradedKeyBlob);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyBlob));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_DELETE_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

Return<ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> input;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(pTransportFactory, Instruction::INS_DELETE_ALL_KEYS_CMD, input, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

Return<ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> input;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(pTransportFactory, Instruction::INS_DESTROY_ATT_IDS_CMD, input, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams, const HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<KeyParameter> outParams;
    uint64_t operationHandle = 0;

    if (KeyPurpose::ENCRYPT == purpose ||
        KeyPurpose::VERIFY == purpose) {
        /* Public key operations are handled here*/
    } else {
        cppbor::Array array;
        const uint8_t* pos;
        std::vector<uint8_t> cborOutData;
        std::unique_ptr<Item> item;
        std::string message;

        /* Convert input data to cbor format */
        array.add(static_cast<uint64_t>(purpose));
        array.add(std::vector<uint8_t>(keyBlob));
        cborConverter_.addKeyparameters(array, inParams);
        cborConverter_.addHardwareAuthToken(array, authToken);
        std::vector<uint8_t> cborData = array.encode();

        errorCode = sendData(pTransportFactory, Instruction::INS_BEGIN_OPERATION_CMD, cborData, cborOutData);

        if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
            std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
            if (item != nullptr) {
                cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
                cborConverter_.getKeyParameters(item, 1, outParams);
                cborConverter_.getUint64(item, 2, operationHandle);
            }
        }
    }
    _hidl_cb(errorCode, outParams, operationHandle);
    return Void();
}

Return<void> JavacardKeymaster4Device::update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, update_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<KeyParameter> outParams;
    uint32_t inputConsumed = 0;
    hidl_vec<uint8_t> output;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, inParams);
    array.add(std::vector<uint8_t>(input));
    cborConverter_.addHardwareAuthToken(array, authToken);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_UPDATE_OPERATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getUint64(item, 1, inputConsumed);
            cborConverter_.getKeyParameters(item, 2, outParams);
            cborConverter_.getBinaryArray(item, 3, bstr);
            output.setToExternal(bstr.data(), bstr.size());
        }
    }
    _hidl_cb(errorCode, inputConsumed, outParams, output);
    return Void();
}

Return<void> JavacardKeymaster4Device::finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, finish_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, inParams);
    array.add(std::vector<uint8_t>(input));
    array.add(std::vector<uint8_t>(signature));
    cborConverter_.addHardwareAuthToken(array, authToken);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_FINISH_OPERATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getKeyParameters(item, 1, outParams);
            cborConverter_.getBinaryArray(item, 2, bstr);
            output.setToExternal(bstr.data(), bstr.size());
        }
    }
    _hidl_cb(errorCode, outParams, output);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::abort(uint64_t operationHandle) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(pTransportFactory, Instruction::INS_ABORT_OPERATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode<ErrorCode>(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

// Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::deviceLocked(bool passwordOnly, const VerificationToken& verificationToken) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(passwordOnly);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    /* TODO DeviceLocked command handled inside HAL */
    ErrorCode ret = sendData(pTransportFactory, Instruction::INS_DEVICE_LOCKED_CMD, cborData, cborOutData);

    if((ret == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::earlyBootEnded() {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> cborInput;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;

    ErrorCode ret = sendData(pTransportFactory, Instruction::INS_EARLY_BOOT_ENDED_CMD, cborInput, cborOutData);

    if((ret == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::tie(item, pos, message) = parse(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2));//Skip last 2 bytes, it is status.
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        }
    }
    return errorCode;
}

}  // javacard
}  // namespace V4_1
}  // namespace keymaster
