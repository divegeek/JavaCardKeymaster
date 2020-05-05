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

#define LOG_TAG "android.hardware.keymaster@4.1-service.javacard"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <climits>
#include <keymaster/authorization_set.h>
#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <JavacardKeymaster4Device.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <Transport.h>

#define JAVACARD_KEYMASTER_NAME      "JavacardKeymaster4.1Device v0.1"
#define JAVACARD_KEYMASTER_AUTHOR    "Android Open Source Project"

namespace android {
namespace hardware {
namespace keymaster {
namespace V4_1 {

#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

enum class Instruction {
     INS_GENERATE_KEY_CMD = 0x10;
     INS_IMPORT_KEY_CMD = 0x11;
     INS_IMPORT_WRAPPED_KEY_CMD = 0x12;
     INS_EXPORT_KEY_CMD = 0x13;
     INS_ATTEST_KEY_CMD = 0x14;
     INS_UPGRADE_KEY_CMD = 0x15;
     INS_DELETE_KEY_CMD = 0x16;
     INS_DELETE_ALL_KEYS_CMD = 0x17;
     INS_ADD_RNG_ENTROPY_CMD = 0x18;
     INS_COMPUTE_SHARED_HMAC_CMD = 0x19;
     INS_DESTROY_ATT_IDS_CMD = 0x1A;
     INS_VERIFY_AUTHORIZATION_CMD = 0x1B;
     INS_GET_HMAC_SHARING_PARAM_CMD = 0x1C;
     INS_GET_KEY_CHARACTERISTICS_CMD = 0x1D;
     INS_GET_HW_INFO_CMD = 0x1E;
     INS_BEGIN_OPERATION_CMD = 0x1F;
     INS_UPDATE_OPERATION_CMD = 0x20;
     INS_FINISH_OPERATION_CMD = 0x21;
     INS_ABORT_OPERATION_CMD = 0x22;
     INS_PROVISION_CMD = 0x23;
};

bool constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut) {
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
        apduOut.push_back(static_cast<uint8_t>(0x00)); //TODO Max expected out ??
    } else if(0 <= inputData.size() && UCHAR_MAX >= inputData.szie()) {
        //Short length
        apduOut.push_back(static_cast<uint8_t>(inputData.size()));
        //Data
        if(inputData.size() > 0)
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        //Expected length of output
        apduOut.push_back(static_cast<uint8_t>(0x00));//TODO Max expected out ??
    } else {
        return false;
    }

    return true;
}

uint16_t getStatus(std::vector<uint8_t>& inputData) {
	//Last two bytes are the status SW0SW1
    return (inputData.at(inputData.size()-2) << 8) | (inputData.at(inputData.size()-1));
    /*if (status == (uint16_t)APDU_RESP_STATUS_OK) {
        resOut.insert(resOut.begin(), inputData.begin(), inputData.end()-2);
        return true;
    }
    return false;*/
}

JavacardKeymaster4Device::~JavacardKeymaster4Device() {
}

// Methods from IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    //_hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
    std::vector<uint8_t> apdu;
	std::vector<uint8_t> resp;
	std::unique_ptr<Item> item;
    std::string message;
	uint64_t securityLevel;
	hidl_string jcKeymasterName;
	hidl_string jcKeymasterAuthor;

	bool ret;
    ret = constructApduMessage(INS_GET_HW_INFO_CMD, std::vector<uint8_t>(), apdu );
	static_assert(ret, "Failed to get hardware info");

    ret = pTransport->openConnection();
	static_assert(ret, "Failed to open connection with secure element");

    ret = pTransport->sendData(apdu.data(), apdu.size(), resp);
	static_assert(ret, "Failed to send data to secure element");

	static_assert(APDU_RESP_STATUS_OK == getStatus(resp), "Failed to get response from secure element.");

	std::tie(item, pos, message) = parse(std::vector<uint8_t>(resp.begin(), resp.end()-2));//Skip last 2 bytes, it is status.
    if (item != nullptr) {
		std::vector<uint8_t> temp;
        cborConverter_.getUint64(item, 0, securityLevel); //SecurityLevel
		cborConverter_.getBinaryArray(item, 1, temp);
		jcKeymasterName.setToExternal(temp.data(), temp.size());
		temp.clear();
		cborConverter_.getBinaryArray(item, 2, temp);
		jcKeymasterAuthor.setToExternal(temp.data(), temp.size());
    }
    _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
    return Void();
}

Return<void> JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    std::vector<uint8_t> cborData;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::HmacSharingParameters hmacSharingParameters;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    // TODO Call OMAPI layer and get the Cbor format data.

    std::tie(item, pos, message) = parse(cborData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Error Code
        cborConverter_.getHmacSharingParameters(item, 1, hmacSharingParameters); //HmacSharingParameters.
    }
    _hidl_cb(errorCode, hmacSharingParameters);
    return Void();
}

Return<void> JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> sharingCheck;

    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
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

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Error Code
        cborConverter_.getBinaryArray(item, 1, bstr);
        sharingCheck.setToExternal(bstr.data(), bstr.size());
    }
    _hidl_cb(errorCode, sharingCheck);
    return Void();
}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& parametersToVerify, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::keymaster::V4_0::VerificationToken verificationToken;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, parametersToVerify);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getVerificationToken(item, 1, verificationToken);
    }
    _hidl_cb(errorCode, verificationToken);
    return Void();
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    const uint8_t* pos;
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(std::vector<uint8_t>(data));
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::generateKey(const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams, generateKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::keymaster::V4_0::KeyCharacteristics keyCharacteristics;

    cborConverter_.addKeyparameters(array, keyParams);
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        /* TODO keyBlob is BSTR <ARRAY> */
        cborConverter_.getBinaryArray(item, 1, bstr);
        keyBlob.setToExternal(bstr.data(), bstr.size());
        cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importKey(const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams, ::android::hardware::keymaster::V4_0::KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::keymaster::V4_0::KeyCharacteristics keyCharacteristics;

    cborConverter_.addKeyparameters(array, keyParams);
    array.add(static_cast<uint64_t>(keyFormat));
    array.add(std::vector<uint8_t>(keyData));
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.
    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        /* TODO keyBlob is BSTR <ARRAY> */
        cborConverter_.getBinaryArray(item, 1, bstr);
        keyBlob.setToExternal(bstr.data(), bstr.size());
        cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob, const hidl_vec<uint8_t>& maskingKey, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& unwrappingParams, uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::keymaster::V4_0::KeyCharacteristics keyCharacteristics;

    array.add(std::vector<uint8_t>(wrappedKeyData));
    array.add(std::vector<uint8_t>(wrappingKeyBlob));
    array.add(std::vector<uint8_t>(maskingKey));
    cborConverter_.addKeyparameters(array, unwrappingParams);
    array.add(passwordSid);
    array.add(biometricSid); /* TODO if biometricSid optional if user not sent this don't encode this cbor format */
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.
    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        /* TODO keyBlob is BSTR <ARRAY> */
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getBinaryArray(item, 1, bstr);
        keyBlob.setToExternal(bstr.data(), bstr.size());
        cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);

    return Void();
}

Return<void> JavacardKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::keymaster::V4_0::KeyCharacteristics keyCharacteristics;

    array.add(std::vector<uint8_t>(keyBlob));
    array.add(std::vector<uint8_t>(clientId));
    array.add(std::vector<uint8_t>(appData));
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.
    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getKeyCharacteristics(item, 1, keyCharacteristics);
    }
    _hidl_cb(errorCode, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::exportKey(::android::hardware::keymaster::V4_0::KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyMaterial;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    array.add(static_cast<uint64_t>(keyFormat));
    array.add(std::vector<uint8_t>(keyBlob));
    array.add(std::vector<uint8_t>(clientId));
    array.add(std::vector<uint8_t>(appData));
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.
    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        /* TODO Keyblobc - BSTR(<ARRAY>)*/
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getBinaryArray(item, 1, bstr);
        keyMaterial.setToExternal(bstr.data(), bstr.size());
    }
    _hidl_cb(errorCode, keyMaterial);
    return Void();
}

Return<void> JavacardKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& attestParams, attestKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> keyBlob;
    ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>> certChain;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyToAttest));
    cborConverter_.addKeyparameters(array, attestParams);
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.
    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getMultiBinaryArray(item, 1, certChain);
    }
    _hidl_cb(errorCode, certChain);
    return Void();
}

Return<void> JavacardKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    hidl_vec<uint8_t> upgradedKeyBlob;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyBlobToUpgrade));
    cborConverter_.addKeyparameters(array, upgradeParams);
    std::vector<uint8_t> cborData = array.encode();
    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.
    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        /* TODO Keyblob BSTR(ARRAY) */
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getBinaryArray(item, 1, bstr);
        upgradedKeyBlob.setToExternal(bstr.data(), bstr.size());
    }
    _hidl_cb(errorCode, upgradedKeyBlob);
    return Void();
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyBlob));
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;


    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;


    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::begin(::android::hardware::keymaster::V4_0::KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter> outParams;
    uint64_t operationHandle = 0;

    if (::android::hardware::keymaster::V4_0::KeyPurpose::ENCRYPT == purpose ||
        ::android::hardware::keymaster::V4_0::KeyPurpose::VERIFY == purpose) {
        /* Public key operations are handled here*/
    } else {
        cppbor::Array array;
        const uint8_t* pos;
        std::unique_ptr<Item> item;
        std::string message;

        /* Convert input data to cbor format */
        array.add(static_cast<uint64_t>(purpose));
        array.add(std::vector<uint8_t>(keyBlob));
        cborConverter_.addKeyparameters(array, inParams);
        cborConverter_.addHardwareAuthToken(array, authToken);
        std::vector<uint8_t> cborData = array.encode();

        // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

        std::vector<uint8_t> cborOutData; /*Received from OMAPI */
        std::tie(item, pos, message) = parse(cborOutData);
        if (item != nullptr) {
            cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
            cborConverter_.getKeyParameters(item, 1, outParams);
            cborConverter_.getUint64(item, 2, operationHandle);
        }
    }
    _hidl_cb(errorCode, outParams, operationHandle);
    return Void();
}

Return<void> JavacardKeymaster4Device::update(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken, update_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter> outParams;
    uint32_t inputConsumed = 0;
    hidl_vec<uint8_t> output;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, inParams);
    array.add(std::vector<uint8_t>(input));
    cborConverter_.addHardwareAuthToken(array, authToken);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getUint64(item, 1, inputConsumed);
        cborConverter_.getKeyParameters(item, 2, outParams);
        cborConverter_.getBinaryArray(item, 3, bstr);
        output.setToExternal(bstr.data(), bstr.size());
    }
    _hidl_cb(errorCode, inputConsumed, outParams, output);
    return Void();
}

Return<void> JavacardKeymaster4Device::finish(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken, finish_cb _hidl_cb) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;
    ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter> outParams;
    hidl_vec<uint8_t> output;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, inParams);
    array.add(std::vector<uint8_t>(input));
    array.add(std::vector<uint8_t>(signature));
    cborConverter_.addHardwareAuthToken(array, authToken);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        std::vector<uint8_t> bstr;
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
        cborConverter_.getKeyParameters(item, 1, outParams);
        cborConverter_.getBinaryArray(item, 2, bstr);
        output.setToExternal(bstr.data(), bstr.size());
    }
    _hidl_cb(errorCode, outParams, output);
    return Void();
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::abort(uint64_t operationHandle) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_0::ErrorCode errorCode = ::android::hardware::keymaster::V4_0::ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode<::android::hardware::keymaster::V4_0::ErrorCode>(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

// Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::deviceLocked(bool passwordOnly, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken) {
    cppbor::Array array;
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(passwordOnly);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::earlyBootEnded() {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;

    // TODO Call OMAPI layer and sent the cbor data and get the Cbor format data back.

    std::vector<uint8_t> cborOutData; /*Received from OMAPI */
    std::tie(item, pos, message) = parse(cborOutData);
    if (item != nullptr) {
        cborConverter_.getErrorCode(item, 0, errorCode); //Errorcode
    }
    return errorCode;
}

}  // namespace V4_1
}  // namespace keymaster
}  // namespace hardware
}  // namespace android
