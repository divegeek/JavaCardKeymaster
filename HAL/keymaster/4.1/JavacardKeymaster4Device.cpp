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

#include <climits>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <Transport.h>
#include <keymaster/key_blob_utils/software_keyblobs.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/wrapped_key.h>
#include <openssl/aes.h>

#include <JavacardKeymaster4Device.h>
#include <java_card_soft_keymaster_context.h>
#include <CommonUtils.h>
#include <android-base/logging.h>

#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000
#define ROOT_RSA_KEY   "/data/data/rsa_key.der"
#define ROOT_RSA_CERT  "/data/data/certificate_rsa.der"
/*This property is used to check if javacard is already provisioned or not */
#define KM_JAVACARD_PROVISIONED_PROPERTY "keymaster.javacard.provisioned"

namespace keymaster {
namespace V4_1 {
namespace javacard {

static std::unique_ptr<se_transport::TransportFactory> pTransportFactory = nullptr;
constexpr size_t kOperationTableSize = 16;

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
    INS_SET_BOOT_PARAMS_CMD = 0x24,
    INS_DEVICE_LOCKED_CMD = 0x25,
    INS_EARLY_BOOT_ENDED_CMD = 0x26,
};

static inline std::unique_ptr<se_transport::TransportFactory>& getTransportFactoryInstance() {
    if(pTransportFactory == nullptr) {
        pTransportFactory = std::unique_ptr<se_transport::TransportFactory>(new se_transport::TransportFactory(
                    android::base::GetBoolProperty("ro.kernel.qemu", false)));
    }
    return pTransportFactory;
}

ErrorCode prepareCborArrayFromRawKey(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>& blob, cppbor::Array&
        array) {
    ErrorCode errorCode = ErrorCode::OK;
    AuthorizationSet paramSet;
    keymaster_algorithm_t algorithm;
    if(keyFormat == KeyFormat::PKCS8) {

        paramSet.Reinitialize(KmParamSet(keyParams));
        paramSet.GetTagValue(TAG_ALGORITHM, &algorithm);

        if(KM_ALGORITHM_RSA == algorithm) {
            std::vector<uint8_t> privExp;
            std::vector<uint8_t> modulus;
            if(ErrorCode::OK != (errorCode = rsaRawKeyFromPKCS8(std::vector<uint8_t>(blob), privExp, modulus))) {
                return errorCode;
            }
            array.add(privExp);
            array.add(modulus);
        } else if(KM_ALGORITHM_EC == algorithm) {
            std::vector<uint8_t> privKey;
            std::vector<uint8_t> pubKey;
            EcCurve curve;
            if(ErrorCode::OK != (errorCode = ecRawKeyFromPKCS8(std::vector<uint8_t>(blob), privKey, pubKey, curve))) {
                return errorCode;
            }
            array.add(privKey);
            array.add(pubKey);
        } else {
            return ErrorCode::UNSUPPORTED_ALGORITHM;
        }
    } else if(keyFormat == KeyFormat::RAW) {
        array.add(std::vector<uint8_t>(blob));
    }
    return errorCode;
}

ErrorCode parseWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, std::vector<uint8_t>& iv, std::vector<uint8_t>& transitKey,
std::vector<uint8_t>& secureKey, std::vector<uint8_t>& tag, hidl_vec<KeyParameter>& authList, KeyFormat&
keyFormat, std::vector<uint8_t>& wrappedKeyDescription) {
    KeymasterBlob kmIv;
    KeymasterKeyBlob kmTransitKey;
    KeymasterKeyBlob kmSecureKey;
    KeymasterBlob kmTag;
    AuthorizationSet authSet;
    keymaster_key_format_t kmKeyFormat;
    KeymasterBlob kmWrappedKeyDescription;

    size_t keyDataLen = wrappedKeyData.size();
    uint8_t *keyData = dup_buffer(wrappedKeyData.data(), keyDataLen);
    keymaster_key_blob_t keyMaterial = {keyData, keyDataLen};

    keymaster_error_t error = parse_wrapped_key(KeymasterKeyBlob(keyMaterial), &kmIv, &kmTransitKey,
                                                &kmSecureKey, &kmTag, &authSet,
                                                &kmKeyFormat, &kmWrappedKeyDescription);
    if (error != KM_ERROR_OK) return legacy_enum_conversion(error);
    blob2Vec(kmIv.data, kmIv.data_length, iv);
    blob2Vec(kmTransitKey.key_material, kmTransitKey.key_material_size, transitKey);
    blob2Vec(kmSecureKey.key_material, kmSecureKey.key_material_size, secureKey);
    blob2Vec(kmTag.data, kmTag.data_length, tag);
    authList = kmParamSet2Hidl(authSet);
    keyFormat = static_cast<KeyFormat>(kmKeyFormat);
    blob2Vec(kmWrappedKeyDescription.data, kmWrappedKeyDescription.data_length, wrappedKeyDescription);

    return ErrorCode::OK;
}

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

bool readDataFromFile(const char *filename, std::vector<uint8_t>& data) {
    FILE *fp;
    bool ret = true;
    fp = fopen(filename, "rb");
    if(fp == NULL) {
        LOG(ERROR) << "Failed to open file: " << filename;
        return false;
    }
    fseek(fp, 0L, SEEK_END);
    long int filesize = ftell(fp);
    rewind(fp);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[filesize]);
    if( 0 == fread(buf.get(), filesize, 1, fp)) {
        LOG(ERROR) << "No Content in the file: " << filename;
        ret = false;
    }
    if(true == ret) {
        data.insert(data.begin(), buf.get(), buf.get() + filesize);
    }
    fclose(fp);
    return ret;
}

ErrorCode initiateProvision() {
    /* This is just a reference implemenation */
    std::string brand("Google");
    std::string device("Pixel 3A");
    std::string product("Pixel");
    std::string serial("UGYJFDjFeRuBEH");
    std::string imei("987080543071019");
    std::string meid("27863510227963");
    std::string manufacturer("Foxconn");
    std::string model("HD1121");
    AuthorizationSet authSet(AuthorizationSetBuilder()
            .Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA)
            .Authorization(TAG_ATTESTATION_ID_BRAND, brand.data(), brand.size())
            .Authorization(TAG_ATTESTATION_ID_DEVICE, device.data(), device.size())
            .Authorization(TAG_ATTESTATION_ID_PRODUCT, product.data(), product.size())
            .Authorization(TAG_ATTESTATION_ID_SERIAL, serial.data(), serial.size())
            .Authorization(TAG_ATTESTATION_ID_IMEI, imei.data(), imei.size())
            .Authorization(TAG_ATTESTATION_ID_MEID, meid.data(), meid.size())
            .Authorization(TAG_ATTESTATION_ID_MANUFACTURER, manufacturer.data(), manufacturer.size())
            .Authorization(TAG_ATTESTATION_ID_MODEL, model.data(), model.size()));

    hidl_vec<KeyParameter> keyParams = kmParamSet2Hidl(authSet);
    std::vector<uint8_t> data;
    if(!readDataFromFile(ROOT_RSA_KEY, data)) {
        LOG(ERROR) << " Failed to read the Root rsa key";
        return ErrorCode::UNKNOWN_ERROR;
    }
    return JavacardKeymaster4Device::provision(keyParams, KeyFormat::PKCS8, data);
}

Return<ErrorCode> setBootParams() {
    std::vector<uint8_t> verifiedBootKey(32, 0);
    std::vector<uint8_t> verifiedBootKeyHash(32, 0);

    return JavacardKeymaster4Device::setBootParams(GetOsVersion(), GetOsPatchlevel(), verifiedBootKey, verifiedBootKeyHash,
    KM_VERIFIED_BOOT_UNVERIFIED, 0/*deviceLocked*/);
}

ErrorCode sendData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response) {
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> apdu;

    if(!android::base::GetBoolProperty(KM_JAVACARD_PROVISIONED_PROPERTY, false)) {
        if(ErrorCode::OK != (ret = setBootParams())) {
            LOG(ERROR) << "Failed to set boot params";
            return ret;
        }

        if(ErrorCode::OK != (ret = initiateProvision())) {
            LOG(ERROR) << "Failed to provision the device";
            return ret;
        }
        android::base::SetProperty(KM_JAVACARD_PROVISIONED_PROPERTY, "true");
    }

    ret = constructApduMessage(ins, inData, apdu);
    if(ret != ErrorCode::OK) return ret;

    if(!getTransportFactoryInstance()->sendData(apdu.data(), apdu.size(), response)) {
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    if((response.size() < 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return (ErrorCode::UNKNOWN_ERROR);
    }
    return (ErrorCode::OK);//success
}

ErrorCode JavacardKeymaster4Device::provision(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>&
keyData) {
    cppbor::Array array;
    cppbor::Array subArray;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> apdu;
    hidl_vec<uint8_t> keyBlob;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    Instruction ins = Instruction::INS_PROVISION_CMD;
    std::vector<uint8_t> response;
    CborConverter cborConverter;

    if(ErrorCode::OK != (errorCode = prepareCborArrayFromRawKey(keyParams, keyFormat, keyData, subArray))) {
        return errorCode;
    }
    /* construct cbor */
    cborConverter.addKeyparameters(array, keyParams);
    array.add(static_cast<uint32_t>(keyFormat));
    std::vector<uint8_t> encodedArray = subArray.encode();
    cppbor::Bstr bstr(encodedArray.begin(), encodedArray.end());
    array.add(bstr);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = constructApduMessage(ins, cborData, apdu)))
        return errorCode;

    if(!getTransportFactoryInstance()->sendData(apdu.data(), apdu.size(), response)) {
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    if((response.size() < 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return (ErrorCode::UNKNOWN_ERROR);
    }

    if((response.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter.decodeData(std::vector<uint8_t>(response.begin(), response.end()-2),
                true);
    }
    return errorCode;
}

ErrorCode JavacardKeymaster4Device::setBootParams(uint32_t osVersion, uint32_t osPatchLevel, const std::vector<uint8_t>& verifiedBootKey,
std::vector<uint8_t>& verifiedBootKeyHash, keymaster_verified_boot_t kmVerifiedBoot, bool deviceLocked) {
    cppbor::Array array;
    std::vector<uint8_t> apdu;
    std::vector<uint8_t> response;
    Instruction ins = Instruction::INS_SET_BOOT_PARAMS_CMD;
    array.add(osVersion).
        add(osPatchLevel).
        /* Verified Boot Key */
        add(verifiedBootKey).
        /* Verified Boot Hash */
        add(verifiedBootKeyHash).
        /* boot state */
        add(static_cast<uint32_t>(kmVerifiedBoot)).
        /* device locked */
        add(static_cast<uint32_t>(deviceLocked));
    std::vector<uint8_t> cborData = array.encode();

    ErrorCode ret = constructApduMessage(ins, cborData, apdu);
    if(ret != ErrorCode::OK) return ret;

    if(!getTransportFactoryInstance()->sendData(apdu.data(), apdu.size(), response)) {
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    if((response.size() < 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return (ErrorCode::UNKNOWN_ERROR);
    }
    return ErrorCode::OK;

}

JavacardKeymaster4Device::JavacardKeymaster4Device(): softKm_(new ::keymaster::AndroidKeymaster(
            []() -> auto {
            auto context = new JavaCardSoftKeymasterContext();
            context->SetSystemVersion(GetOsVersion(), GetOsPatchlevel());
            return context;
            }(),
            kOperationTableSize)), oprCtx_(new OperationContext()) {

    getTransportFactoryInstance()->openConnection();
}

JavacardKeymaster4Device::~JavacardKeymaster4Device() {}

// Methods from IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    //_hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
	std::vector<uint8_t> resp;
	std::vector<uint8_t> input;
	std::unique_ptr<Item> item;
	uint64_t securityLevel = static_cast<uint64_t>(SecurityLevel::STRONGBOX);
	hidl_string jcKeymasterName;
	hidl_string jcKeymasterAuthor;

    ErrorCode ret = sendData(Instruction::INS_GET_HW_INFO_CMD, input, resp);

    if((ret == ErrorCode::OK) && (resp.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, ret) = cborConverter_.decodeData(std::vector<uint8_t>(resp.begin(), resp.end()-2),
                true);
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
	std::vector<uint8_t> input;
    std::unique_ptr<Item> item;
    HmacSharingParameters hmacSharingParameters;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(Instruction::INS_GET_HMAC_SHARING_PARAM_CMD, input, cborData);

    if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborData.begin(), cborData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getHmacSharingParameters(item, 1, hmacSharingParameters); //HmacSharingParameters.
        }
    }
    _hidl_cb(errorCode, hmacSharingParameters);
    return Void();
}

Return<void> JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
	std::vector<uint8_t> cborOutData;
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

    errorCode = sendData(Instruction::INS_COMPUTE_SHARED_HMAC_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            cborConverter_.getBinaryArray(item, 1, bstr);
            sharingCheck.setToExternal(bstr.data(), bstr.size());
        }
    }
    _hidl_cb(errorCode, sharingCheck);
    return Void();
}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t operationHandle, const hidl_vec<KeyParameter>& parametersToVerify, const HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    VerificationToken verificationToken;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    cborConverter_.addKeyparameters(array, parametersToVerify);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_VERIFY_AUTHORIZATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getVerificationToken(item, 1, verificationToken);
        }
    }
    _hidl_cb(errorCode, verificationToken);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    cppbor::Array array;
    std::vector<uint8_t> cborOutData;
    std::unique_ptr<Item> item;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(std::vector<uint8_t>(data));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_ADD_RNG_ENTROPY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::generateKey(const hidl_vec<KeyParameter>& keyParams, generateKey_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;

    /* Convert to cbor format */
    cborConverter_.addKeyparameters(array, keyParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_GENERATE_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getBinaryArray(item, 1, keyBlob);
            cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importKey(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
	cppbor::Array array;
	std::unique_ptr<Item> item;
	hidl_vec<uint8_t> keyBlob;
	std::vector<uint8_t> cborOutData;
	ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
	KeyCharacteristics keyCharacteristics;
    cppbor::Array subArray;

    if(keyFormat != KeyFormat::PKCS8 && keyFormat != KeyFormat::RAW) {
        _hidl_cb(ErrorCode::UNSUPPORTED_KEY_FORMAT, keyBlob, keyCharacteristics);
        return Void();
    }
	cborConverter_.addKeyparameters(array, keyParams);
	array.add(static_cast<uint32_t>(KeyFormat::RAW)); //javacard accepts only RAW.
    if(ErrorCode::OK != (errorCode = prepareCborArrayFromRawKey(keyParams, keyFormat, keyData, subArray))) {
        _hidl_cb(errorCode, keyBlob, keyCharacteristics);
        return Void();
    }
    std::vector<uint8_t> encodedArray = subArray.encode();
    cppbor::Bstr bstr(encodedArray.begin(), encodedArray.end());
    array.add(bstr);

	std::vector<uint8_t> cborData = array.encode();

	errorCode = sendData(Instruction::INS_IMPORT_KEY_CMD, cborData, cborOutData);

	if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
		//Skip last 2 bytes in cborData, it contains status.
		std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
				true);
		if (item != nullptr) {
			cborConverter_.getBinaryArray(item, 1, keyBlob);
			cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
		}
	}
	_hidl_cb(errorCode, keyBlob, keyCharacteristics);
	return Void();
}

Return<void> JavacardKeymaster4Device::importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob, const hidl_vec<uint8_t>& maskingKey, const hidl_vec<KeyParameter>& unwrappingParams, uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> transitKey;
    std::vector<uint8_t> secureKey;
    std::vector<uint8_t> tag;
    hidl_vec<KeyParameter> authList;
    KeyFormat keyFormat;
    std::vector<uint8_t> wrappedKeyDescription;

    if(ErrorCode::OK != (errorCode = parseWrappedKey(wrappedKeyData, iv, transitKey, secureKey,
                                        tag, authList, keyFormat, wrappedKeyDescription))) {
        _hidl_cb(errorCode, keyBlob, keyCharacteristics);
        return Void();
    }
    cborConverter_.addKeyparameters(array, authList);
    array.add(static_cast<uint64_t>(keyFormat));
    array.add(secureKey);
    array.add(tag);
    array.add(iv);
    array.add(transitKey);
    array.add(std::vector<uint8_t>(wrappingKeyBlob));
    array.add(std::vector<uint8_t>(maskingKey));
    cborConverter_.addKeyparameters(array, unwrappingParams);
    array.add(std::vector<uint8_t>(wrappedKeyDescription));
    array.add(passwordSid);
    array.add(biometricSid); /* TODO if biometricSid optional if user not sent this don't encode this cbor format */
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_IMPORT_WRAPPED_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getBinaryArray(item, 1, keyBlob);
            cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyBlob, keyCharacteristics);

    return Void();
}

Return<void> JavacardKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    KeyCharacteristics keyCharacteristics;

    array.add(std::vector<uint8_t>(keyBlob));
    array.add(std::vector<uint8_t>(clientId));
    array.add(std::vector<uint8_t>(appData));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_GET_KEY_CHARACTERISTICS_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getKeyCharacteristics(item, 1, keyCharacteristics);
        }
    }
    _hidl_cb(errorCode, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& /*clientId*/, const hidl_vec<uint8_t>& /*appData*/, exportKey_cb _hidl_cb) {

    ExportKeyRequest request;
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    ExportKeyResponse response;
    softKm_->ExportKey(request, &response);

    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob);
    return Void();
}

Return<void> JavacardKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<KeyParameter>& attestParams, attestKey_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    hidl_vec<uint8_t> keyBlob;
    std::vector<uint8_t> cborOutData;
    hidl_vec<hidl_vec<uint8_t>> certChain;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyToAttest));
    cborConverter_.addKeyparameters(array, attestParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_ATTEST_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        std::vector<std::vector<uint8_t>> temp;
        std::vector<uint8_t> rootCert;
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getMultiBinaryArray(item, 1, temp);
        }
        if(readDataFromFile(ROOT_RSA_CERT, rootCert)) {
            temp.push_back(std::move(rootCert));
            certChain.resize(temp.size());
            for(int i = 0; i < temp.size(); i++) {
                certChain[i] = temp[i];
            }
        } else {
            LOG(ERROR) << "No root certificate found";
        }
    }
    _hidl_cb(errorCode, certChain);
    return Void();
}

Return<void> JavacardKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    hidl_vec<uint8_t> upgradedKeyBlob;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyBlobToUpgrade));
    cborConverter_.addKeyparameters(array, upgradeParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_UPGRADE_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getBinaryArray(item, 1, upgradedKeyBlob);
        }
    }
    _hidl_cb(errorCode, upgradedKeyBlob);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(std::vector<uint8_t>(keyBlob));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_DELETE_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
    }
    return errorCode;
}

Return<ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> input;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(Instruction::INS_DELETE_ALL_KEYS_CMD, input, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
    }
    return errorCode;
}

Return<ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> input;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(Instruction::INS_DESTROY_ATT_IDS_CMD, input, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams, const HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<KeyParameter> outParams;
    uint64_t operationHandle = 0;

    if (KeyPurpose::ENCRYPT == purpose || KeyPurpose::VERIFY == purpose) {
        BeginOperationRequest request;
        request.purpose = legacy_enum_conversion(purpose);
        request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        BeginOperationResponse response;
        softKm_->BeginOperation(request, &response);

        hidl_vec<KeyParameter> resultParams;
        if (response.error == KM_ERROR_OK) {
            resultParams = kmParamSet2Hidl(response.output_params);
        }
        if (response.error != KM_ERROR_INCOMPATIBLE_ALGORITHM) { /*Incompatible algorithm could be handled by JavaCard*/
            _hidl_cb(legacy_enum_conversion(response.error), resultParams, response.op_handle);
            return Void();
        }
    }

    cppbor::Array array;
    std::vector<uint8_t> cborOutData;
    std::unique_ptr<Item> item;
    std::unique_ptr<Item> blobItem = nullptr;
    KeyCharacteristics keyCharacteristics;

    /* Convert input data to cbor format */
    array.add(static_cast<uint64_t>(purpose));
    array.add(std::vector<uint8_t>(keyBlob));
    cborConverter_.addKeyparameters(array, inParams);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    /* Store the operationInfo */
    std::tie(blobItem, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(keyBlob), false);

    if(blobItem == NULL) {
        _hidl_cb(errorCode, outParams, operationHandle);
        return Void();
    }
    errorCode = sendData(Instruction::INS_BEGIN_OPERATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
            true);
        if (item != nullptr) {
            cborConverter_.getKeyParameters(item, 1, outParams);
            cborConverter_.getUint64(item, 2, operationHandle);
            /* Store the operationInfo */
            if (blobItem != nullptr) {
                cborConverter_.getKeyCharacteristics(blobItem, 3, keyCharacteristics);
                oprCtx_->setOperationInfo(operationHandle, purpose, keyCharacteristics.hardwareEnforced);
            }
        }
    }
    _hidl_cb(errorCode, outParams, operationHandle);
    return Void();
}

Return<void> JavacardKeymaster4Device::update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, update_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    UpdateOperationRequest request;
    request.op_handle = operationHandle;
    request.input.Reinitialize(input.data(), input.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));

    UpdateOperationResponse response;
    softKm_->UpdateOperation(request, &response);

    uint32_t inputConsumed = 0;
    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;
    errorCode = legacy_enum_conversion(response.error);
    if (response.error == KM_ERROR_OK) {
        inputConsumed = response.input_consumed;
        outParams = kmParamSet2Hidl(response.output_params);
        output = kmBuffer2hidlVec(response.output);
    } else if(response.error == KM_ERROR_INVALID_OPERATION_HANDLE) {
        std::vector<uint8_t> tempOut;
        /* OperationContext calls this below sendDataCallback callback function. This callback
         * may be called multiple times if the input data is larger than MAX_ALLOWED_INPUT_SIZE.
         */
        auto sendDataCallback = [&](std::vector<uint8_t>& data, bool) -> ErrorCode {
            cppbor::Array array;
            std::unique_ptr<Item> item;
            std::vector<uint8_t> cborOutData;

            // Convert input data to cbor format
            array.add(operationHandle);
            cborConverter_.addKeyparameters(array, inParams);
            array.add(data);
            cborConverter_.addHardwareAuthToken(array, authToken);
            cborConverter_.addVerificationToken(array, verificationToken);
            std::vector<uint8_t> cborData = array.encode();

            errorCode = sendData(Instruction::INS_UPDATE_OPERATION_CMD, cborData, cborOutData);

            if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true);
                if (item != nullptr) {
                    /*Ignore inputConsumed from javacard SE since HAL consumes all the input */
                    //cborConverter_.getUint64(item, 1, inputConsumed);
                    if(outParams.size() == 0)
                        cborConverter_.getKeyParameters(item, 2, outParams);
                    cborConverter_.getBinaryArray(item, 3, tempOut);
                }
            }
            return errorCode;
        };
        if(ErrorCode::OK == (errorCode = oprCtx_->update(operationHandle, std::vector<uint8_t>(input),
                        sendDataCallback))) {
            /* Consumed all the input */
            inputConsumed = input.size();
            output = tempOut;
        }
    }
    if(ErrorCode::OK != errorCode) {
        /* Delete the entry on this operationHandle */
        oprCtx_->clearOperationData(operationHandle);
    }
    _hidl_cb(errorCode, inputConsumed, outParams, output);
    return Void();
}

Return<void> JavacardKeymaster4Device::finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, finish_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    FinishOperationRequest request;
    request.op_handle = operationHandle;
    request.input.Reinitialize(input.data(), input.size());
    request.signature.Reinitialize(signature.data(), signature.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));

    FinishOperationResponse response;
    softKm_->FinishOperation(request, &response);

    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;
    errorCode = legacy_enum_conversion(response.error);
    if (response.error == KM_ERROR_OK) {
        outParams = kmParamSet2Hidl(response.output_params);
        output = kmBuffer2hidlVec(response.output);
    } else if (response.error == KM_ERROR_INVALID_OPERATION_HANDLE) {
        std::vector<uint8_t> tempOut;
        /* OperationContext calls this below sendDataCallback callback function. This callback
         * may be called multiple times if the input data is larger than MAX_ALLOWED_INPUT_SIZE.
         * This callback function decides whether to call update/finish instruction based on the
         * input received from the OperationContext through finish variable.
         * if finish variable is false update instruction is called, if it is true finish instruction
         * is called.
         */
        auto sendDataCallback = [&](std::vector<uint8_t>& data, bool finish) -> ErrorCode {
            cppbor::Array array;
            Instruction ins;
            std::unique_ptr<Item> item;
            std::vector<uint8_t> cborOutData;
            int keyParamPos, outputPos;

            // Convert input data to cbor format
            array.add(operationHandle);
            cborConverter_.addKeyparameters(array, inParams);
            array.add(data);
            if(finish) {
                array.add(std::vector<uint8_t>(signature));
                ins = Instruction::INS_FINISH_OPERATION_CMD;
                keyParamPos = 1;
                outputPos = 2;
            } else {
                ins = Instruction::INS_UPDATE_OPERATION_CMD;
                keyParamPos = 2;
                outputPos = 3;
            }
            cborConverter_.addHardwareAuthToken(array, authToken);
            cborConverter_.addVerificationToken(array, verificationToken);
            std::vector<uint8_t> cborData = array.encode();

            errorCode = sendData(ins, cborData, cborOutData);

            if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true);
                if (item != nullptr) {
                    if(outParams.size() == 0)
                        cborConverter_.getKeyParameters(item, keyParamPos, outParams);
                    cborConverter_.getBinaryArray(item, outputPos, tempOut);
                }
            }
            return errorCode;
        };
        if(ErrorCode::OK == (errorCode = oprCtx_->finish(operationHandle, std::vector<uint8_t>(input),
                        sendDataCallback))) {
            output = tempOut;
        }
    }
    /* Delete the entry on this operationHandle */
    oprCtx_->clearOperationData(operationHandle);
    _hidl_cb(errorCode, outParams, output);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::abort(uint64_t operationHandle) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    AbortOperationRequest request;
    request.op_handle = operationHandle;

    AbortOperationResponse response;
    softKm_->AbortOperation(request, &response);

    errorCode = legacy_enum_conversion(response.error);
    if (response.error == KM_ERROR_INVALID_OPERATION_HANDLE) {
        cppbor::Array array;
        std::unique_ptr<Item> item;
        std::vector<uint8_t> cborOutData;

        /* Convert input data to cbor format */
        array.add(operationHandle);
        std::vector<uint8_t> cborData = array.encode();

        errorCode = sendData(Instruction::INS_ABORT_OPERATION_CMD, cborData, cborOutData);

        if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
            //Skip last 2 bytes in cborData, it contains status.
            std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                    true);
        }
    }
    /* Delete the entry on this operationHandle */
    oprCtx_->clearOperationData(operationHandle);
    return errorCode;
}

// Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::deviceLocked(bool passwordOnly, const VerificationToken& verificationToken) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(passwordOnly);
    cborConverter_.addVerificationToken(array, verificationToken);
    std::vector<uint8_t> cborData = array.encode();

    /* TODO DeviceLocked command handled inside HAL */
    ErrorCode ret = sendData(Instruction::INS_DEVICE_LOCKED_CMD, cborData, cborOutData);

    if((ret == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData<::android::hardware::keymaster::V4_1::ErrorCode>(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
    }
    return errorCode;
}

Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::earlyBootEnded() {
    std::unique_ptr<Item> item;
    std::string message;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> cborInput;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;

    ErrorCode ret = sendData(Instruction::INS_EARLY_BOOT_ENDED_CMD, cborInput, cborOutData);

    if((ret == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData<::android::hardware::keymaster::V4_1::ErrorCode>(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
    }
    return errorCode;
}

}  // javacard
}  // namespace V4_1
}  // namespace keymaster
