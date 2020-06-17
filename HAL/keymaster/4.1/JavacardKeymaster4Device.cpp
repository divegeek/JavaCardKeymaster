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
#include <android-base/logging.h>
#include <keymaster/key_blob_utils/integrity_assured_key_blob.h>
#include <keymaster/key_blob_utils/software_keyblobs.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/wrapped_key.h>
#include <openssl/aes.h>

#include <JavacardKeymaster4Device.h>
#include <java_card_soft_keymaster_context.h>

//#define JAVACARD_KEYMASTER_NAME      "JavacardKeymaster4.1Device v0.1"
//#define JAVACARD_KEYMASTER_AUTHOR    "Android Open Source Project"
#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

namespace keymaster {
namespace V4_1 {
namespace javacard {

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

inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return static_cast<ErrorCode>(value);
}

inline keymaster_purpose_t legacy_enum_conversion(const KeyPurpose value) {
    return static_cast<keymaster_purpose_t>(value);
}

inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return static_cast<keymaster_key_format_t>(value);
}

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return keymaster_tag_t(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return Tag(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

keymaster_key_param_set_t hidlKeyParams2Km(const hidl_vec<KeyParameter>& keyParams) {
    keymaster_key_param_set_t set;

    set.params = new keymaster_key_param_t[keyParams.size()];
    set.length = keyParams.size();

    for (size_t i = 0; i < keyParams.size(); ++i) {
        auto tag = legacy_enum_conversion(keyParams[i].tag);
        switch (typeFromTag(tag)) {
            case KM_ENUM:
            case KM_ENUM_REP:
                set.params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
                break;
            case KM_UINT:
            case KM_UINT_REP:
                set.params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
                break;
            case KM_ULONG:
            case KM_ULONG_REP:
                set.params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
                break;
            case KM_DATE:
                set.params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
                break;
            case KM_BOOL:
                if (keyParams[i].f.boolValue)
                    set.params[i] = keymaster_param_bool(tag);
                else
                    set.params[i].tag = KM_TAG_INVALID;
                break;
            case KM_BIGNUM:
            case KM_BYTES:
                set.params[i] =
                    keymaster_param_blob(tag, &keyParams[i].blob[0], keyParams[i].blob.size());
                break;
            case KM_INVALID:
            default:
                set.params[i].tag = KM_TAG_INVALID;
                /* just skip */
                break;
        }
    }

    return set;
}

class KmParamSet : public keymaster_key_param_set_t {
    public:
        explicit KmParamSet(const hidl_vec<KeyParameter>& keyParams)
            : keymaster_key_param_set_t(hidlKeyParams2Km(keyParams)) {}
        KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
            other.length = 0;
            other.params = nullptr;
        }
        KmParamSet(const KmParamSet&) = delete;
        ~KmParamSet() { delete[] params; }
};

static inline hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set) {
    hidl_vec<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr)
        return result;

    result.resize(set.length);
    keymaster_key_param_t* params = set.params;
    for (size_t i = 0; i < set.length; ++i) {
        auto tag = params[i].tag;
        result[i].tag = legacy_enum_conversion(tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            result[i].f.integer = params[i].enumerated;
            break;
        case KM_UINT:
        case KM_UINT_REP:
            result[i].f.integer = params[i].integer;
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            result[i].f.longInteger = params[i].long_integer;
            break;
        case KM_DATE:
            result[i].f.dateTime = params[i].date_time;
            break;
        case KM_BOOL:
            result[i].f.boolValue = params[i].boolean;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            result[i].blob.setToExternal(const_cast<unsigned char*>(params[i].blob.data),
                                         params[i].blob.data_length);
            break;
        case KM_INVALID:
        default:
            params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }
    return result;
}

inline hidl_vec<uint8_t> kmBuffer2hidlVec(const ::keymaster::Buffer& buf) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(buf.peek_read()), buf.available_read());
    return result;
}

static inline void blob2Vec(const uint8_t *from, size_t size, std::vector<uint8_t>& to) {
    for(int i = 0; i < size; ++i) {
        to.push_back(from[i]);
    }
}

static inline ErrorCode parseWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, std::vector<uint8_t>& iv, std::vector<uint8_t>& transitKey,
std::vector<uint8_t>& secureKey, std::vector<uint8_t>& tag, hidl_vec<KeyParameter>& authList, KeyFormat&
keyFormat, std::vector<uint8_t>& wrappedKeyDescription) {
    KeymasterBlob kmIv;
    KeymasterKeyBlob kmTransitKey;
    KeymasterKeyBlob kmSecureKey;
    KeymasterBlob kmTag;
    AuthorizationSet authSet;
    keymaster_key_format_t kmKeyFormat;
    KeymasterBlob kmWrappedKeyDescription;
    KeymasterKeyBlob kmWrappedKeyData;

    kmWrappedKeyData.key_material = dup_buffer(wrappedKeyData.data(), wrappedKeyData.size());

    keymaster_error_t error = parse_wrapped_key(kmWrappedKeyData, &kmIv, &kmTransitKey,
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


JavacardKeymaster4Device::JavacardKeymaster4Device(): softKm_(new ::keymaster::AndroidKeymaster(
            []() -> auto {
            auto context = new JavaCardSoftKeymasterContext();
            context->SetSystemVersion(GetOsVersion(), GetOsPatchlevel());
            return context;
            }(),
            kOperationTableSize)), oprCtx_(new OperationContext()), setUpBootParams(false) {
    pTransportFactory = std::unique_ptr<se_transport::TransportFactory>(new se_transport::TransportFactory(
                android::base::GetBoolProperty("ro.kernel.qemu", false)));
    pTransportFactory->openConnection();
}

JavacardKeymaster4Device::~JavacardKeymaster4Device() {}

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

/* This method should be called at the time when HAL is initialized for the first time */
Return<ErrorCode> setBootParams(std::unique_ptr<se_transport::TransportFactory>& transport) {
    cppbor::Array array;
    std::vector<uint8_t> apdu;
    std::vector<uint8_t> response;
    Instruction ins = Instruction::INS_SET_BOOT_PARAMS_CMD;
    std::vector<uint8_t> verifiedBootKey(32, 0);
    std::vector<uint8_t> verifiedBootKeyHash(32, 0);
    array.add(GetOsVersion()).
        add(GetOsPatchlevel()).
        /* Verified Boot Key */
        add(verifiedBootKey).
        /* Verified Boot Hash */
        add(verifiedBootKeyHash).
        /* boot state */
        add(static_cast<uint64_t>(KM_VERIFIED_BOOT_UNVERIFIED)).
        /* device locked */
        add(0); /* false */
    std::vector<uint8_t> cborData = array.encode();

    ErrorCode ret = constructApduMessage(ins, cborData, apdu);
    if(ret != ErrorCode::OK) return ret;

    if(!transport->sendData(apdu.data(), apdu.size(), response)) {
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    if((response.size() < 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return (ErrorCode::UNKNOWN_ERROR);
    }
    return ErrorCode::OK;
}

ErrorCode sendData(JavacardKeymaster4Device *pKeymaster, std::unique_ptr<se_transport::TransportFactory>& transport, Instruction ins, std::vector<uint8_t>& inData,
std::vector<uint8_t>& response) {
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> apdu;

    if(!pKeymaster->getBootParamsInitialized()) {
        if((ret = setBootParams(transport)) != ErrorCode::OK) {
            return ret;
        }
        pKeymaster->setBootParams(true);
    }

    ret = constructApduMessage(ins, inData, apdu);
    if(ret != ErrorCode::OK) return ret;

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
	std::unique_ptr<Item> item;
	uint64_t securityLevel = static_cast<uint64_t>(SecurityLevel::STRONGBOX);
	hidl_string jcKeymasterName;
	hidl_string jcKeymasterAuthor;

    ErrorCode ret = sendData(this, pTransportFactory, Instruction::INS_GET_HW_INFO_CMD, input, resp);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_GET_HMAC_SHARING_PARAM_CMD, input, cborData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_COMPUTE_SHARED_HMAC_CMD, cborData, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_VERIFY_AUTHORIZATION_CMD, cborData, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_ADD_RNG_ENTROPY_CMD, cborData, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_GENERATE_KEY_CMD, cborData, cborOutData);

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
    keymaster_error_t error = KM_ERROR_UNKNOWN_ERROR;
    hidl_vec<uint8_t> inKey;
    KeymasterKeyBlob key_material;

    if (keyFormat == KeyFormat::PKCS8) {
        ImportKeyRequest request;
        request.key_description.Reinitialize(KmParamSet(keyParams));
        request.key_format = legacy_enum_conversion(keyFormat);
        request.SetKeyMaterial(keyData.data(), keyData.size());

        ImportKeyResponse response;
        softKm_->ImportKey(request, &response);

        KeyCharacteristics resultCharacteristics;
        hidl_vec<uint8_t> resultKeyBlob;
        error = response.error;
        if (response.error == KM_ERROR_OK) {
            key_material = KeymasterKeyBlob(response.key_blob);
            inKey.setToExternal(const_cast<uint8_t*>(key_material.key_material), key_material.key_material_size);
        }
        if(error != KM_ERROR_OK) {
	        KeyCharacteristics resultCharacteristics;
	        hidl_vec<uint8_t> resultKeyBlob;
	        _hidl_cb(legacy_enum_conversion(error), resultKeyBlob, resultCharacteristics);
	        return Void();
        }
    } else if (keyFormat == KeyFormat::RAW) {
        //convert keyData to keyMaterial
        inKey = keyData;
    } else {
        KeyCharacteristics resultCharacteristics;
        hidl_vec<uint8_t> resultKeyBlob;
        _hidl_cb(legacy_enum_conversion(KM_ERROR_UNSUPPORTED_KEY_FORMAT), resultKeyBlob, resultCharacteristics);
        return Void();
    }

	cppbor::Array array;
	std::unique_ptr<Item> item;
	hidl_vec<uint8_t> keyBlob;
	std::vector<uint8_t> cborOutData;
	ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
	KeyCharacteristics keyCharacteristics;

	cborConverter_.addKeyparameters(array, keyParams);
	array.add(static_cast<uint64_t>(KeyFormat::RAW)); //PKCS8 is already converted to RAW
	array.add(std::vector<uint8_t>(inKey));
	std::vector<uint8_t> cborData = array.encode();

	errorCode = sendData(this, pTransportFactory, Instruction::INS_IMPORT_KEY_CMD, cborData, cborOutData);

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
    array.add(transitKey);
    array.add(iv);
    array.add(static_cast<uint64_t>(keyFormat));
    cborConverter_.addKeyparameters(array, authList);
    array.add(secureKey);
    array.add(tag);
    array.add(std::vector<uint8_t>(wrappingKeyBlob));
    array.add(std::vector<uint8_t>(maskingKey));
    cborConverter_.addKeyparameters(array, unwrappingParams);
    array.add(passwordSid);
    array.add(biometricSid); /* TODO if biometricSid optional if user not sent this don't encode this cbor format */
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(this, pTransportFactory, Instruction::INS_IMPORT_WRAPPED_KEY_CMD, cborData, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_GET_KEY_CHARACTERISTICS_CMD, cborData, cborOutData);

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
    //addClientAndAppData(clientId, appData, &request.additional_params);

    ExportKeyResponse response;
    softKm_->ExportKey(request, &response);

    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob);
    return Void();
/*
    cppbor::Array array;
    std::unique_ptr<Item> item;
    hidl_vec<uint8_t> keyMaterial;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    array.add(static_cast<uint64_t>(exportFormat));
    array.add(std::vector<uint8_t>(keyBlob));
    array.add(std::vector<uint8_t>(clientId));
    array.add(std::vector<uint8_t>(appData));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(this, pTransportFactory, Instruction::INS_EXPORT_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getBinaryArray(item, 1, keyMaterial);
        }
    }
    _hidl_cb(errorCode, keyMaterial);
    return Void();*/
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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_ATTEST_KEY_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            cborConverter_.getMultiBinaryArray(item, 1, certChain);
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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_UPGRADE_KEY_CMD, cborData, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_DELETE_KEY_CMD, cborData, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_DELETE_ALL_KEYS_CMD, input, cborOutData);

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

    errorCode = sendData(this, pTransportFactory, Instruction::INS_DESTROY_ATT_IDS_CMD, input, cborOutData);

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

    /* Convert input data to cbor format */
    array.add(static_cast<uint64_t>(purpose));
    array.add(std::vector<uint8_t>(keyBlob));
    cborConverter_.addKeyparameters(array, inParams);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(this, pTransportFactory, Instruction::INS_BEGIN_OPERATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
            true);
        if (item != nullptr) {
            cborConverter_.getKeyParameters(item, 1, outParams);
            cborConverter_.getUint64(item, 2, operationHandle);
            /* Store the operationInfo */
            oprCtx_->setOperationInfo(operationHandle, purpose, inParams);
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

            errorCode = sendData(this, pTransportFactory, Instruction::INS_UPDATE_OPERATION_CMD, cborData, cborOutData);

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

            errorCode = sendData(this, pTransportFactory, ins, cborData, cborOutData);

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
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(this, pTransportFactory, Instruction::INS_ABORT_OPERATION_CMD, cborData, cborOutData);

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
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
    ErrorCode ret = sendData(this, pTransportFactory, Instruction::INS_DEVICE_LOCKED_CMD, cborData, cborOutData);

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

    ErrorCode ret = sendData(this, pTransportFactory, Instruction::INS_EARLY_BOOT_ENDED_CMD, cborInput, cborOutData);

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
