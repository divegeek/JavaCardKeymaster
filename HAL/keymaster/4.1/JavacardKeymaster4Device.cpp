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
#include <time.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <Transport.h>
#include <keymaster/key_blob_utils/software_keyblobs.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/wrapped_key.h>
#include <keymaster/attestation_record.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <openssl/aes.h>

#include <JavacardKeymaster4Device.h>
#include <JavacardSoftKeymasterContext.h>
#include <CommonUtils.h>
#include <android-base/logging.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

#define JAVACARD_KEYMASTER_NAME      "JavacardKeymaster4.1Device v1.0"
#define JAVACARD_KEYMASTER_AUTHOR    "Android Open Source Project"

#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

#define INS_BEGIN_KM_CMD 0x00
#define INS_END_KM_PROVISION_CMD 0x20
#define INS_END_KM_CMD 0x7F
#define SW_KM_OPR 0UL
#define SB_KM_OPR 1UL
#define SE_POWER_RESET_STATUS_FLAG ( 1 << 30)

namespace keymaster {
namespace V4_1 {
namespace javacard {

static std::unique_ptr<se_transport::TransportFactory> pTransportFactory = nullptr;
constexpr size_t kOperationTableSize = 4;
/* Key is the newly generated operation handle. Value is a pair with first element having
 * original operation handle and second element represents SW or SB operation.
 */
std::map<uint64_t, std::pair<uint64_t, uint64_t>> operationTable;

struct KM_AUTH_LIST_Delete {
    void operator()(KM_AUTH_LIST* p) { KM_AUTH_LIST_free(p); }
};

enum class Instruction {
    // Keymaster commands
    INS_GENERATE_KEY_CMD = INS_END_KM_PROVISION_CMD+1,
    INS_IMPORT_KEY_CMD = INS_END_KM_PROVISION_CMD+2,
    INS_IMPORT_WRAPPED_KEY_CMD = INS_END_KM_PROVISION_CMD+3,
    INS_EXPORT_KEY_CMD = INS_END_KM_PROVISION_CMD+4,
    INS_ATTEST_KEY_CMD = INS_END_KM_PROVISION_CMD+5,
    INS_UPGRADE_KEY_CMD = INS_END_KM_PROVISION_CMD+6,
    INS_DELETE_KEY_CMD = INS_END_KM_PROVISION_CMD+7,
    INS_DELETE_ALL_KEYS_CMD = INS_END_KM_PROVISION_CMD+8,
    INS_ADD_RNG_ENTROPY_CMD = INS_END_KM_PROVISION_CMD+9,
    INS_COMPUTE_SHARED_HMAC_CMD = INS_END_KM_PROVISION_CMD+10,
    INS_DESTROY_ATT_IDS_CMD = INS_END_KM_PROVISION_CMD+11,
    INS_VERIFY_AUTHORIZATION_CMD = INS_END_KM_PROVISION_CMD+12,
    INS_GET_HMAC_SHARING_PARAM_CMD = INS_END_KM_PROVISION_CMD+13,
    INS_GET_KEY_CHARACTERISTICS_CMD = INS_END_KM_PROVISION_CMD+14,
    INS_GET_HW_INFO_CMD = INS_END_KM_PROVISION_CMD+15,
    INS_BEGIN_OPERATION_CMD = INS_END_KM_PROVISION_CMD+16,
    INS_UPDATE_OPERATION_CMD = INS_END_KM_PROVISION_CMD+17,
    INS_FINISH_OPERATION_CMD = INS_END_KM_PROVISION_CMD+18,
    INS_ABORT_OPERATION_CMD = INS_END_KM_PROVISION_CMD+19,
    INS_DEVICE_LOCKED_CMD = INS_END_KM_PROVISION_CMD+20,
    INS_EARLY_BOOT_ENDED_CMD = INS_END_KM_PROVISION_CMD+21,
    INS_GET_CERT_CHAIN_CMD = INS_END_KM_PROVISION_CMD+22,
    INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD+8,
    INS_SET_VERSION_PATCHLEVEL_CMD = INS_BEGIN_KM_CMD+9,
};

enum ProvisionStatus {
    NOT_PROVISIONED = 0x00,
    PROVISION_STATUS_ATTESTATION_KEY = 0x01,
    PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02,
    PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04,
    PROVISION_STATUS_ATTEST_IDS = 0x08,
    PROVISION_STATUS_PRESHARED_SECRET = 0x10,
    PROVISION_STATUS_BOOT_PARAM = 0x20,
    PROVISION_STATUS_PROVISIONING_LOCKED = 0x40,
};

//Extended error codes
enum ExtendedErrors {
    SW_CONDITIONS_NOT_SATISFIED = -10001,
    UNSUPPORTED_CLA = -10002,
    INVALID_P1P2 = -10003,
    UNSUPPORTED_INSTRUCTION = -10004,
    CMD_NOT_ALLOWED = -10005,
    SW_WRONG_LENGTH = -10006,
    INVALID_DATA = -10007,
    CRYPTO_ILLEGAL_USE = -10008,
    CRYPTO_ILLEGAL_VALUE = -10009,
    CRYPTO_INVALID_INIT = -10010,
    CRYPTO_NO_SUCH_ALGORITHM = -10011,
    CRYPTO_UNINITIALIZED_KEY = -10012,
    GENERIC_UNKNOWN_ERROR = -10013
};

static inline std::unique_ptr<se_transport::TransportFactory>& getTransportFactoryInstance() {
    if(pTransportFactory == nullptr) {
        pTransportFactory = std::unique_ptr<se_transport::TransportFactory>(new se_transport::TransportFactory(
                    android::base::GetBoolProperty("ro.kernel.qemu", false)));
        pTransportFactory->openConnection();
    }
    return pTransportFactory;
}

static inline bool findTag(const hidl_vec<KeyParameter>& params, Tag tag) {
    size_t size = params.size();
    for(size_t i = 0; i < size; ++i) {
        if(tag == params[i].tag)
            return true;
    }
    return false;
}

static inline bool getTag(const hidl_vec<KeyParameter>& params, Tag tag, KeyParameter& param) {
    size_t size = params.size();
    for(size_t i = 0; i < size; ++i) {
        if(tag == params[i].tag) {
            param = params[i];
            return true;
        }
    }
    return false;
}

template<typename T = ErrorCode>
static T translateExtendedErrorsToHalErrors(T& errorCode) {
    T err;
    switch(static_cast<int32_t>(errorCode)) {
        case SW_CONDITIONS_NOT_SATISFIED:
        case UNSUPPORTED_CLA:
        case INVALID_P1P2:
        case INVALID_DATA:
        case CRYPTO_ILLEGAL_USE:
        case CRYPTO_ILLEGAL_VALUE:
        case CRYPTO_INVALID_INIT:
        case CRYPTO_UNINITIALIZED_KEY:
        case GENERIC_UNKNOWN_ERROR:
            err = T::UNKNOWN_ERROR;
            break;
        case CRYPTO_NO_SUCH_ALGORITHM:
            err = T::UNSUPPORTED_ALGORITHM;
            break;
        case UNSUPPORTED_INSTRUCTION:
        case CMD_NOT_ALLOWED:
        case SW_WRONG_LENGTH:
            err = T::UNIMPLEMENTED;
            break;
        default:
            err = static_cast<T>(errorCode);
            break;
    }
    return err;
}

/* Generate new operation handle */
static ErrorCode generateOperationHandle(uint64_t& oprHandle) {
    std::map<uint64_t, std::pair<uint64_t, uint64_t>>::iterator it;
    do {
        keymaster_error_t err = GenerateRandom(reinterpret_cast<uint8_t*>(&oprHandle), (size_t)sizeof(oprHandle));
        if (err != KM_ERROR_OK) {
            return legacy_enum_conversion(err);
        }
        it = operationTable.find(oprHandle);
    } while (it != operationTable.end());
    return ErrorCode::OK;
}

/* Create a new operation handle entry in operation table.*/
static ErrorCode createOprHandleEntry(uint64_t origOprHandle, uint64_t keymasterSrc, uint64_t& newOperationHandle) {
    ErrorCode errorCode = ErrorCode::OK;
    if (ErrorCode::OK != (errorCode = generateOperationHandle(newOperationHandle))) {
        return errorCode;
    }
    operationTable[newOperationHandle] = std::make_pair(origOprHandle, keymasterSrc);
    return errorCode;
}

/* Get original operation handle generated by softkeymaster/strongboxkeymaster. */
static ErrorCode getOrigOperationHandle(uint64_t halGeneratedOperationHandle, uint64_t& origOprHandle) {
    std::map<uint64_t, std::pair<uint64_t, uint64_t>>::iterator it = operationTable.find(halGeneratedOperationHandle);
    if (it == operationTable.end()) {
        return ErrorCode::INVALID_OPERATION_HANDLE;
    }
    origOprHandle = it->second.first;
    return ErrorCode::OK;
}

/* Tells if the operation handle belongs to strongbox keymaster. */
static bool isStrongboxOperation(uint64_t halGeneratedOperationHandle) {
    std::map<uint64_t, std::pair<uint64_t, uint64_t>>::iterator it = operationTable.find(halGeneratedOperationHandle);
    if (it == operationTable.end()) {
        return false;
    }
    return (SB_KM_OPR == it->second.second);
}

/* Delete the operation handle entry from operation table. */
static void deleteOprHandleEntry(uint64_t halGeneratedOperationHandle) {
    operationTable.erase(halGeneratedOperationHandle);
}

/* Clears all the strongbox operation handle entries from operation table */
static void clearStrongboxOprHandleEntries(const std::unique_ptr<OperationContext>& oprCtx) {
    LOG(INFO) << "Secure Element reset or applet upgrade detected. Removing existing operation handles";
    auto it = operationTable.begin();
    while (it != operationTable.end()) {
        if (it->second.second == SB_KM_OPR) { //Strongbox operation
            LOG(INFO) << "operation handle: " << it->first << " is removed";
            oprCtx->clearOperationData(it->second.first);
            it = operationTable.erase(it);
        } else {
            ++it;
        }
    }
}

/**
 * Returns the negative value of the same number.
 */
static inline int32_t get2sCompliment(uint32_t value) { 
    return static_cast<int32_t>(~value+1); 
}

/**
 * Clears all the strongbox operation handle entries if secure element power reset happens.
 * And also extracts the error code value after unmasking the power reset status flag.
 */
static uint32_t handleErrorCode(const std::unique_ptr<OperationContext>& oprCtx, uint32_t errorCode) {
    //Check if secure element is reset
    bool isSeResetOccurred = (0 != (errorCode & SE_POWER_RESET_STATUS_FLAG));

    if (isSeResetOccurred) {
        //Clear the operation table for Strongbox operations entries.
        clearStrongboxOprHandleEntries(oprCtx);
        // Unmask the power reset status flag.
        errorCode &= ~SE_POWER_RESET_STATUS_FLAG;
    }
    return errorCode;
}

template<typename T = ErrorCode>
static std::tuple<std::unique_ptr<Item>, T> decodeData(CborConverter& cb, const std::vector<uint8_t>& response, bool
        hasErrorCode, const std::unique_ptr<OperationContext>& oprCtx) {
    std::unique_ptr<Item> item(nullptr);
    T errorCode = T::OK;
    std::tie(item, errorCode) = cb.decodeData<T>(response, hasErrorCode);

    uint32_t tempErrCode = handleErrorCode(oprCtx, static_cast<uint32_t>(errorCode));

    // SE sends errocode as unsigned value so convert the unsigned value
    // into a signed value of same magnitude and copy back to errorCode.
    errorCode = static_cast<T>(get2sCompliment(tempErrCode));

    if (T::OK != errorCode) {
        LOG(ERROR) << "error in decodeData: " << (int32_t) errorCode;
        errorCode = translateExtendedErrorsToHalErrors<T>(errorCode);
    }
    LOG(DEBUG) << "decodeData status: " << (int32_t) errorCode;
    return {std::move(item), errorCode};
}

ErrorCode encodeParametersVerified(const VerificationToken& verificationToken, std::vector<uint8_t>& asn1ParamsVerified) {
    if (verificationToken.parametersVerified.size() > 0) {
        AuthorizationSet paramSet;
        KeymasterBlob derBlob;
        UniquePtr<KM_AUTH_LIST, KM_AUTH_LIST_Delete> kmAuthList(KM_AUTH_LIST_new());

        paramSet.Reinitialize(KmParamSet(verificationToken.parametersVerified));

        auto err = build_auth_list(paramSet, kmAuthList.get());
        if (err != KM_ERROR_OK) {
            return legacy_enum_conversion(err);
        }
        int len = i2d_KM_AUTH_LIST(kmAuthList.get(), nullptr);
        if (len < 0) {
            return legacy_enum_conversion(TranslateLastOpenSslError());
        }

        if (!derBlob.Reset(len)) {
            return legacy_enum_conversion(KM_ERROR_MEMORY_ALLOCATION_FAILED);
        }

        uint8_t* p = derBlob.writable_data();
        len = i2d_KM_AUTH_LIST(kmAuthList.get(), &p);
        if (len < 0) {
            return legacy_enum_conversion(TranslateLastOpenSslError());
        }
        asn1ParamsVerified.insert(asn1ParamsVerified.begin(), p, p+len);
        derBlob.release();
    }
    return ErrorCode::OK;
}

ErrorCode prepareCborArrayFromKeyData(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>& blob, cppbor::Array&
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

    if(USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le all set to 00.
        // Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        //Extended length 3 bytes, starts with 0x00
        apduOut.push_back(static_cast<uint8_t>(0x00));
        if (inputData.size() > 0) {
            apduOut.push_back(static_cast<uint8_t>(inputData.size() >> 8));
            apduOut.push_back(static_cast<uint8_t>(inputData.size() & 0xFF));
            //Data
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        }
        //Expected length of output.
        //Accepting complete length of output every time.
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));
    } else {
        return (ErrorCode::INSUFFICIENT_BUFFER_SPACE);
    }

    return (ErrorCode::OK);//success
}

uint16_t getStatus(std::vector<uint8_t>& inputData) {
    //Last two bytes are the status SW0SW1
    return (inputData.at(inputData.size()-2) << 8) | (inputData.at(inputData.size()-1));
}

ErrorCode sendData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response) {
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> apdu;

    ret = constructApduMessage(ins, inData, apdu);
    if(ret != ErrorCode::OK) {
        LOG(ERROR) << "error in constructApduMessage cmd: " << (int32_t)ins << " status: " << (int32_t)ret;
        return ret;
    }

    if(!getTransportFactoryInstance()->sendData(apdu.data(), apdu.size(), response)) {
        LOG(ERROR) << "error in sendData cmd: " << (int32_t)ins << " status: "
                   << (int32_t)ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU status.
    if((response.size() <= 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        LOG(ERROR) << "error in sendData cmd: " << (int32_t)ins << " status: " << getStatus(response);
        return (ErrorCode::UNKNOWN_ERROR);
    }
    LOG(DEBUG) << "sendData cmd: " << (int32_t)ins << " status: " << (int32_t)ErrorCode::OK;
    return (ErrorCode::OK);//success
}

/**
 * Sends android system properties like os_version, os_patchlevel and vendor_patchlevel to
 * the Applet.
 */
static ErrorCode setAndroidSystemProperties(CborConverter& cborConverter_, const std::unique_ptr<OperationContext>& oprCtx) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;

    array.add(GetOsVersion()).
        add(GetOsPatchlevel()).
        add(GetVendorPatchlevel());

    std::vector<uint8_t> cborData = array.encode();
    errorCode = sendData(Instruction::INS_SET_VERSION_PATCHLEVEL_CMD, cborData, cborOutData);
    if (ErrorCode::OK == errorCode) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx);
    }
    if (ErrorCode::OK != errorCode) 
        LOG(ERROR) << "Failed to set os_version, os_patchlevel and vendor_patchlevel err: " << (int32_t) errorCode;

    return errorCode;
}

JavacardKeymaster4Device::JavacardKeymaster4Device(): softKm_(new ::keymaster::AndroidKeymaster(
            []() -> auto {
            auto context = new JavaCardSoftKeymasterContext();
            context->SetSystemVersion(GetOsVersion(), GetOsPatchlevel());
            return context;
            }(),
            kOperationTableSize)), oprCtx_(new OperationContext()), isEachSystemPropertySet(false) {
    // Send Android system properties like os_version, os_patchlevel and vendor_patchlevel
    // to the Applet. Incase if setting system properties fails here, again try setting
    // it from computeSharedHmac.
    if (ErrorCode::OK == setAndroidSystemProperties(cborConverter_, oprCtx_)) {
        isEachSystemPropertySet = true;
    }

}

JavacardKeymaster4Device::~JavacardKeymaster4Device() {}

// Methods from IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    // When socket is not connected return hardware info parameters from HAL itself.
    std::vector<uint8_t> resp;
    std::vector<uint8_t> input;
    std::unique_ptr<Item> item;
    uint64_t securityLevel = static_cast<uint64_t>(SecurityLevel::STRONGBOX);
    hidl_string jcKeymasterName;
    hidl_string jcKeymasterAuthor;

    ErrorCode ret = sendData(Instruction::INS_GET_HW_INFO_CMD, input, resp);
    if (ret == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, ret) = decodeData(cborConverter_, std::vector<uint8_t>(resp.begin(), resp.end()-2),
                false, oprCtx_);
        if (item != nullptr) {
            std::vector<uint8_t> temp;
            if(!cborConverter_.getUint64(item, 0, securityLevel) ||
                    !cborConverter_.getBinaryArray(item, 1, jcKeymasterName) ||
                    !cborConverter_.getBinaryArray(item, 2, jcKeymasterAuthor)) {
                LOG(ERROR) << "Failed to convert cbor data of INS_GET_HW_INFO_CMD";
                _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
                return Void();
            }
        }
        _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
        return Void();
    } else {
        // It should not come here, but incase if for any reason SB keymaster fails to getHardwareInfo
        // return proper values from HAL.
        LOG(ERROR) << "Failed to fetch getHardwareInfo from javacard";
        _hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
        return Void();
    }
}

Return<void> JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> input;
    std::unique_ptr<Item> item;
    HmacSharingParameters hmacSharingParameters;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    errorCode = sendData(Instruction::INS_GET_HMAC_SHARING_PARAM_CMD, input, cborData);
    if (ErrorCode::OK == errorCode) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborData.begin(), cborData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getHmacSharingParameters(item, 1, hmacSharingParameters)) {
                LOG(ERROR) << "Failed to convert cbor data of INS_GET_HMAC_SHARING_PARAM_CMD";
                errorCode = ErrorCode::UNKNOWN_ERROR;
            }
        }
    }
#ifdef VTS_EMULATOR
    /* TODO temporary fix: vold daemon calls performHmacKeyAgreement. At that time when vold calls this API there is no
     * network connectivity and socket cannot be connected. So as a hack we are calling softkeymaster to getHmacSharing
     * parameters.
     */
    else {
        auto response = softKm_->GetHmacSharingParameters();
        LOG(DEBUG) << "INS_GET_HMAC_SHARING_PARAM_CMD not succeded with javacard";
        LOG(DEBUG) << "Setting software keymaster hmac sharing parameters";
        hmacSharingParameters.seed.setToExternal(const_cast<uint8_t*>(response.params.seed.data),
                response.params.seed.data_length);
        static_assert(sizeof(response.params.nonce) == hmacSharingParameters.nonce.size(), "Nonce sizes don't match");
        memcpy(hmacSharingParameters.nonce.data(), response.params.nonce, hmacSharingParameters.nonce.size());
        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "INS_GET_HMAC_SHARING_PARAM_CMD softkm status: " << (int32_t) errorCode;
    }
#endif
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
    cppbor::Array outerArray;
#ifndef VTS_EMULATOR
    // The Android system properties like OS_VERSION, OS_PATCHLEVEL and VENDOR_PATCHLEVEL are to 
    // be delivered to the Applet when the HAL is first loaded. Incase if settting system properties
    // failed at construction time then this is one of the ideal places to send this information
    // to the Applet as computeSharedHmac is called everytime when Android device boots.
    if (!isEachSystemPropertySet) {
        errorCode = setAndroidSystemProperties(cborConverter_);
        if (ErrorCode::OK != errorCode) {
            LOG(ERROR) << " Failed to set os_version, os_patchlevel and vendor_patchlevel err: " << (int32_t)errorCode;
            _hidl_cb(errorCode, sharingCheck);
            return Void();
        }
        isEachSystemPropertySet = true;
    }
#endif

    for(size_t i = 0; i < params.size(); ++i) {
        cppbor::Array innerArray;
        innerArray.add(static_cast<std::vector<uint8_t>>(params[i].seed));
        for(size_t j = 0; j < params[i].nonce.size(); j++) {
            tempVec.push_back(params[i].nonce[j]);
        }
        innerArray.add(tempVec);
        tempVec.clear();
        outerArray.add(std::move(innerArray));
    }
    array.add(std::move(outerArray));
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_COMPUTE_SHARED_HMAC_CMD, cborData, cborOutData);
    if (ErrorCode::OK == errorCode) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            std::vector<uint8_t> bstr;
            if(!cborConverter_.getBinaryArray(item, 1, bstr)) {
                LOG(ERROR) << "INS_COMPUTE_SHARED_HMAC_CMD: failed to convert cbor sharing check value";
                errorCode = ErrorCode::UNKNOWN_ERROR;
            } else {
                sharingCheck = bstr;
            }
        }
    }
#ifdef VTS_EMULATOR
    /* TODO temporary fix: vold daemon calls performHmacKeyAgreement. At that time when vold calls this API there is no
     * network connectivity and socket cannot be connected. So as a hack we are calling softkeymaster to
     * computeSharedHmac.
     */
    else {
        ComputeSharedHmacRequest request;
        request.params_array.params_array = new keymaster::HmacSharingParameters[params.size()];
        request.params_array.num_params = params.size();
        for (size_t i = 0; i < params.size(); ++i) {
            request.params_array.params_array[i].seed = {params[i].seed.data(), params[i].seed.size()};
            static_assert(sizeof(request.params_array.params_array[i].nonce) ==
                    decltype(params[i].nonce)::size(),
                    "Nonce sizes don't match");
            memcpy(request.params_array.params_array[i].nonce, params[i].nonce.data(),
                    params[i].nonce.size());
        }

        LOG(DEBUG) << "INS_COMPUTE_SHARED_HMAC_CMD failed, computing shared check data using soft-key-master" << (int32_t) errorCode;
        auto response = softKm_->ComputeSharedHmac(request);
        if (response.error == KM_ERROR_OK) sharingCheck = kmBlob2hidlVec(response.sharing_check);
        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "INS_COMPUTE_SHARED_HMAC_CMD softkm status: " << (int32_t) errorCode;
    }
#endif
    _hidl_cb(errorCode, sharingCheck);
    return Void();
 }

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t , const hidl_vec<KeyParameter>& , const HardwareAuthToken& , verifyAuthorization_cb _hidl_cb) {
    VerificationToken verificationToken;
    LOG(DEBUG) << "Verify authorizations UNIMPLEMENTED";
    _hidl_cb(ErrorCode::UNIMPLEMENTED, verificationToken);
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
    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
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
    hidl_vec<KeyParameter> updatedParams(keyParams);

    if(!findTag(keyParams, Tag::CREATION_DATETIME) &&
            !findTag(keyParams, Tag::ACTIVE_DATETIME)) {
        //Add CREATION_DATETIME in HAL, as secure element is not having clock.
        size_t size = keyParams.size();
        updatedParams.resize(size+1);
        updatedParams[size].tag = Tag::CREATION_DATETIME;
        updatedParams[size].f.dateTime = java_time(time(nullptr));
    }

    /* Convert to cbor format */
    cborConverter_.addKeyparameters(array, updatedParams);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_GENERATE_KEY_CMD, cborData, cborOutData);
    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getBinaryArray(item, 1, keyBlob) ||
                    !cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics)) {
                //Clear the buffer.
                keyBlob.setToExternal(nullptr, 0);
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_GENERATE_KEY_CMD: error while converting cbor data: " << (int32_t) errorCode;
            }
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
        LOG(ERROR) << "INS_IMPORT_KEY_CMD unsupported key format " << (int32_t)keyFormat;
        _hidl_cb(ErrorCode::UNSUPPORTED_KEY_FORMAT, keyBlob, keyCharacteristics);
        return Void();
    }
    cborConverter_.addKeyparameters(array, keyParams);
    array.add(static_cast<uint32_t>(KeyFormat::RAW)); //javacard accepts only RAW.
    if(ErrorCode::OK != (errorCode = prepareCborArrayFromKeyData(keyParams, keyFormat, keyData, subArray))) {
        LOG(ERROR) << "INS_IMPORT_KEY_CMD Error in while creating cbor data from key data:" << (int32_t) errorCode;
        _hidl_cb(errorCode, keyBlob, keyCharacteristics);
        return Void();
    }
    std::vector<uint8_t> encodedArray = subArray.encode();
    cppbor::Bstr bstr(encodedArray.begin(), encodedArray.end());
    array.add(bstr);

    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_IMPORT_KEY_CMD, cborData, cborOutData);

    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getBinaryArray(item, 1, keyBlob) ||
                    !cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics)) {
                //Clear the buffer.
                keyBlob.setToExternal(nullptr, 0);
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_IMPORT_KEY_CMD: error while converting cbor data, status: " << (int32_t) errorCode;
            }
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
        LOG(ERROR) << "INS_IMPORT_WRAPPED_KEY_CMD error while parsing wrapped key status: " << (int32_t) errorCode;
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
    array.add(biometricSid);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_IMPORT_WRAPPED_KEY_CMD, cborData, cborOutData);

    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getBinaryArray(item, 1, keyBlob) ||
                    !cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics)) {
                //Clear the buffer.
                keyBlob.setToExternal(nullptr, 0);
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_IMPORT_WRAPPED_KEY_CMD: error while converting cbor data, status: " << (int32_t) errorCode;
            }
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
    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getKeyCharacteristics(item, 1, keyCharacteristics)) {
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_GET_KEY_CHARACTERISTICS_CMD: error while converting cbor data, status: " << (int32_t) errorCode;
            }
        }
    }
    _hidl_cb(errorCode, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<uint8_t> resultKeyBlob;

    //Check if keyblob is corrupted
    getKeyCharacteristics(keyBlob, clientId, appData,
            [&](ErrorCode error, KeyCharacteristics /*keyCharacteristics*/) {
            errorCode = error;
            });

    if(errorCode != ErrorCode::OK) {
        LOG(ERROR) << "Error in exportKey: " << (int32_t) errorCode;
        _hidl_cb(errorCode, resultKeyBlob);
        return Void();
    }

    ExportKeyRequest request;
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    ExportKeyResponse response;
    softKm_->ExportKey(request, &response);

    if(response.error == KM_ERROR_INCOMPATIBLE_ALGORITHM) {
        //Symmetric Keys cannot be exported.
        response.error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        LOG(ERROR) << "error in exportKey: unsupported algorithm or key format";
    }
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    errorCode = legacy_enum_conversion(response.error);
    LOG(DEBUG) << "exportKey status: " << (int32_t) errorCode;
    _hidl_cb(errorCode, resultKeyBlob);
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

    if(errorCode == ErrorCode::OK) {
        std::vector<std::vector<uint8_t>> temp;
        std::vector<uint8_t> rootCert;
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getMultiBinaryArray(item, 1, temp)) {
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_ATTEST_KEY_CMD: error in converting cbor data, status: " << (int32_t) errorCode;
            } else {
                cborData.clear();
                cborOutData.clear();
                errorCode = sendData(Instruction::INS_GET_CERT_CHAIN_CMD, cborData, cborOutData);
                if(errorCode == ErrorCode::OK) {
                    //Skip last 2 bytes in cborData, it contains status.
                    std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(),
                    cborOutData.end()-2),
                            true, oprCtx_);
                    if (item != nullptr) {
                        std::vector<uint8_t> chain;
                        if(!cborConverter_.getBinaryArray(item, 1, chain)) {
                            errorCode = ErrorCode::UNKNOWN_ERROR;
                            LOG(ERROR) << "attestkey INS_GET_CERT_CHAIN_CMD: errorn in converting cbor data, status: " << (int32_t) errorCode;
                        } else {
                            if(ErrorCode::OK == (errorCode = getCertificateChain(chain, temp))) {
                                certChain.resize(temp.size());
                                for(int i = 0; i < temp.size(); i++) {
                                    certChain[i] = temp[i];
                                }
                            } else {
                                LOG(ERROR) << "Error in attestkey getCertificateChain: " << (int32_t) errorCode;
                            }
                        }
                    }
                }
            }
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

    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
        if (item != nullptr) {
            if(!cborConverter_.getBinaryArray(item, 1, upgradedKeyBlob)) {
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_UPGRADE_KEY_CMD: error in converting cbor data, status: " << (int32_t) errorCode;
            }
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

    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
    }
    return errorCode;
}

Return<ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> input;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(Instruction::INS_DELETE_ALL_KEYS_CMD, input, cborOutData);

    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
    }
    return errorCode;
}

Return<ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    std::vector<uint8_t> input;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(Instruction::INS_DESTROY_ATT_IDS_CMD, input, cborOutData);

    if(errorCode == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true, oprCtx_);
    }
    return errorCode;
}

Return<void> JavacardKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams, const HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<KeyParameter> outParams;
    uint64_t operationHandle = 0;
    hidl_vec<KeyParameter> resultParams;
    uint64_t generatedOpHandle = 0;

    if(keyBlob.size() == 0) {
        LOG(ERROR) << "Error in INS_BEGIN_OPERATION_CMD, keyblob size is 0";
        _hidl_cb(ErrorCode::INVALID_ARGUMENT, resultParams, operationHandle);
        return Void();
    }
    /* Asymmetric public key operations like RSA Verify, RSA Encrypt, ECDSA verify
     * are handled by softkeymaster.
     */
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD purpose: " << (int32_t)purpose;
    if (KeyPurpose::ENCRYPT == purpose || KeyPurpose::VERIFY == purpose) {
        BeginOperationRequest request;
        request.purpose = legacy_enum_conversion(purpose);
        request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        BeginOperationResponse response;
        /* For Symmetric key operation, the BeginOperation returns KM_ERROR_INCOMPATIBLE_ALGORITHM error. */
        softKm_->BeginOperation(request, &response);
        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD softkm BeginOperation status: " << (int32_t) errorCode;
        if (errorCode != ErrorCode::OK)
            LOG(ERROR) << "INS_BEGIN_OPERATION_CMD error in softkm BeginOperation status: " << (int32_t) errorCode;

        if (response.error == KM_ERROR_OK) {
            resultParams = kmParamSet2Hidl(response.output_params);
        }
        if (response.error != KM_ERROR_INCOMPATIBLE_ALGORITHM) { /*Incompatible algorithm could be handled by JavaCard*/
            errorCode = legacy_enum_conversion(response.error);
            /* Create a new operation handle and add a entry inside the operation table map with
             * key - new operation handle
             * value - hal generated operation handle.
             */
            if (errorCode == ErrorCode::OK) {
                errorCode = createOprHandleEntry(response.op_handle, SW_KM_OPR, generatedOpHandle);
                if (errorCode != ErrorCode::OK)
                    LOG(ERROR) << "INS_BEGIN_OPERATION_CMD error while creating new operation handle: " << (int32_t) errorCode;
            }
            _hidl_cb(errorCode, resultParams, generatedOpHandle);
            return Void();
        }
    }

    cppbor::Array array;
    std::vector<uint8_t> cborOutData;
    std::unique_ptr<Item> item;
    std::unique_ptr<Item> blobItem = nullptr;
    KeyCharacteristics keyCharacteristics;
    KeyParameter param;

    /* Convert input data to cbor format */
    array.add(static_cast<uint64_t>(purpose));
    array.add(std::vector<uint8_t>(keyBlob));
    cborConverter_.addKeyparameters(array, inParams);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    // keyCharacteristics.hardwareEnforced is required to store algorithm, digest and padding values in operationInfo
    // structure. To retrieve keyCharacteristics.hardwareEnforced, call getKeyCharacateristics.
    // By calling getKeyCharacateristics also helps in finding a corrupted keyblob.
    hidl_vec<uint8_t> applicationId;
    hidl_vec<uint8_t> applicationData;
    if(getTag(inParams, Tag::APPLICATION_ID, param)) {
        applicationId = param.blob;
    }
    if(getTag(inParams, Tag::APPLICATION_DATA, param)) {
        applicationData = param.blob;
    }
    //Call to getKeyCharacteristics.
    getKeyCharacteristics(keyBlob, applicationId, applicationData,
            [&](ErrorCode error, KeyCharacteristics keyChars) {
            errorCode = error;
            keyCharacteristics = keyChars;
            });
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD getKeyCharacteristics status: " << (int32_t) errorCode;

    if(errorCode == ErrorCode::OK) {
        errorCode = ErrorCode::UNKNOWN_ERROR;
        if(getTag(keyCharacteristics.hardwareEnforced, Tag::ALGORITHM, param)) {
            errorCode = sendData(Instruction::INS_BEGIN_OPERATION_CMD, cborData, cborOutData);
            if(errorCode == ErrorCode::OK) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true, oprCtx_);
                if (item != nullptr) {
                    if(!cborConverter_.getKeyParameters(item, 1, outParams) ||
                            !cborConverter_.getUint64(item, 2, operationHandle)) {
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        outParams.setToExternal(nullptr, 0);
                        operationHandle = 0;
                        LOG(ERROR) << "INS_BEGIN_OPERATION_CMD: error in converting cbor data, status: " << (int32_t) errorCode;
                    } else {
                        /* Store the operationInfo */
                        oprCtx_->setOperationInfo(operationHandle, purpose, param.f.algorithm, inParams);
                    }
                }
            }
        } else {
            LOG(ERROR) << "INS_BEGIN_OPERATION_CMD couldn't find algorithm tag: " << (int32_t)Tag::ALGORITHM;
        }
    } else {
        LOG(ERROR) << "INS_BEGIN_OPERATION_CMD error in getKeyCharacteristics status: " << (int32_t) errorCode;
    }
    /* Create a new operation handle and add a entry inside the operation table map with
     * key - new operation handle
     * value - hal generated operation handle.
     */
    if (ErrorCode::OK == errorCode)
        errorCode = createOprHandleEntry(operationHandle, SB_KM_OPR, generatedOpHandle);

    _hidl_cb(errorCode, outParams, generatedOpHandle);
    return Void();
}

Return<void> JavacardKeymaster4Device::update(uint64_t halGeneratedOprHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, update_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    uint32_t inputConsumed = 0;
    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;
    uint64_t operationHandle;
    UpdateOperationResponse response;
    if (ErrorCode::OK != (errorCode = getOrigOperationHandle(halGeneratedOprHandle, operationHandle))) {
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle is passed or if"
            << " secure element reset occurred.";
        _hidl_cb(errorCode, inputConsumed, outParams, output);
        return Void();
    }

    if (!isStrongboxOperation(halGeneratedOprHandle)) {
        /* SW keymaster (Public key operation) */
        LOG(DEBUG) << "INS_UPDATE_OPERATION_CMD - swkm operation ";
        UpdateOperationRequest request;
        request.op_handle = operationHandle;
        request.input.Reinitialize(input.data(), input.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        softKm_->UpdateOperation(request, &response);
        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "INS_UPDATE_OPERATION_CMD - swkm update operation status: "
                   << (int32_t) errorCode;
        if (response.error == KM_ERROR_OK) {
            inputConsumed = response.input_consumed;
            outParams = kmParamSet2Hidl(response.output_params);
            output = kmBuffer2hidlVec(response.output);
        } else {
          LOG(ERROR) << "INS_UPDATE_OPERATION_CMD - error swkm update operation status: "
                     << (int32_t) errorCode;
        }
    } else {
        /* Strongbox Keymaster operation */
        std::vector<uint8_t> tempOut;
        /* OperationContext calls this below sendDataCallback callback function. This callback
         * may be called multiple times if the input data is larger than MAX_ALLOWED_INPUT_SIZE.
         */
        auto sendDataCallback = [&](std::vector<uint8_t>& data, bool) -> ErrorCode {
            cppbor::Array array;
            std::unique_ptr<Item> item;
            std::vector<uint8_t> cborOutData;
            std::vector<uint8_t> asn1ParamsVerified;
            // For symmetic ciphers only block aligned data is send to javacard Applet to reduce the number of calls to
            //javacard. If the input message is less than block size then it is buffered inside the HAL. so in case if
            // after buffering there is no data to send to javacard don't call javacard applet.
            //For AES GCM operations, even though the input length is 0(which is not block aligned), if there is
            //ASSOCIATED_DATA present in KeyParameters. Then we need to make a call to javacard Applet.
            if(data.size() == 0 && !findTag(inParams, Tag::ASSOCIATED_DATA)) {
                //Return OK, since this is not error case.
                LOG(DEBUG) << "sendDataCallback: data size is zero";
                return ErrorCode::OK;
            }

            if(ErrorCode::OK != (errorCode = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
                LOG(ERROR) << "sendDataCallback: error in encodeParametersVerified status: "
                           << (int32_t) errorCode;
                return errorCode;
            }

            // Convert input data to cbor format
            array.add(operationHandle);
            cborConverter_.addKeyparameters(array, inParams);
            array.add(data);
            cborConverter_.addHardwareAuthToken(array, authToken);
            cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
            std::vector<uint8_t> cborData = array.encode();

            errorCode = sendData(Instruction::INS_UPDATE_OPERATION_CMD, cborData, cborOutData);

            if(errorCode == ErrorCode::OK) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true, oprCtx_);
                if (item != nullptr) {
                    /*Ignore inputConsumed from javacard SE since HAL consumes all the input */
                    //cborConverter_.getUint64(item, 1, inputConsumed);
                    //This callback function may gets called multiple times so parse and get the outParams only once.
                    //Otherwise there can be chance of duplicate entries in outParams. Use tempOut to collect all the
                    //cipher text and finally copy it to the output. getBinaryArray function appends the new cipher text
                    //at the end of the tempOut(std::vector<uint8_t>).
                    if((outParams.size() == 0 && !cborConverter_.getKeyParameters(item, 2, outParams)) ||
                            !cborConverter_.getBinaryArray(item, 3, tempOut)) {
                        outParams.setToExternal(nullptr, 0);
                        tempOut.clear();
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        LOG(ERROR) << "sendDataCallback: INS_UPDATE_OPERATION_CMD: error while converting cbor data, status: " << (int32_t) errorCode;
                    }
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
        LOG(DEBUG) << "Update operation status: " << (int32_t) errorCode;
        if(ErrorCode::OK != errorCode) {
            LOG(ERROR) << "Error in update operation, status: " << (int32_t) errorCode;
            abort(halGeneratedOprHandle);
        }
    }
    if(ErrorCode::OK != errorCode) {
        /* Delete the entry from operation table. */
        LOG(ERROR) << "Delete entry from operation table, status: " << (int32_t) errorCode;
        deleteOprHandleEntry(halGeneratedOprHandle);
    }

    _hidl_cb(errorCode, inputConsumed, outParams, output);
    return Void();
}

Return<void> JavacardKeymaster4Device::finish(uint64_t halGeneratedOprHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, finish_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    uint64_t operationHandle;
    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;
    FinishOperationResponse response;

    if (ErrorCode::OK != (errorCode = getOrigOperationHandle(halGeneratedOprHandle, operationHandle))) {
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle is passed or if"
            << " secure element reset occurred.";
        _hidl_cb(errorCode, outParams, output);
        return Void();
    }

    if (!isStrongboxOperation(halGeneratedOprHandle)) {
        /* SW keymaster (Public key operation) */
        LOG(DEBUG) << "FINISH - swkm operation ";
        FinishOperationRequest request;
        request.op_handle = operationHandle;
        request.input.Reinitialize(input.data(), input.size());
        request.signature.Reinitialize(signature.data(), signature.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        softKm_->FinishOperation(request, &response);

        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "FINISH - swkm operation, status: " << (int32_t) errorCode;

        if (response.error == KM_ERROR_OK) {
            outParams = kmParamSet2Hidl(response.output_params);
            output = kmBuffer2hidlVec(response.output);
        } else {
            LOG(ERROR) << "Error in finish operation, status: " << (int32_t) errorCode;
        }
    } else {
        /* Strongbox Keymaster operation */
        std::vector<uint8_t> tempOut;
        bool aadTag = false;
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
            std::vector<uint8_t> asn1ParamsVerified;

            if(ErrorCode::OK != (errorCode = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
                LOG(ERROR) << "sendDataCallback: Error in encodeParametersVerified, status: " << (int32_t) errorCode;
                return errorCode;
            }

            //In case if there is ASSOCIATED_DATA present in the keyparams, then make sure it is either passed with
            //update call or finish call. Don't send ASSOCIATED_DATA in both update and finish calls. aadTag is used to
            //check if ASSOCIATED_DATA is already sent in update call. If addTag is true then skip ASSOCIATED_DATA from
            //keyparams in finish call.
            // Convert input data to cbor format
            array.add(operationHandle);
            if(finish) {
                std::vector<KeyParameter> finishParams;
                LOG(DEBUG) << "sendDataCallback: finish operation";
                if(aadTag) {
                    for(int i = 0; i < inParams.size(); i++) {
                        if(inParams[i].tag != Tag::ASSOCIATED_DATA)
                            finishParams.push_back(inParams[i]);
                    }
                } else {
                    finishParams = inParams;
                }
                cborConverter_.addKeyparameters(array, finishParams);
                array.add(data);
                array.add(std::vector<uint8_t>(signature));
                ins = Instruction::INS_FINISH_OPERATION_CMD;
                keyParamPos = 1;
                outputPos = 2;
            } else {
                LOG(DEBUG) << "sendDataCallback: update operation";
                if(findTag(inParams, Tag::ASSOCIATED_DATA)) {
                    aadTag = true;
                }
                cborConverter_.addKeyparameters(array, inParams);
                array.add(data);
                ins = Instruction::INS_UPDATE_OPERATION_CMD;
                keyParamPos = 2;
                outputPos = 3;
            }
            cborConverter_.addHardwareAuthToken(array, authToken);
            cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
            std::vector<uint8_t> cborData = array.encode();
            errorCode = sendData(ins, cborData, cborOutData);

            if(errorCode == ErrorCode::OK) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true, oprCtx_);
                if (item != nullptr) {
                    //There is a change that this finish callback may gets called multiple times if the input data size
                    //is larger the MAX_ALLOWED_INPUT_SIZE (Refer OperationContext) so parse and get the outParams only
                    //once. Otherwise there can be chance of duplicate entries in outParams. Use tempOut to collect all
                    //the cipher text and finally copy it to the output. getBinaryArray function appends the new cipher
                    //text at the end of the tempOut(std::vector<uint8_t>).
                    if((outParams.size() == 0 && !cborConverter_.getKeyParameters(item, keyParamPos, outParams)) ||
                            !cborConverter_.getBinaryArray(item, outputPos, tempOut)) {
                        outParams.setToExternal(nullptr, 0);
                        tempOut.clear();
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        LOG(ERROR) << "sendDataCallback: error while converting cbor data in operation: " << (int32_t)ins << " decodeData, status: " << (int32_t) errorCode;
                    }
                }
            }
            return errorCode;
        };
        if(ErrorCode::OK == (errorCode = oprCtx_->finish(operationHandle, std::vector<uint8_t>(input),
                        sendDataCallback))) {
            output = tempOut;
        }
        if (ErrorCode::OK != errorCode) {
            LOG(ERROR) << "Error in finish operation, status: " << (int32_t) errorCode;
            abort(halGeneratedOprHandle);
        }
    }
    /* Delete the entry from operation table. */
    deleteOprHandleEntry(halGeneratedOprHandle);
    oprCtx_->clearOperationData(operationHandle);
    LOG(DEBUG) << "finish operation, status: " << (int32_t) errorCode;
    _hidl_cb(errorCode, outParams, output);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::abort(uint64_t halGeneratedOprHandle) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    uint64_t operationHandle;
    if (ErrorCode::OK != (errorCode = getOrigOperationHandle(halGeneratedOprHandle, operationHandle))) {
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle is passed or if"
            << " secure element reset occurred.";
        return errorCode;
    }
    AbortOperationRequest request;
    request.op_handle = operationHandle;

    AbortOperationResponse response;
    softKm_->AbortOperation(request, &response);

    errorCode = legacy_enum_conversion(response.error);
    LOG(DEBUG) << "swkm abort operation, status: " << (int32_t) errorCode;
    if (response.error == KM_ERROR_INVALID_OPERATION_HANDLE) {
        cppbor::Array array;
        std::unique_ptr<Item> item;
        std::vector<uint8_t> cborOutData;

        /* Convert input data to cbor format */
        array.add(operationHandle);
        std::vector<uint8_t> cborData = array.encode();

        errorCode = sendData(Instruction::INS_ABORT_OPERATION_CMD, cborData, cborOutData);

        if(errorCode == ErrorCode::OK) {
            //Skip last 2 bytes in cborData, it contains status.
            std::tie(item, errorCode) = decodeData(cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                    true, oprCtx_);
        }
    }
    /* Delete the entry on this operationHandle */
    oprCtx_->clearOperationData(operationHandle);
    deleteOprHandleEntry(halGeneratedOprHandle);
    return errorCode;
}

// Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::deviceLocked(bool passwordOnly, const VerificationToken& verificationToken) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    ::android::hardware::keymaster::V4_1::ErrorCode errorCode = ::android::hardware::keymaster::V4_1::ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> asn1ParamsVerified;
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    if(ErrorCode::OK != (ret = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
        LOG(DEBUG) << "INS_DEVICE_LOCKED_CMD: Error in encodeParametersVerified, status: " << (int32_t) errorCode;
        return errorCode;
    }

    /* Convert input data to cbor format */
    array.add(passwordOnly);
    cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
    std::vector<uint8_t> cborData = array.encode();

    ret = sendData(Instruction::INS_DEVICE_LOCKED_CMD, cborData, cborOutData);

    if(ret == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData<::android::hardware::keymaster::V4_1::ErrorCode>(
                cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2), true, oprCtx_);
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

    if(ret == ErrorCode::OK) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData<::android::hardware::keymaster::V4_1::ErrorCode>(
                cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2), true, oprCtx_);
    }
    return errorCode;
}

}  // javacard
}  // namespace V4_1
}  // namespace keymaster
