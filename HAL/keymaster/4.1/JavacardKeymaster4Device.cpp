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
#include <openssl/aes.h>

#include <JavacardKeymaster4Device.h>
#include <JavacardSoftKeymasterContext.h>
#include <CommonUtils.h>
#include <android-base/logging.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

#define JAVACARD_KEYMASTER_NAME      "JavacardKeymaster4.1Device v0.1"
#define JAVACARD_KEYMASTER_AUTHOR    "Android Open Source Project"

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
//This key is used as master key for computing Hmac shared secret.
constexpr uint8_t kFakeKeyAgreementKey[32] = {};

static std::unique_ptr<se_transport::TransportFactory> pTransportFactory = nullptr;
constexpr size_t kOperationTableSize = 4;

struct KM_AUTH_LIST_Delete {
    void operator()(KM_AUTH_LIST* p) { KM_AUTH_LIST_free(p); }
};

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
        pTransportFactory->openConnection();
    }
    return pTransportFactory;
}

static inline bool readDataFromFile(const char *filename, std::vector<uint8_t>& data) {
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

static inline X509* parseDerCertificate(const char* filename) {
    X509 *x509 = NULL;
    std::vector<uint8_t> certData;

    /* Read the Root certificate */
    if(!readDataFromFile(filename, certData)) {
        LOG(ERROR) << " Failed to read the Root certificate";
        return NULL;
    }
    /* Create BIO instance from certificate data */
    BIO *bio = BIO_new_mem_buf(certData.data(), certData.size());
    if(bio == NULL) {
        LOG(ERROR) << " Failed to create BIO from buffer.";
        return NULL;
    }
    /* Create X509 instance from BIO */
    x509 = d2i_X509_bio(bio, NULL);
    if(x509 == NULL) {
        LOG(ERROR) << " Failed to get X509 instance from BIO.";
        return NULL;
    }
    BIO_free(bio);
    return x509;
}

static inline void getDerSubjectName(X509* x509, std::vector<uint8_t>& subject) {
    uint8_t *subjectDer = NULL;
    X509_NAME* asn1Subject = X509_get_subject_name(x509);
    if(asn1Subject == NULL) {
        LOG(ERROR) << " Failed to read the subject.";
        return;
    }
    /* Convert X509_NAME to der encoded subject */
    int len = i2d_X509_NAME(asn1Subject, &subjectDer);
    if (len < 0) {
        LOG(ERROR) << " Failed to get readable name from X509_NAME.";
        return;
    }
    subject.insert(subject.begin(), subjectDer, subjectDer+len);
}

static inline void getAuthorityKeyIdentifier(X509* x509, std::vector<uint8_t>& authKeyId) {
    long xlen;
    int tag, xclass;

    int loc = X509_get_ext_by_NID(x509, NID_authority_key_identifier, -1);
    X509_EXTENSION *ext = X509_get_ext(x509, loc);
    if(ext == NULL) {
        LOG(ERROR) << " Failed to read authority key identifier.";
        return;
    }

    ASN1_OCTET_STRING *asn1AuthKeyId = X509_EXTENSION_get_data(ext);
    const uint8_t *strAuthKeyId = ASN1_STRING_get0_data(asn1AuthKeyId);
    int strAuthKeyIdLen = ASN1_STRING_length(asn1AuthKeyId);
    int ret = ASN1_get_object(&strAuthKeyId, &xlen, &tag, &xclass, strAuthKeyIdLen);
    if (ret == 0x80 || strAuthKeyId == NULL) {
        LOG(ERROR) << "Failed to get the auth key identifier from ASN1 sequence.";
        return;
    }
    authKeyId.insert(authKeyId.begin(), strAuthKeyId, strAuthKeyId + xlen);
}

static inline void getNotAfter(X509* x509, std::vector<uint8_t>& notAfterDate) {
    const ASN1_TIME* notAfter = X509_get0_notAfter(x509);
    if(notAfter == NULL) {
        LOG(ERROR) << " Failed to read expiry time.";
        return;
    }
    int strNotAfterLen = ASN1_STRING_length(notAfter);
    const uint8_t *strNotAfter = ASN1_STRING_get0_data(notAfter);
    if(strNotAfter == NULL) {
        LOG(ERROR) << " Failed to read expiry time from ASN1 string.";
        return;
    }
    notAfterDate.insert(notAfterDate.begin(), strNotAfter, strNotAfter + strNotAfterLen);
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
            .Authorization(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_KEY_SIZE, 2048)
            .Authorization(TAG_PURPOSE, static_cast<keymaster_purpose_t>(0x7F)) /* The value 0x7F is not present in types.hal */
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
    X509 *x509 = NULL;
    std::vector<uint8_t> subject;
    std::vector<uint8_t> authorityKeyIdentifier;
    std::vector<uint8_t> notAfter;
    std::vector<uint8_t> masterKey(kFakeKeyAgreementKey, kFakeKeyAgreementKey +
    sizeof(kFakeKeyAgreementKey)/sizeof(kFakeKeyAgreementKey[0]));

    /* Subject, AuthorityKeyIdentifier and Expirty time of the root certificate are required by javacard. */
    /* Get X509 certificate instance for the root certificate.*/
    if(NULL == (x509 = parseDerCertificate(ROOT_RSA_CERT))) {
        return errorCode;
    }

    if(ErrorCode::OK != (errorCode = prepareCborArrayFromKeyData(keyParams, keyFormat, keyData, subArray))) {
        return errorCode;
    }
    /* Get subject in DER */
    getDerSubjectName(x509, subject);
    /* Get AuthorityKeyIdentifier */
    getAuthorityKeyIdentifier(x509, authorityKeyIdentifier);
    /* Get Expirty Time */
    getNotAfter(x509, notAfter);
    /*Free X509 */
    X509_free(x509);

    /* construct cbor */
    cborConverter.addKeyparameters(array, keyParams);
    array.add(static_cast<uint32_t>(KeyFormat::RAW));
    std::vector<uint8_t> encodedArray = subArray.encode();
    cppbor::Bstr bstr(encodedArray.begin(), encodedArray.end());
    array.add(bstr);
    array.add(subject);
    array.add(notAfter);
    array.add(authorityKeyIdentifier);
    array.add(masterKey);
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
    if(ret == ErrorCode::SECURE_HW_COMMUNICATION_FAILED) {
        //Socket not connected.
        _hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
        return Void();
    } else {
        if((ret == ErrorCode::OK) && (resp.size() > 2)) {
            //Skip last 2 bytes in cborData, it contains status.
            std::tie(item, ret) = cborConverter_.decodeData(std::vector<uint8_t>(resp.begin(), resp.end()-2),
                    true);
            if (item != nullptr) {
                std::vector<uint8_t> temp;
                if(!cborConverter_.getUint64(item, 0, securityLevel) ||
                        !cborConverter_.getBinaryArray(item, 1, jcKeymasterName) ||
                        !cborConverter_.getBinaryArray(item, 2, jcKeymasterAuthor)) {
                    _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
                    return Void();
                }
            }
        }
        _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
        return Void();
    }
}

Return<void> JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    /* TODO temporary fix: vold daemon calls performHmacKeyAgreement. At that time when vold calls this API there is no
     * network connectivity and socket cannot be connected. So as a hack we are calling softkeymaster to getHmacSharing
     * parameters.
     */
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> input;
    std::unique_ptr<Item> item;
    HmacSharingParameters hmacSharingParameters;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;

    errorCode = sendData(Instruction::INS_GET_HMAC_SHARING_PARAM_CMD, input, cborData);
    if(errorCode == ErrorCode::SECURE_HW_COMMUNICATION_FAILED) {
        auto response = softKm_->GetHmacSharingParameters();
        ::android::hardware::keymaster::V4_0::HmacSharingParameters params;
        params.seed.setToExternal(const_cast<uint8_t*>(response.params.seed.data),
                response.params.seed.data_length);
        static_assert(sizeof(response.params.nonce) == params.nonce.size(), "Nonce sizes don't match");
        memcpy(params.nonce.data(), response.params.nonce, params.nonce.size());
        _hidl_cb(legacy_enum_conversion(response.error), params);
        return Void();
    } else {
        if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
            //Skip last 2 bytes in cborData, it contains status.
            std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborData.begin(), cborData.end()-2),
                    true);
            if (item != nullptr) {
                if(!cborConverter_.getHmacSharingParameters(item, 1, hmacSharingParameters)) {
                    errorCode = ErrorCode::UNKNOWN_ERROR;
                }
            }
        }
        _hidl_cb(errorCode, hmacSharingParameters);
        return Void();
    }
}

Return<void> JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    /* TODO temporary fix: vold daemon calls performHmacKeyAgreement. At that time when vold calls this API there is no
     * network connectivity and socket cannot be connected. So as a hack we are calling softkeymaster to
     * computeSharedHmac.
     */
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;
    hidl_vec<uint8_t> sharingCheck;

    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> tempVec;
    cppbor::Array outerArray;
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
    if(errorCode == ErrorCode::SECURE_HW_COMMUNICATION_FAILED) {
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

        auto response = softKm_->ComputeSharedHmac(request);
        hidl_vec<uint8_t> sharing_check;
        if (response.error == KM_ERROR_OK) sharing_check = kmBlob2hidlVec(response.sharing_check);

        _hidl_cb(legacy_enum_conversion(response.error), sharing_check);
        return Void();

    } else {
        if((errorCode == ErrorCode::OK) && (cborData.size() > 2)) {
            //Skip last 2 bytes in cborData, it contains status.
            std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                    true);
            if (item != nullptr) {
                std::vector<uint8_t> bstr;
                if(!cborConverter_.getBinaryArray(item, 1, bstr)) {
                    errorCode = ErrorCode::UNKNOWN_ERROR;
                } else {
                    sharingCheck = bstr;
                }
            }
        }
        _hidl_cb(errorCode, sharingCheck);
        return Void();
    }

}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t , const hidl_vec<KeyParameter>& , const HardwareAuthToken& , verifyAuthorization_cb _hidl_cb) {
    VerificationToken verificationToken;
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

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            if(!cborConverter_.getBinaryArray(item, 1, keyBlob) ||
                    !cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics)) {
                //Clear the buffer.
                keyBlob.setToExternal(nullptr, 0);
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
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
        _hidl_cb(ErrorCode::UNSUPPORTED_KEY_FORMAT, keyBlob, keyCharacteristics);
        return Void();
    }
    cborConverter_.addKeyparameters(array, keyParams);
    array.add(static_cast<uint32_t>(KeyFormat::RAW)); //javacard accepts only RAW.
    if(ErrorCode::OK != (errorCode = prepareCborArrayFromKeyData(keyParams, keyFormat, keyData, subArray))) {
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
            if(!cborConverter_.getBinaryArray(item, 1, keyBlob) ||
                    !cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics)) {
                //Clear the buffer.
                keyBlob.setToExternal(nullptr, 0);
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
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
            if(!cborConverter_.getBinaryArray(item, 1, keyBlob) ||
                    !cborConverter_.getKeyCharacteristics(item, 2, keyCharacteristics)) {
                //Clear the buffer.
                keyBlob.setToExternal(nullptr, 0);
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
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

    if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                true);
        if (item != nullptr) {
            if(!cborConverter_.getKeyCharacteristics(item, 1, keyCharacteristics)) {
                keyCharacteristics.softwareEnforced.setToExternal(nullptr, 0);
                keyCharacteristics.hardwareEnforced.setToExternal(nullptr, 0);
                errorCode = ErrorCode::UNKNOWN_ERROR;
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
    }
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
            if(!cborConverter_.getMultiBinaryArray(item, 1, temp)) {
                errorCode = ErrorCode::UNKNOWN_ERROR;
            } else {
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
            if(!cborConverter_.getBinaryArray(item, 1, upgradedKeyBlob))
                errorCode = ErrorCode::UNKNOWN_ERROR;
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
    hidl_vec<KeyParameter> resultParams;

    if(keyBlob.size() == 0) {
        _hidl_cb(ErrorCode::INVALID_ARGUMENT, resultParams, operationHandle);
        return Void();
    }

    if (KeyPurpose::ENCRYPT == purpose || KeyPurpose::VERIFY == purpose) {
        BeginOperationRequest request;
        request.purpose = legacy_enum_conversion(purpose);
        request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        BeginOperationResponse response;
        softKm_->BeginOperation(request, &response);

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

    if(errorCode == ErrorCode::OK) {
        errorCode = ErrorCode::UNKNOWN_ERROR;
        if(getTag(keyCharacteristics.hardwareEnforced, Tag::ALGORITHM, param)) {
            errorCode = sendData(Instruction::INS_BEGIN_OPERATION_CMD, cborData, cborOutData);
            if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true);
                if (item != nullptr) {
                    if(!cborConverter_.getKeyParameters(item, 1, outParams) ||
                            !cborConverter_.getUint64(item, 2, operationHandle)) {
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        outParams.setToExternal(nullptr, 0);
                        operationHandle = 0;
                    } else {
                        /* Store the operationInfo */
                        oprCtx_->setOperationInfo(operationHandle, purpose, param.f.algorithm, inParams);
                    }
                }
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
            std::vector<uint8_t> asn1ParamsVerified;
            // For symmetic ciphers only block aligned data is send to javacard Applet to reduce the number of calls to
            //javacard. If the input message is less than block size then it is buffered inside the HAL. so in case if
            // after buffering there is no data to send to javacard don't call javacard applet.
            //For AES GCM operations, even though the input length is 0(which is not block aligned), if there is
            //ASSOCIATED_DATA present in KeyParameters. Then we need to make a call to javacard Applet.
            if(data.size() == 0 && !findTag(inParams, Tag::ASSOCIATED_DATA)) {
                //Return OK, since this is not error case.
                return ErrorCode::OK;
            }

            if(ErrorCode::OK != (errorCode = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
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

            if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true);
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
    }
    if(ErrorCode::OK != errorCode) {
        abort(operationHandle);
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

            if((errorCode == ErrorCode::OK) && (cborOutData.size() > 2)) {
                //Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) = cborConverter_.decodeData(std::vector<uint8_t>(cborOutData.begin(), cborOutData.end()-2),
                        true);
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
                    }
                }
            }
            return errorCode;
        };
        if(ErrorCode::OK == (errorCode = oprCtx_->finish(operationHandle, std::vector<uint8_t>(input),
                        sendDataCallback))) {
            output = tempOut;
        }
    }
    abort(operationHandle);
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
    std::vector<uint8_t> asn1ParamsVerified;
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    if(ErrorCode::OK != (ret = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
        return errorCode;
    }

    /* Convert input data to cbor format */
    array.add(passwordOnly);
    cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
    std::vector<uint8_t> cborData = array.encode();

    /* TODO DeviceLocked command handled inside HAL */
    ret = sendData(Instruction::INS_DEVICE_LOCKED_CMD, cborData, cborOutData);

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
