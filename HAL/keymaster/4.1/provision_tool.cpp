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
#include <fstream>
#include <unistd.h>
#include <getopt.h>
#include <utils/StrongPointer.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#include <keymaster/authorization_set.h>
#include <android-base/properties.h>
#include <android-base/logging.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <CommonUtils.h>
#include <TransportFactory.h>
#include <json/reader.h>
#include <json/value.h>

#define BUFFER_MAX_LENGTH 256
#define SB_KEYMASTER_SERVICE "javacard"
#define INS_BEGIN_KM_CMD 0x00
#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000
#define MAX_ATTEST_IDS_SIZE 8
#define SHARED_SECRET_SIZE 32

enum class Instruction {
    // Provisioning commands
    INS_PROVISION_ATTESTATION_KEY_CMD = INS_BEGIN_KM_CMD+1,
    INS_PROVISION_CERT_CHAIN_CMD = INS_BEGIN_KM_CMD+2,
    INS_PROVISION_CERT_PARAMS_CMD = INS_BEGIN_KM_CMD+3,
    INS_PROVISION_ATTEST_IDS_CMD = INS_BEGIN_KM_CMD+4,
    INS_PROVISION_SHARED_SECRET_CMD = INS_BEGIN_KM_CMD+5,
    INS_SET_BOOT_PARAMS_CMD = INS_BEGIN_KM_CMD+6,
    INS_LOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD+7,
    INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD+8,
};

enum ProvisionStatus {
    NOT_PROVISIONED = 0x00,
    PROVISION_STATUS_ATTESTATION_KEY = 0x01,
    PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02,
    PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04,
    PROVISION_STATUS_ATTEST_IDS = 0x08,
    PROVISION_STATUS_SHARED_SECRET = 0x10,
    PROVISION_STATUS_BOOT_PARAM = 0x20,
    PROVISION_STATUS_PROVISIONING_LOCKED = 0x40,
};

using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::EcCurve;
using ::android::hardware::keymaster::V4_0::HardwareAuthenticatorType;
using ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using ::android::hardware::keymaster::V4_0::HmacSharingParameters;
using ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using ::android::hardware::keymaster::V4_0::KeyFormat;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::KeyPurpose;
using ::android::hardware::keymaster::V4_0::OperationHandle;
using ::android::hardware::keymaster::V4_0::SecurityLevel;
using ::android::hardware::keymaster::V4_0::VerificationToken;
using ::android::hardware::keymaster::V4_0::Tag;
using ::android::hardware::keymaster::V4_1::IKeymasterDevice;
using ::android::sp;
using se_transport::TransportFactory;

static sp<IKeymasterDevice> sbKeymaster;
static TransportFactory *pTransportFactory;
Json::Value root;

constexpr char hex_value[256] = {0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 1,  2,  3,  4,  5,  6,  7, 8, 9, 0, 0, 0, 0, 0, 0,  // '0'..'9'
                                 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'A'..'F'
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'a'..'f'
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0};

std::string hex2str(std::string a) { 
    std::string b;
    size_t num = a.size() / 2;
    b.resize(num);
    for (size_t i = 0; i < num; i++) {
        b[i] = (hex_value[a[i * 2] & 0xFF] << 4) + (hex_value[a[i * 2 + 1] & 0xFF]);
    }    
    return b;
}

//static function declarations.
static ErrorCode constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut, bool
extendedOutput);
static ErrorCode sendProvisionData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response, bool
extendedOutput);
static Tag mapAttestKeyToAttestTag(std::string key);
bool parseJsonFile(const char* filename);

static bool readDataFromFile(const char *filename, std::vector<uint8_t>& data) {
    FILE *fp;
    bool ret = true;
    fp = fopen(filename, "rb");
    if(fp == NULL) {
        printf("\nFailed to open file: \n");
        return false;
    }
    fseek(fp, 0L, SEEK_END);
    long int filesize = ftell(fp);
    rewind(fp);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[filesize]);
    if( 0 == fread(buf.get(), filesize, 1, fp)) {
        printf("\n No content in the file \n");
        ret = false;
    }
    if(true == ret) {
        data.insert(data.end(), buf.get(), buf.get() + filesize);
    }
    fclose(fp);
    return ret;
}

static inline X509* parseDerCertificate(std::vector<uint8_t>& certData) {
    X509 *x509 = NULL;

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

static inline uint16_t getStatus(std::vector<uint8_t>& inputData) {
    //Last two bytes are the status SW0SW1
    return (inputData.at(inputData.size()-2) << 8) | (inputData.at(inputData.size()-1));
}

static inline TransportFactory* getTransportFactoryInstance() {
    if(pTransportFactory == nullptr) {
        pTransportFactory = new se_transport::TransportFactory(
                    android::base::GetBoolProperty("ro.kernel.qemu", false));
        pTransportFactory->openConnection();
    }
    return pTransportFactory;
}

static Tag  mapAttestKeyToAttestTag(std::string keyStr) {
    Tag tag = Tag::INVALID;

    if (0 == keyStr.compare("brand")) {
        tag = Tag::ATTESTATION_ID_BRAND;
    } else if(0 == keyStr.compare("device")) {
        tag = Tag::ATTESTATION_ID_DEVICE;
    } else if(0 == keyStr.compare("product")) {
        tag = Tag::ATTESTATION_ID_PRODUCT;
    } else if(0 == keyStr.compare("serial")) {
        tag = Tag::ATTESTATION_ID_SERIAL;
    } else if(0 == keyStr.compare("imei")) {
        tag = Tag::ATTESTATION_ID_IMEI;
    } else if(0 == keyStr.compare("meid")) {
        tag = Tag::ATTESTATION_ID_MEID;
    } else if(0 == keyStr.compare("manufacturer")) {
        tag = Tag::ATTESTATION_ID_MANUFACTURER;
    } else if(0 == keyStr.compare("model")) {
        tag = Tag::ATTESTATION_ID_MODEL;
    }
    return tag;
}

static ErrorCode constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut, bool
extendedOutput) {
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
        if(extendedOutput)
            apduOut.push_back(static_cast<uint8_t>(0x00));

    } else {
        return (ErrorCode::INSUFFICIENT_BUFFER_SPACE);
    }

    return (ErrorCode::OK);//success
}

static ErrorCode sendProvisionData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response, bool
extendedOutput=false) {
    ErrorCode ret = ErrorCode::OK;
    std::vector<uint8_t> apdu;
    CborConverter cborConverter;
    std::unique_ptr<Item> item;
    ret = constructApduMessage(ins, inData, apdu, extendedOutput);
    if(ret != ErrorCode::OK) return ret;

    if(!pTransportFactory->sendData(apdu.data(), apdu.size(), response)) {
        return (ErrorCode::SECURE_HW_COMMUNICATION_FAILED);
    }

    if((response.size() < 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return (ErrorCode::UNKNOWN_ERROR);
    }

    if((response.size() > 2)) {
        //Skip last 2 bytes in cborData, it contains status.
        std::tie(item, ret) = cborConverter.decodeData(std::vector<uint8_t>(response.begin(), response.end()-2),
                true);
    } else {
        ret = ErrorCode::UNKNOWN_ERROR;
    }

    return ret;
}

void usage() {
    printf("Usage: provision_tool [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-a, --all jsonFile \t Executes all the provision commands \n");
    printf("-k, --attest_key jsonFile \t Provision attestation key \n");
    printf("-c, --cert_chain jsonFile \t Provision attestation certificate chain \n");
    printf("-p, --cert_params jsonFile \t Provision attestation certificate parameters \n");
    printf("-i, --attest_ids jsonFile \t Provision attestation IDs \n");
    printf("-r, --shared_secret jsonFile \t Provion shared secret  \n");
    printf("-b, --set_boot_params jsonFile \t Provion boot parameters  \n");
    printf("-s, --provision_status \t Prints the provision status.\n");
    printf("-l, --lock_provision  \t  Locks the provision commands.\n");
}

bool getBootParameterIntValue(Json::Value& bootParamsObj, const char* key, uint32_t *value) {
    bool ret = false;
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return ret;

    if(!val.isInt())
        return ret;

    *value = (uint32_t)val.asInt();

    return true;
}

bool getBootParameterBlobValue(Json::Value& bootParamsObj, const char* key, std::vector<uint8_t>& blob) {
    bool ret = false;
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return ret;

    if(!val.isString())
        return ret;

    std::string blobStr = hex2str(val.asString());

    for(char ch : blobStr) {
        blob.push_back((uint8_t)ch);
    }

    return true;
}

bool setBootParameters(const char* filename) {
    Json::Value bootParamsObj;
    bool ret = false;

    if(!parseJsonFile(filename))
        return ret;

    bootParamsObj = root.get("set_boot_params", bootParamsObj);
    if (!bootParamsObj.isNull()) {
        cppbor::Array array;
        ErrorCode errorCode = ErrorCode::OK;
        std::vector<uint8_t> apdu;
        std::vector<uint8_t> response;
        Instruction ins = Instruction::INS_SET_BOOT_PARAMS_CMD;
        uint32_t value;
        std::vector<uint8_t> blob;

        if(!getBootParameterIntValue(bootParamsObj, "os_version", &value)) {
            printf("\n Invalid value for os_version or os_version tag missing\n");
            return ret;
        }
        array.add(value);
        if(!getBootParameterIntValue(bootParamsObj, "os_patch_level", &value)) {
            printf("\n Invalid value for os_patch_level or os_patch_level tag missing\n");
            return ret;
        }
        array.add(value);
        if(!getBootParameterIntValue(bootParamsObj, "vendor_patch_level", &value)) {
            printf("\n Invalid value for vendor_patch_level or vendor_patch_level tag missing\n");
            return ret;
        }
        array.add(value);
        if(!getBootParameterIntValue(bootParamsObj, "boot_patch_level", &value)) {
            printf("\n Invalid value for boot_patch_level or boot_patch_level tag missing\n");
            return ret;
        }
        array.add(value);
        if(!getBootParameterBlobValue(bootParamsObj, "verified_boot_key", blob)) {
            printf("\n Invalid value for verified_boot_key or verified_boot_key tag missing\n");
            return ret;
        }
        array.add(blob);
        blob.clear();
        if(!getBootParameterBlobValue(bootParamsObj, "verified_boot_key_hash", blob)) {
            printf("\n Invalid value for verified_boot_key_hash or verified_boot_key_hash tag missing\n");
            return ret;
        }
        array.add(blob);
        blob.clear();
        if(!getBootParameterIntValue(bootParamsObj, "boot_state", &value)) {
            printf("\n Invalid value for boot_state or boot_state tag missing\n");
            return ret;
        }
        array.add(value);
        if(!getBootParameterIntValue(bootParamsObj, "device_locked", &value)) {
            printf("\n Invalid value for device_locked or device_locked tag missing\n");
            return ret;
        }
        array.add(value);

        std::vector<uint8_t> cborData = array.encode();

        if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
            printf("\n Failed to set boot parameters errorCode:%d\n", errorCode);
            return ret;
        }

    } else {
        return ret;
    }
    printf("\n SE successfully accepted boot paramters \n");
    return true;
}

bool provisionAttestationIds(const char *filename) {
    Json::Value attestIds;
    bool ret = false;

    if(!parseJsonFile(filename))
        return ret;

    attestIds = root.get("attest_ids", attestIds);
    if (!attestIds.isNull()) {
        if (attestIds.size() != MAX_ATTEST_IDS_SIZE) {
            return ret;
        }
        Json::Value value;
        std::vector<uint8_t> temp;
        int i = 0;
        std::vector<KeyParameter> params(attestIds.size());
        Json::Value::Members keys = attestIds.getMemberNames();
        Tag tag;
        for(std::string key : keys) {
            if(Tag::INVALID == (tag = mapAttestKeyToAttestTag(key))) {
                break;
            }
            value = attestIds[key];
            if(value.empty()) {
                break;
            }
            params[i].tag = tag;
            for(char ch : value.asString()) {
                temp.push_back((uint8_t)ch);
            }
            params[i].blob.resize(temp.size());
            params[i].blob = temp;
            temp.clear();
            i++;
        }

        if(i != MAX_ATTEST_IDS_SIZE)
            return ret;

        CborConverter cborConverter;
        cppbor::Array array;
        Instruction ins = Instruction::INS_PROVISION_ATTEST_IDS_CMD;
        ErrorCode errorCode = ErrorCode::OK;
        std::vector<uint8_t> response;
        hidl_vec<KeyParameter> attestParams(params);

        //Encode input data into CBOR.
        cborConverter.addKeyparameters(array, attestParams);
        std::vector<uint8_t> cborData = array.encode();

        if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
            printf("\n Failed to provision attestation ids error: %d\n", uint32_t(errorCode));
            return ret;
        }
    } else {
        return ret;
    }
    printf("\n provisioned attestation ids successfully \n");
    return true;
}

bool lockProvision() {
	bool ret = false;
    cppbor::Array array;
    Instruction ins = Instruction::INS_LOCK_PROVISIONING_CMD;
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;

    if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
        printf("\n Failed to lock provisioning error: %d\n", uint32_t(errorCode));
        return ret;
    }
    printf("\n Successfully locked provisioning process. Now SE doesn't accept any further provision commands. \n");
	return true;
}

bool getProvisionStatus() {
	bool ret = false;
    CborConverter cborConverter;
    cppbor::Array array;
    Instruction ins = Instruction::INS_GET_PROVISION_STATUS_CMD;
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;
    std::unique_ptr<Item> item;

    if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
        printf("\n Failed to get provision status error: %d\n", uint32_t(errorCode));
        return ret;
    }
    std::tie(item, errorCode) = cborConverter.decodeData(std::vector<uint8_t>(response.begin(), response.end()-2),
            true);
    if(item != NULL) {
        uint64_t status;

        if(!cborConverter.getUint64(item, 1, status)) {
            printf("\n Failed to get the status value \n");
            return ret;
        } else {
            printf("\nCurrent provision status: %ld\n", status);
        }
    } else {
        return ret;
    }
	return true;
}

bool provisionSharedSecret(const char* filename) {
    Json::Value sharedSecret;
    bool ret = false;

    if(!parseJsonFile(filename))
        return ret;

    sharedSecret = root.get("shared_secret", sharedSecret);
    if (!sharedSecret.isNull()) {
        cppbor::Array array;
        Instruction ins = Instruction::INS_PROVISION_SHARED_SECRET_CMD;
        ErrorCode errorCode = ErrorCode::OK;
        std::vector<uint8_t> response;
        std::string str = sharedSecret.asString();
        std::string secret = hex2str(str);

        //Length of the secret should be 32 bytes.
        if(SHARED_SECRET_SIZE != secret.size()) {
            return ret;
        }
        std::vector<uint8_t> input(secret.data(), secret.data() + secret.length());

        //Encode input data into CBOR.
        array.add(input);
        std::vector<uint8_t> cborData = array.encode();

        if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
            printf("\n Failed to provision shared secret error: %d\n", uint32_t(errorCode));
            return ret;
        }
    } else {
        return ret;
    }
    printf("\n Provisioned shared secret successfully \n");
    return true;
}

static bool provisionAttestationKey(const char* filename) {
    Json::Value keyFile;
    bool ret = false;

    if(!parseJsonFile(filename))
        return ret;

    keyFile = root.get("attest_key", keyFile);
    if (!keyFile.isNull()) {
        ErrorCode errorCode = ErrorCode::OK;
        CborConverter cborConverter;
        cppbor::Array array;
        cppbor::Array subArray;
        std::vector<uint8_t> data;
        std::vector<uint8_t> privKey;
        std::vector<uint8_t> pubKey;
        Instruction ins = Instruction::INS_PROVISION_ATTESTATION_KEY_CMD;
        EcCurve curve;
        std::vector<uint8_t> response;

        std::string keyFileName = keyFile.asString();
        if(!readDataFromFile(keyFileName.data(), data)) {
            printf("\n Failed to read the Root ec key\n");
            return ret;
        }
        keymaster::AuthorizationSet authSetKeyParams(keymaster::AuthorizationSetBuilder()
                .Authorization(keymaster::TAG_ALGORITHM, KM_ALGORITHM_EC)
                .Authorization(keymaster::TAG_DIGEST, KM_DIGEST_SHA_2_256)
                .Authorization(keymaster::TAG_EC_CURVE, KM_EC_CURVE_P_256)
                .Authorization(keymaster::TAG_PURPOSE, static_cast<keymaster_purpose_t>(0x7F))); /* The value 0x7F is not present in types.hal */
        // Read the ECKey from the file.         
        hidl_vec<KeyParameter> keyParams = keymaster::V4_1::javacard::kmParamSet2Hidl(authSetKeyParams);

        if(ErrorCode::OK != (errorCode = keymaster::V4_1::javacard::ecRawKeyFromPKCS8(data, privKey, pubKey, curve))) {
            printf("\n Failed to convert PKCS8 to RAW key\n");
            return ret;
        }
        subArray.add(privKey);
        subArray.add(pubKey);
        std::vector<uint8_t> encodedArray = subArray.encode();
        cppbor::Bstr bstr(encodedArray.begin(), encodedArray.end());

        //Encode data.
        cborConverter.addKeyparameters(array, keyParams);
        array.add(static_cast<uint32_t>(KeyFormat::RAW));
        array.add(bstr);

        std::vector<uint8_t> cborData = array.encode();

        if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
            printf("\n Failed to provision attestation key\n");
            return ret;
        }
    } else {
        return ret;
    }
    printf("\n Provisioned attestation key successfully\n");
    return true;
}

bool provisionAttestationCertificateChain(const char* filename) {
    Json::Value certChainFile;
    bool ret = false;

    if(!parseJsonFile(filename))
        return ret;

    certChainFile = root.get("attest_cert_chain", certChainFile);
    if (!certChainFile.isNull()) {
        ErrorCode errorCode = ErrorCode::OK;
        cppbor::Array array;
        Instruction ins = Instruction::INS_PROVISION_CERT_CHAIN_CMD;
        std::vector<uint8_t> response;

        std::vector<uint8_t> certData;
        std::string strCertChain = certChainFile.asString();
        /* Read the Root certificate */
        if(!readDataFromFile(strCertChain.data(), certData)) {
            printf("\n Failed to read the Root certificate\n");
            return ret;
        }
        cppbor::Bstr certChain(certData.begin(), certData.end());
        std::vector<uint8_t> cborData = certChain.encode();

        if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
            printf("\n Failed to provision cert chain errorCode:%d\n", static_cast<int32_t>(errorCode));
            return ret;
        }
    } else {
        return ret;
    }
    printf("\n Provisioned attestation certificate chain successfully\n");
    return true;
}

bool provisionAttestationCertificateParams(const char* filename) {
    Json::Value certChainFile;
    bool ret = false;

    if(!parseJsonFile(filename))
        return ret;

    certChainFile = root.get("attest_cert_chain", certChainFile);
    if (!certChainFile.isNull()) {
        ErrorCode errorCode = ErrorCode::OK;
        cppbor::Array array;
        Instruction ins = Instruction::INS_PROVISION_CERT_PARAMS_CMD;
        std::vector<uint8_t> response;
        X509 *x509 = NULL;
        std::vector<uint8_t> subject;
        std::vector<uint8_t> authorityKeyIdentifier;
        std::vector<uint8_t> notAfter;
        std::vector<uint8_t> certData;
        std::vector<std::vector<uint8_t>> certChain;


        std::string strCertChain = certChainFile.asString();
        /* Read the Root certificate */
        if(!readDataFromFile(strCertChain.data(), certData)) {
            printf("\n Failed to read the Root certificate\n");
            return ret;
        }

        // Get first certificate from chain of certificates.
        if(ErrorCode::OK != (errorCode =keymaster::V4_1::javacard::getCertificateChain(certData, certChain))) {
            printf("\n Failed to parse the certificate chain \n");
            return ret;
        }

        if(certChain.size() == 0) {
            printf("\n Length of the certificate chain is 0\n");
            return ret;
        }


        /* Subject, AuthorityKeyIdentifier and Expirty time of the root certificate are required by javacard. */
        /* Get X509 certificate instance for the root certificate.*/
        if(NULL == (x509 = parseDerCertificate(certChain[0]))) {
            printf("\n Failed to parse the DER certificate \n");
            return ret;
        }

        /* Get subject in DER */
        getDerSubjectName(x509, subject);
        /* Get AuthorityKeyIdentifier */
        getAuthorityKeyIdentifier(x509, authorityKeyIdentifier);
        /* Get Expirty Time */
        getNotAfter(x509, notAfter);
        /*Free X509 */
        X509_free(x509);

        array.add(subject);
        array.add(notAfter);
        array.add(authorityKeyIdentifier);
        std::vector<uint8_t> cborData = array.encode();

        if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
            printf("\n Failed to provision cert params errorCode:%d\n", static_cast<int32_t>(errorCode));
            return ret;
        }
    } else {
        return ret;
    }
    printf("\n Provisioned attestation certificate parameters successfully\n");
    return true;
}

bool provision(const char* filename) {

    if(!provisionAttestationKey(filename)) {
        printf("\n Failed to provision attestation Key\n");
        return false;
    }
    if(!provisionAttestationCertificateChain(filename)) {
        printf("\n Failed to provision certificate chain\n");
        return false;
    }
    if(!provisionAttestationCertificateParams(filename)) {
        printf("\n Failed to provision certificate paramters\n");
        return false;
    }
    if(!provisionSharedSecret(filename)) {
        printf("\n Failed to provision shared secret\n");
        return false;
    }
    if(!provisionAttestationIds(filename)) {
        printf("\n Failed to provision attestation ids\n");
        return false;
    }
    if(!setBootParameters(filename)) {
        printf("\n Failed to set boot parameters\n");
        return false;
    }
    return true;
}

bool parseJsonFile(const char* filename) {
    std::stringstream buffer;
    Json::Reader jsonReader;

    if(!root.empty()) {
        printf("\n Already parsed \n");
        return true;
    }
    std::ifstream stream(filename);
    buffer << stream.rdbuf();
    if(jsonReader.parse(buffer.str(), root)) {
        printf("\n Parsed json file successfully\n");
        return true;
    } else {
        printf("\n Failed to parse json file\n");
        return false;
    }
}

int main(int argc, char* argv[])
{
	int c;
	struct option longOpts[] = {
		{"all",              required_argument, NULL, 'a'},
		{"attest_key",       required_argument, NULL, 'k'},
		{"cert_chain",       required_argument, NULL, 'c'},
		{"cert_params",       required_argument, NULL,'p'},
		{"attest_ids",       required_argument, NULL, 'i'},
		{"shared_secret",    required_argument, NULL, 'r'},
		{"set_boot_params",  required_argument, NULL, 'b'},
		{"provision_status", no_argument,       NULL, 's'},
		{"lock_provision",   no_argument,       NULL, 'l'},
		{"help",             no_argument,       NULL, 'h'},
        {0,0,0,0}
	};

    sbKeymaster = IKeymasterDevice::getService(SB_KEYMASTER_SERVICE);
    if(NULL == sbKeymaster) {
        printf("\n Failed to get StrongBox Keymaster service\n");
        exit(0);
    }
    pTransportFactory = getTransportFactoryInstance();
    if(NULL == pTransportFactory) {
        printf("\n Failed to create transport factory\n");
        exit(0);
    }

    if (argc <= 1) {
        printf("\n Invalid command \n");
        usage();
    }

	/* getopt_long stores the option index here. */
	while ((c = getopt_long(argc, argv, ":slha:k:c:p:i:r:b:", longOpts, NULL)) != -1) {
		switch(c) {
            case 'a':
                //all
                provision(optarg);
                break;
            case 'k':
                //attest key
                provisionAttestationKey(optarg);
                break;
            case 'c':
                //attest certchain
                provisionAttestationCertificateChain(optarg);
                break;
            case 'p':
                //attest cert params
                provisionAttestationCertificateParams(optarg);
                break;
			case 'i':
                provisionAttestationIds(optarg);
				break;
			case 'r':
                provisionSharedSecret(optarg);
				break;
            case 'b':
                //set boot params
                setBootParameters(optarg);
                break;
			case 's':
                getProvisionStatus();
				break;
			case 'l':
                lockProvision();
				break;
			case 'h':
                usage();
				break;
			case ':':
				printf("\n missing argument\n");
                usage();
				break;
			case '?':
			default:
				printf("\n Invalid option\n");
                usage();
				break;
		}
	}
    if(optind < argc) {
        usage();
    }
	return 0;
}
