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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <keymaster/keymaster_configuration.h>
#include <keymaster/attestation_record.h>
#include <android-base/logging.h>
#include <Transport.h>
#include <CommonUtils.h>
#include <Provision.h>

#define ROOT_EC_KEY   "/data/data/ec_key.der"
#define INTERMEDIATE_EC_CERT "/data/data/ec_cert.der"
#define ROOT_EC_CERT  "/data/data/ec_root_cert.der"
#define INS_BEGIN_KM_CMD 0x00
#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

namespace keymaster {
namespace V4_1 {
namespace javacard {

constexpr uint8_t kFakeKeyAgreementKey[32] = {};
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

// Static function declarations.
static bool readDataFromFile(const char *filename, std::vector<uint8_t>& data);
static ErrorCode constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut, bool
extendedOutput=false);
static ErrorCode sendProvisionData(std::unique_ptr<se_transport::TransportFactory>& transport, Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response, bool
extendedOutput = false);
static ErrorCode provisionAttestationKey(std::unique_ptr<se_transport::TransportFactory>& transport);
static ErrorCode provisionAttestationCertificateChain(std::unique_ptr<se_transport::TransportFactory>& transport);
static ErrorCode provisionAttestationCertificateParams(std::unique_ptr<se_transport::TransportFactory>& transport);
static ErrorCode provisionAttestationIDs(std::unique_ptr<se_transport::TransportFactory>& transport);
static ErrorCode provisionSharedSecret(std::unique_ptr<se_transport::TransportFactory>& transport);
static ErrorCode getProvisionStatus(std::unique_ptr<se_transport::TransportFactory>& transport, std::vector<uint8_t>&
response);
static ErrorCode lockProvision(std::unique_ptr<se_transport::TransportFactory>& transport);
static ErrorCode setBootParameters(std::unique_ptr<se_transport::TransportFactory>& transport);
static uint16_t getStatus(std::vector<uint8_t>& inputData);
static bool isSEProvisioned(uint64_t status);

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

static uint16_t getStatus(std::vector<uint8_t>& inputData) {
    //Last two bytes are the status SW0SW1
    return (inputData.at(inputData.size()-2) << 8) | (inputData.at(inputData.size()-1));
}

static bool readDataFromFile(const char *filename, std::vector<uint8_t>& data) {
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
        //data.insert(data.begin(), buf.get(), buf.get() + filesize);
        data.insert(data.end(), buf.get(), buf.get() + filesize);
    }
    fclose(fp);
    return ret;
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



static ErrorCode sendProvisionData(std::unique_ptr<se_transport::TransportFactory>& transport, Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response, bool
extendedOutput) {
    ErrorCode ret = ErrorCode::OK;
    std::vector<uint8_t> apdu;
    CborConverter cborConverter;
    std::unique_ptr<Item> item;
    ret = constructApduMessage(ins, inData, apdu, extendedOutput);
    if(ret != ErrorCode::OK) return ret;

    if(!transport->sendData(apdu.data(), apdu.size(), response)) {
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

static ErrorCode provisionAttestationKey(std::unique_ptr<se_transport::TransportFactory>& transport) {
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

    AuthorizationSet authSetKeyParams(AuthorizationSetBuilder()
            .Authorization(TAG_ALGORITHM, KM_ALGORITHM_EC)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_EC_CURVE, KM_EC_CURVE_P_256)
            .Authorization(TAG_PURPOSE, static_cast<keymaster_purpose_t>(0x7F))); /* The value 0x7F is not present in types.hal */
    // Read the ECKey from the file.         
    hidl_vec<KeyParameter> keyParams = kmParamSet2Hidl(authSetKeyParams);

    if(!readDataFromFile(ROOT_EC_KEY, data)) {
        LOG(ERROR) << " Failed to read the Root rsa key";
        return ErrorCode::UNKNOWN_ERROR;
    }
    if(ErrorCode::OK != (errorCode = ecRawKeyFromPKCS8(data, privKey, pubKey, curve))) {
        return errorCode;
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

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

static ErrorCode provisionAttestationCertificateChain(std::unique_ptr<se_transport::TransportFactory>& transport) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_CERT_CHAIN_CMD;
    std::vector<uint8_t> response;

    std::vector<uint8_t> certData;
    /* Read the Root certificate */
    if(!readDataFromFile(INTERMEDIATE_EC_CERT, certData)) {
        LOG(ERROR) << " Failed to read the Root certificate";
        return (ErrorCode::UNKNOWN_ERROR);
    }
    if(!readDataFromFile(ROOT_EC_CERT, certData)) {
        LOG(ERROR) << " Failed to read the Root certificate";
        return (ErrorCode::UNKNOWN_ERROR);
    }
    cppbor::Bstr certChain(certData.begin(), certData.end());
    std::vector<uint8_t> cborData = certChain.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

static ErrorCode provisionAttestationCertificateParams(std::unique_ptr<se_transport::TransportFactory>& transport) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_CERT_PARAMS_CMD;
    std::vector<uint8_t> response;
    X509 *x509 = NULL;
    std::vector<uint8_t> subject;
    std::vector<uint8_t> authorityKeyIdentifier;
    std::vector<uint8_t> notAfter;

    /* Subject, AuthorityKeyIdentifier and Expirty time of the root certificate are required by javacard. */
    /* Get X509 certificate instance for the root certificate.*/
    if(NULL == (x509 = parseDerCertificate(INTERMEDIATE_EC_CERT))) {
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

    array = cppbor::Array();
    array.add(subject);
    array.add(notAfter);
    array.add(authorityKeyIdentifier);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}


static ErrorCode provisionAttestationIDs(std::unique_ptr<se_transport::TransportFactory>& transport) {
    ErrorCode errorCode = ErrorCode::OK;
    CborConverter cborConverter;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_ATTEST_IDS_CMD;
    std::vector<uint8_t> response;

    std::string brand("Google");
    std::string device("Pixel 3A");
    std::string product("Pixel");
    std::string serial("UGYJFDjFeRuBEH");
    std::string imei("987080543071019");
    std::string meid("27863510227963");
    std::string manufacturer("Foxconn");
    std::string model("HD1121");

    AuthorizationSet authSetAttestParams(AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_ID_BRAND, brand.data(), brand.size())
            .Authorization(TAG_ATTESTATION_ID_DEVICE, device.data(), device.size())
            .Authorization(TAG_ATTESTATION_ID_PRODUCT, product.data(), product.size())
            .Authorization(TAG_ATTESTATION_ID_SERIAL, serial.data(), serial.size())
            .Authorization(TAG_ATTESTATION_ID_IMEI, imei.data(), imei.size())
            .Authorization(TAG_ATTESTATION_ID_MEID, meid.data(), meid.size())
            .Authorization(TAG_ATTESTATION_ID_MANUFACTURER, manufacturer.data(), manufacturer.size())
            .Authorization(TAG_ATTESTATION_ID_MODEL, model.data(), model.size()));

    hidl_vec<KeyParameter> attestParams = kmParamSet2Hidl(authSetAttestParams);

    array = cppbor::Array();
    cborConverter.addKeyparameters(array, attestParams);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

static ErrorCode provisionSharedSecret(std::unique_ptr<se_transport::TransportFactory>& transport) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_SHARED_SECRET_CMD;
    std::vector<uint8_t> response;
    std::vector<uint8_t> masterKey(kFakeKeyAgreementKey, kFakeKeyAgreementKey +
            sizeof(kFakeKeyAgreementKey)/sizeof(kFakeKeyAgreementKey[0]));

    array = cppbor::Array();
    array.add(masterKey);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

static ErrorCode getProvisionStatus(std::unique_ptr<se_transport::TransportFactory>& transport, std::vector<uint8_t>&
response) {
    ErrorCode errorCode = ErrorCode::OK;
    Instruction ins = Instruction::INS_GET_PROVISION_STATUS_CMD;
    std::vector<uint8_t> cborData;

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;

}

static ErrorCode lockProvision(std::unique_ptr<se_transport::TransportFactory>& transport) {
    ErrorCode errorCode = ErrorCode::OK;
    Instruction ins = Instruction::INS_LOCK_PROVISIONING_CMD;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

static ErrorCode setBootParameters(std::unique_ptr<se_transport::TransportFactory>& transport) {
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> verifiedBootKey(32, 0);
    std::vector<uint8_t> verifiedBootKeyHash(32, 0);
    uint32_t vendorPatchLevel = 0;
    uint32_t bootPatchLevel = 0;
    cppbor::Array array;
    std::vector<uint8_t> apdu;
    std::vector<uint8_t> response;
    Instruction ins = Instruction::INS_SET_BOOT_PARAMS_CMD;
    keymaster_verified_boot_t kmVerifiedBoot = KM_VERIFIED_BOOT_UNVERIFIED;

    array.add(GetOsVersion()).
        add(GetOsPatchlevel()).
        add(vendorPatchLevel).
        add(bootPatchLevel).
        /* Verified Boot Key */
        add(verifiedBootKey).
        /* Verified Boot Hash */
        add(verifiedBootKeyHash).
        /* boot state */
        add(static_cast<uint32_t>(kmVerifiedBoot)).
        /* device locked */
        add(0);

    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(transport, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

static bool isSEProvisioned(uint64_t status) {
    bool ret = true;

    if(status != (ProvisionStatus::PROVISION_STATUS_ATTESTATION_KEY | ProvisionStatus::PROVISION_STATUS_ATTESTATION_CERT_CHAIN |
                ProvisionStatus::PROVISION_STATUS_ATTESTATION_CERT_PARAMS | ProvisionStatus::PROVISION_STATUS_ATTEST_IDS |
                ProvisionStatus::PROVISION_STATUS_SHARED_SECRET | ProvisionStatus::PROVISION_STATUS_BOOT_PARAM
                |ProvisionStatus::PROVISION_STATUS_PROVISIONING_LOCKED)) {
        ret = false;
    }
    return ret;
}

ErrorCode provision(std::unique_ptr<se_transport::TransportFactory>& transport) {
    std::vector<uint8_t> response;
    std::unique_ptr<Item> item;
    CborConverter cborConverter;
    ErrorCode errorCode = ErrorCode::OK;

    //Get Provision status.
    if(ErrorCode::OK != (errorCode = getProvisionStatus(transport, response))) {
        return errorCode;
    }

    //Check if SE is provisioned.
    std::tie(item, errorCode) = cborConverter.decodeData(std::vector<uint8_t>(response.begin(), response.end()-2),
            true);
    if(item != NULL) {
        uint64_t status;

        if(!cborConverter.getUint64(item, 1, status))
            return ErrorCode::UNKNOWN_ERROR;

        if(isSEProvisioned(status)) {
            return ErrorCode::OK; //SE is Provisioned.
        }

    } else {
        return ErrorCode::UNKNOWN_ERROR;
    }

    //SE not provisioned so Provision the SE.

    //Provision Attestation Key.
    if(ErrorCode::OK != (errorCode = provisionAttestationKey(transport))) {
        return errorCode;
    }
    //Provision Attestation certificate chain.
    if(ErrorCode::OK != (errorCode = provisionAttestationCertificateChain(transport))) {
        return errorCode;
    }
    //Provision certificate parameters.
    if(ErrorCode::OK != (errorCode = provisionAttestationCertificateParams(transport))) {
        return errorCode;
    }
    //Provision Attestation IDs.
    if(ErrorCode::OK != (errorCode = provisionAttestationIDs(transport))) {
        return errorCode;
    }
    //Provision Shared secret.
    if(ErrorCode::OK != (errorCode = provisionSharedSecret(transport))) {
        return errorCode;
    }
    //Set Boot parameters.
    if(ErrorCode::OK != (errorCode = setBootParameters(transport))) {
        return errorCode;
    }
    //Lock the provisioning.
    if(ErrorCode::OK != (errorCode = lockProvision(transport))) {
        return errorCode;
    }
    //return OK
    return errorCode;
}

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
