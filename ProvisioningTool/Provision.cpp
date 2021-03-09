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
 #include <android-base/properties.h>

#define INS_BEGIN_KM_CMD 0x00
#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

namespace keymaster {
namespace V4_1 {
namespace javacard {

enum class Instruction {
    // Provisioning commands
    INS_PROVISION_ATTESTATION_KEY_CMD = INS_BEGIN_KM_CMD+1,
    INS_PROVISION_CERT_CHAIN_CMD = INS_BEGIN_KM_CMD+2,
    INS_PROVISION_CERT_PARAMS_CMD = INS_BEGIN_KM_CMD+3,
    INS_PROVISION_ATTEST_IDS_CMD = INS_BEGIN_KM_CMD+4,
    INS_PROVISION_PRESHARED_SECRET_CMD = INS_BEGIN_KM_CMD+5,
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
    PROVISION_STATUS_PRESHARED_SECRET = 0x10,
    PROVISION_STATUS_BOOT_PARAM = 0x20,
    PROVISION_STATUS_PROVISIONING_LOCKED = 0x40,
};

// Static function declarations.
static ErrorCode constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut);
static ErrorCode sendProvisionData(std::unique_ptr<se_transport::TransportFactory>& transport, Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response);
static uint16_t getStatus(std::vector<uint8_t>& inputData);

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

static ErrorCode constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut) {

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



static ErrorCode sendProvisionData(std::unique_ptr<se_transport::TransportFactory>& transport, Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response) {
    ErrorCode ret = ErrorCode::OK;
    std::vector<uint8_t> apdu;
    CborConverter cborConverter;
    std::unique_ptr<Item> item;
    ret = constructApduMessage(ins, inData, apdu);
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

ErrorCode Provision::init() {
	if(pTransportFactory == nullptr) {
		pTransportFactory = std::unique_ptr<se_transport::TransportFactory>(new se_transport::TransportFactory(
					android::base::GetBoolProperty("ro.kernel.qemu", false)));
		if(!pTransportFactory->openConnection())
            return ErrorCode::UNKNOWN_ERROR;
	}
	return ErrorCode::OK;
}

ErrorCode Provision::provisionAttestationKey(std::vector<uint8_t>& batchKey) {
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> privKey;
    std::vector<uint8_t> pubKey;
    EcCurve curve;
    CborConverter cborConverter;
    cppbor::Array array;
    cppbor::Array subArray;
    std::vector<uint8_t> response;
    Instruction ins = Instruction::INS_PROVISION_ATTESTATION_KEY_CMD;

    AuthorizationSet authSetKeyParams(AuthorizationSetBuilder()
            .Authorization(TAG_ALGORITHM, KM_ALGORITHM_EC)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_EC_CURVE, KM_EC_CURVE_P_256)
            .Authorization(TAG_PURPOSE, static_cast<keymaster_purpose_t>(0x7F))); /* The value 0x7F is not present in types.hal */
    hidl_vec<KeyParameter> keyParams = kmParamSet2Hidl(authSetKeyParams);
    if(ErrorCode::OK != (errorCode = ecRawKeyFromPKCS8(batchKey, privKey, pubKey, curve))) {
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
    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::provisionAtestationCertificateChain(std::vector<std::vector<uint8_t>>& certChain) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_CERT_CHAIN_CMD;
    std::vector<uint8_t> response;

    std::vector<uint8_t> certData;
    for (auto data : certChain) {
        certData.insert(certData.end(), data.begin(), data.end());
    }
    cppbor::Bstr bstrCertChain(certData.begin(), certData.end());
    std::vector<uint8_t> cborData = bstrCertChain.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::provisionAttestationCertificateParams(std::vector<uint8_t>& batchCertificate) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_CERT_PARAMS_CMD;
    std::vector<uint8_t> response;
    X509 *x509 = NULL;
    std::vector<uint8_t> subject;
    std::vector<uint8_t> notAfter;

    /* Subject, AuthorityKeyIdentifier and Expirty time of the root certificate are required by javacard. */
    /* Get X509 certificate instance for the root certificate.*/
    if(NULL == (x509 = parseDerCertificate(batchCertificate))) {
        return errorCode;
    }

    /* Get subject in DER */
    getDerSubjectName(x509, subject);
    /* Get Expirty Time */
    getNotAfter(x509, notAfter);
    /*Free X509 */
    X509_free(x509);

    array = cppbor::Array();
    array.add(subject);
    array.add(notAfter);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::provisionAttestationID(AttestIDParams& attestParams) {
    ErrorCode errorCode = ErrorCode::OK;
    CborConverter cborConverter;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_ATTEST_IDS_CMD;
    std::vector<uint8_t> response;

    AuthorizationSet authSetAttestParams(AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_ID_BRAND, attestParams.brand.data(), attestParams.brand.size())
            .Authorization(TAG_ATTESTATION_ID_DEVICE, attestParams.device.data(), attestParams.device.size())
            .Authorization(TAG_ATTESTATION_ID_PRODUCT, attestParams.product.data(), attestParams.product.size())
            .Authorization(TAG_ATTESTATION_ID_SERIAL, attestParams.serial.data(), attestParams.serial.size())
            .Authorization(TAG_ATTESTATION_ID_IMEI, attestParams.imei.data(), attestParams.imei.size())
            .Authorization(TAG_ATTESTATION_ID_MEID, attestParams.meid.data(), attestParams.meid.size())
            .Authorization(TAG_ATTESTATION_ID_MANUFACTURER, attestParams.manufacturer.data(), attestParams.manufacturer.size())
            .Authorization(TAG_ATTESTATION_ID_MODEL, attestParams.model.data(), attestParams.model.size()));

    hidl_vec<KeyParameter> attestKeyParams = kmParamSet2Hidl(authSetAttestParams);

    array = cppbor::Array();
    cborConverter.addKeyparameters(array, attestKeyParams);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::provisionPreSharedSecret(std::vector<uint8_t>& preSharedSecret) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_PRESHARED_SECRET_CMD;
    std::vector<uint8_t> response;

    array = cppbor::Array();
    array.add(preSharedSecret);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::provisionBootParameters(BootParams& bootParams) {
    ErrorCode errorCode = ErrorCode::OK;
    cppbor::Array array;
    std::vector<uint8_t> apdu;
    std::vector<uint8_t> response;
    Instruction ins = Instruction::INS_SET_BOOT_PARAMS_CMD;

    array.add(GetOsVersion()).
        add(GetOsPatchlevel()).
        add(bootParams.vendorPatchLevel).
        add(bootParams.bootPatchLevel).
        /* Verified Boot Key */
        add(bootParams.verifiedBootKey).
        /* Verified Boot Hash */
        add(bootParams.verifiedBootKeyHash).
        /* boot state */
        add(bootParams.verifiedBootState).
        /* device locked */
        add(bootParams.deviceLocked);

    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::getProvisionStatus(uint64_t& status) {
    ErrorCode errorCode = ErrorCode::OK;
    Instruction ins = Instruction::INS_GET_PROVISION_STATUS_CMD;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;
    std::unique_ptr<Item> item;
    CborConverter cborConverter;

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        LOG(ERROR) << "Failed to get provision status err: " << static_cast<int32_t>(errorCode);
        return errorCode;
    }
    //Check if SE is provisioned.
    std::tie(item, errorCode) = cborConverter.decodeData(std::vector<uint8_t>(response.begin(), response.end()-2),
            true);
    if(item != NULL) {

        if(!cborConverter.getUint64(item, 1, status)) {
            LOG(ERROR) << "Failed to parse the status from cbor data";
            return ErrorCode::UNKNOWN_ERROR;
        }
    }
    return errorCode;
}

ErrorCode Provision::lockProvision() {
    ErrorCode errorCode = ErrorCode::OK;
    Instruction ins = Instruction::INS_LOCK_PROVISIONING_CMD;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;

    if(ErrorCode::OK != (errorCode = sendProvisionData(pTransportFactory, ins, cborData, response))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode Provision::uninit() {
	if(pTransportFactory != nullptr) {
        if(!pTransportFactory->closeConnection())
            return ErrorCode::UNKNOWN_ERROR;
    }
    return ErrorCode::OK;
}
// Provision End

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
