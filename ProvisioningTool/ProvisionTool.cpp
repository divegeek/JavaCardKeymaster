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
#include <Provision.h>

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
    PROVISION_STATUS_PRESHARED_SECRET = 0x10,
    PROVISION_STATUS_BOOT_PARAM = 0x20,
    PROVISION_STATUS_PROVISIONING_LOCKED = 0x40,
};

using ::android::hardware::keymaster::V4_0::ErrorCode;

static keymaster::V4_1::javacard::Provision mProvision;
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

void usage() {
    printf("Usage: provision_tool [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-a, --all jsonFile \t Executes all the provision commands \n");
    printf("-k, --attest_key jsonFile \t Provision attestation key \n");
    printf("-c, --cert_chain jsonFile \t Provision attestation certificate chain \n");
    printf("-p, --cert_params jsonFile \t Provision attestation certificate parameters \n");
    printf("-i, --attest_ids jsonFile \t Provision attestation IDs \n");
    printf("-r, --shared_secret jsonFile \t Provision shared secret  \n");
    printf("-b, --set_boot_params jsonFile \t Set boot parameters  \n");
    printf("-e, --set_system_properties \t Set system properties  \n");
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

bool setAndroidSystemProperties() {
    ErrorCode err = ErrorCode::OK;
    bool ret = false;
    if (ErrorCode::OK != (err = mProvision.setAndroidSystemProperties())) {
        printf("\n set boot parameters failed with err:%d \n", (int32_t)err);
        return ret;
    }
    printf("\n SE successfully accepted system properties.\n");
    return true;

}

bool setBootParameters(const char* filename) {
    Json::Value bootParamsObj;
    bool ret = false;
    ErrorCode err = ErrorCode::OK;
    keymaster::V4_1::javacard::BootParams bootParams;

    if(!parseJsonFile(filename))
        return ret;

    bootParamsObj = root.get("set_boot_params", bootParamsObj);
    if (!bootParamsObj.isNull()) {

        if(!getBootParameterIntValue(bootParamsObj, "boot_patch_level", &bootParams.bootPatchLevel)) {
            printf("\n Invalid value for boot_patch_level or boot_patch_level tag missing\n");
            return ret;
        }
        if(!getBootParameterBlobValue(bootParamsObj, "verified_boot_key", bootParams.verifiedBootKey)) {
            printf("\n Invalid value for verified_boot_key or verified_boot_key tag missing\n");
            return ret;
        }
        if(!getBootParameterBlobValue(bootParamsObj, "verified_boot_key_hash", bootParams.verifiedBootKeyHash)) {
            printf("\n Invalid value for verified_boot_key_hash or verified_boot_key_hash tag missing\n");
            return ret;
        }
        if(!getBootParameterIntValue(bootParamsObj, "boot_state", &bootParams.verifiedBootState)) {
            printf("\n Invalid value for boot_state or boot_state tag missing\n");
            return ret;
        }
        if(!getBootParameterIntValue(bootParamsObj, "device_locked", &bootParams.deviceLocked)) {
            printf("\n Invalid value for device_locked or device_locked tag missing\n");
            return ret;
        }

    } else {
        printf("\n Fail: Improper value found for set_boot_params key inside the json file\n");
        return ret;
    }

    if (ErrorCode::OK != (err = mProvision.provisionBootParameters(bootParams))) {
        printf("\n set boot parameters failed with err:%d \n", (int32_t)err);
        return ret;
    }

    printf("\n SE successfully accepted boot paramters \n");
    return true;
}

bool provisionAttestationIds(const char *filename) {
    Json::Value attestIds;
    bool ret = false;
    ErrorCode err = ErrorCode::OK;
    keymaster::V4_1::javacard::AttestIDParams params;

    if(!parseJsonFile(filename))
        return ret;

    attestIds = root.get("attest_ids", attestIds);
    if (!attestIds.isNull()) {
        Json::Value value;
        Json::Value::Members keys = attestIds.getMemberNames();
        for(std::string key : keys) {
            value = attestIds[key];
            if(value.empty()) {
                continue;
            }
            if (!value.isString()) {
                printf("\n Fail: Value for each attest ids key should be a string in the json file \n");
                return ret;
            }

            if (0 == key.compare("brand")) {
                params.brand = value.asString();
            } else if(0 == key.compare("device")) {
                params.device = value.asString();
            } else if(0 == key.compare("product")) {
                params.product = value.asString();
            } else if(0 == key.compare("serial")) {
                params.serial = value.asString();
            } else if(0 == key.compare("imei")) {
                params.imei = value.asString();
            } else if(0 == key.compare("meid")) {
                params.meid = value.asString();
            } else if(0 == key.compare("manufacturer")) {
                params.manufacturer = value.asString();
            } else if(0 == key.compare("model")) {
                params.model = value.asString();
            } else {
                printf("\n unknown attestation id key:%s \n", key.c_str());
                return ret;
            }
        }

        if (ErrorCode::OK != (err = mProvision.provisionAttestationID(params))) {
            printf("\n Provision attestationID parameters failed with err:%d \n", (int32_t)err);
            return ret;
        }
    } else {
        printf("\n Fail: Improper value found for attest_ids key inside the json file \n");
        return ret;
    }
    printf("\n provisioned attestation ids successfully \n");
    return true;
}

bool lockProvision() {
    ErrorCode errorCode;
    bool ret = false;

    if(ErrorCode::OK != (errorCode = mProvision.lockProvision())) {
        printf("\n Failed to lock provisioning error: %d\n", uint32_t(errorCode));
        return ret;
    }
    printf("\n Successfully locked provisioning process. Now SE doesn't accept any further provision commands. \n");
	return true;
}

bool getProvisionStatus() {
	bool ret = false;
    uint64_t status;
    if (ErrorCode::OK != mProvision.getProvisionStatus(status)) {
        return ret;
    }
	if ( (0 != (status & ProvisionStatus::PROVISION_STATUS_ATTESTATION_KEY)) &&
			(0 != (status & ProvisionStatus::PROVISION_STATUS_ATTESTATION_CERT_CHAIN)) &&
			(0 != (status & ProvisionStatus::PROVISION_STATUS_ATTESTATION_CERT_PARAMS)) &&
			(0 != (status & ProvisionStatus::PROVISION_STATUS_PRESHARED_SECRET)) &&
			(0 != (status & ProvisionStatus::PROVISION_STATUS_BOOT_PARAM))) {
        printf("\n SE is provisioned \n");
	} else {
        if (0 == (status & ProvisionStatus::PROVISION_STATUS_ATTESTATION_KEY)) {
            printf("\n Attestation key is not provisioned \n");
        }
        if (0 == (status & ProvisionStatus::PROVISION_STATUS_ATTESTATION_CERT_CHAIN)) {
            printf("\n Attestation certificate chain is not provisioned \n");
        }
        if (0 == (status & ProvisionStatus::PROVISION_STATUS_ATTESTATION_CERT_PARAMS)) {
            printf("\n Attestation certificate params are not provisioned \n");
        }
        if (0 == (status & ProvisionStatus::PROVISION_STATUS_PRESHARED_SECRET)) {
            printf("\n Shared secret is not provisioned \n");
        }
        if (0 == (status & ProvisionStatus::PROVISION_STATUS_BOOT_PARAM)) {
            printf("\n Boot params are not provisioned \n");
        }
    }
	return true;
}

bool provisionSharedSecret(const char* filename) {
    Json::Value sharedSecret;
    bool ret = false;
    ErrorCode err = ErrorCode::OK;

    if(!parseJsonFile(filename))
        return ret;

    sharedSecret = root.get("shared_secret", sharedSecret);
    if (!sharedSecret.isNull()) {

        if (!sharedSecret.isString()) {
            printf("\n Fail: Value for shared secret key should be string inside the json file\n");
            return ret;
        }
        std::string secret = hex2str(sharedSecret.asString());
        std::vector<uint8_t> data(secret.begin(), secret.end());
        if(ErrorCode::OK != (err = mProvision.provisionPreSharedSecret(data))) {
            printf("\n Provision pre-shared secret failed with err:%d \n", (int32_t)err);
            return ret;
        }
    } else {
        printf("\n Fail: Improper value for shared_secret key inside the json file\n");
        return ret;
    }
    printf("\n Provisioned shared secret successfully \n");
    return true;
}

static bool provisionAttestationKey(const char* filename) {
    Json::Value keyFile;
    bool ret = false;
    ErrorCode err = ErrorCode::OK;

    if(!parseJsonFile(filename))
        return ret;

    keyFile = root.get("attest_key", keyFile);
    if (!keyFile.isNull()) {
        std::vector<uint8_t> data;

        std::string keyFileName = keyFile.asString();
        if(!readDataFromFile(keyFileName.data(), data)) {
            printf("\n Failed to read the Root ec key\n");
            return ret;
        }
        if(ErrorCode::OK != (err = mProvision.provisionAttestationKey(data))) {
            printf("\n Provision attestation key failed with error: %d\n", (int32_t)err);
            return ret;
        }
    } else {
        printf("\n Improper value for attest_key in json file \n");
        return ret;
    }
    printf("\n Provisioned attestation key successfully\n");
    return true;
}

bool provisionAttestationCertificateChain(const char* filename) {
    Json::Value certChainFile;
    bool ret = false;
    ErrorCode err = ErrorCode::OK;

    if(!parseJsonFile(filename))
        return ret;

    certChainFile = root.get("attest_cert_chain", certChainFile);
    if (!certChainFile.isNull()) {
        std::vector<std::vector<uint8_t>> certData;

        if(certChainFile.isArray()) {
            for (int i = 0; i < certChainFile.size(); i++) {
                std::vector<uint8_t> tmp;
                if(certChainFile[i].isString()) {
                    /* Read the certificates. */
                    if(!readDataFromFile(certChainFile[i].asString().data(), tmp)) {
                        printf("\n Failed to read the Root certificate\n");
                        return ret;
                    }
                    certData.push_back(std::move(tmp));
                } else {
                    printf("\n Fail: Only proper certificate paths as a string is allowed inside the json file. \n");
                    return ret;
                }
            }
        } else {
            printf("\n Fail: cert chain value should be an array inside the json file. \n");
            return ret;
        }
        if (ErrorCode::OK != (err = mProvision.provisionAtestationCertificateChain(certData))) {
            printf("\n Provision certificate chain failed with error: %d\n", (int32_t)err);
            return ret;
        }
    } else {
        printf("\n Fail: Improper value found for attest_cert_chain key inside json file \n");
        return ret;
    }
    printf("\n Provisioned attestation certificate chain successfully\n");
    return true;
}

bool provisionAttestationCertificateParams(const char* filename) {
    Json::Value certChainFile;
    bool ret = false;
    ErrorCode err = ErrorCode::OK;

    if(!parseJsonFile(filename))
        return ret;

    certChainFile = root.get("attest_cert_chain", certChainFile);
    if (!certChainFile.isNull()) {
        std::vector<std::vector<uint8_t>> certData;

        if(certChainFile.isArray()) {
            if (certChainFile.size() == 0) {
                return ret;
            }
            std::vector<uint8_t> tmp;
            if(!readDataFromFile(certChainFile[0].asString().data(), tmp)) {
                printf("\n Failed to read the Root certificate\n");
                return ret;
            }
            if (ErrorCode::OK != (err = mProvision.provisionAttestationCertificateParams(tmp))) {
                printf("\n Provision certificate params failed with error: %d\n", (int32_t)err);
                return ret;
            }
        } else {
            printf("\n Fail: cert chain value should be an array inside the json file. \n");
            return ret;
        }
    } else {
        printf("\n Fail: Improper value found for attest_cert_chain key inside json file \n");
        return ret;
    }
    printf("\n Provisioned attestation certificate parameters successfully\n");
    return true;
}

bool provision(const char* filename) {

    if(!provisionAttestationKey(filename)) {
        return false;
    }
    if(!provisionAttestationCertificateChain(filename)) {
        return false;
    }
    if(!provisionAttestationCertificateParams(filename)) {
        return false;
    }
    if(!provisionSharedSecret(filename)) {
        return false;
    }
    if(!provisionAttestationIds(filename)) {
        return false;
    }
    if(!setBootParameters(filename)) {
        return false;
    }
    if(!setAndroidSystemProperties()) {
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
        {"set_system_properties",  no_argument, NULL, 'e'},
        {"provision_status", no_argument,       NULL, 's'},
        {"lock_provision",   no_argument,       NULL, 'l'},
        {"help",             no_argument,       NULL, 'h'},
        {0,0,0,0}
    };

    if (argc <= 1) {
        printf("\n Invalid command \n");
        usage();
    }
    /* Initialize provision */
    mProvision.init();

    /* getopt_long stores the option index here. */
    while ((c = getopt_long(argc, argv, ":slhea:k:c:p:i:r:b:", longOpts, NULL)) != -1) {
        switch(c) {
            case 'a':
                //all
                if(!provision(optarg))
                    printf("\n Failed to provision the device \n");
                break;
            case 'k':
                //attest key
                if(!provisionAttestationKey(optarg))
                    printf("\n Failed to provision attestaion key\n");
                break;
            case 'c':
                //attest certchain
                if(!provisionAttestationCertificateChain(optarg))
                    printf("\n Failed to provision attestaion certificate chain\n");
                break;
            case 'p':
                //attest cert params
                if(!provisionAttestationCertificateParams(optarg))
                    printf("\n Failed to provision attestaion certificate paramaters\n");
                break;
            case 'i':
                //attestation ids.
                if(!provisionAttestationIds(optarg))
                    printf("\n Failed to provision attestaion ids\n");
                break;
                //shared secret
            case 'r':
                if(!provisionSharedSecret(optarg))
                    printf("\n Failed to provision shared secret\n");
                break;
            case 'b':
                //set boot params
                if(!setBootParameters(optarg))
                    printf("\n Failed to set boot parameters.\n");
                break;
            case 'e':
                //set Android system properties
                if(!setAndroidSystemProperties())
                    printf("\n Failed to set android system properties.\n");
                break;
            case 's':
                if(!getProvisionStatus())
                    printf("\n Failed to get provision status \n");
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
    /*Uninitalize */
    mProvision.uninit();
    return 0;
}
