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
#include <unistd.h>
#include <getopt.h>
#include <utils/StrongPointer.h>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#include <keymaster/authorization_set.h>
#include <android-base/properties.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>
#include <CommonUtils.h>
#include <TransportFactory.h>

#define BUFFER_MAX_LENGTH 256
#define SB_KEYMASTER_SERVICE "javacard"
#define INS_BEGIN_KM_CMD 0x00
#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

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

std::string hex2str(const uint8_t* a, size_t len) { 
    std::string b;
    size_t num = len / 2; 
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
static Tag mapAttestKeyToAttestTag(const char* key);



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

static Tag  mapAttestKeyToAttestTag(const char* key) {
    //keymaster_tag_t tag = KM_TAG_INVALID;
    Tag tag = Tag::INVALID;
    std::string keyStr(key);

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
    printf("Usage:\n");
    printf("provision --attest_ids <file> --shared_secret <32 bytes secret> --set_boot_params <file> --lock_provision"
    "--provision_status\n");
    printf("\n\n");
    printf("Options:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-a, --attest_ids FILE \n");
    printf("\t Syntax for attest_ids inside the file:\n");
    printf("\t brand=Google\n");
    printf("\t device=Pixel 3A\n");
    printf("\t product=Pixel\n");
    printf("\t serial=UGYJFDjFeRuBEH\n");
    printf("\t imei=987080543071019\n");
    printf("\t meid=27863510227963\n");
    printf("\t manufacturer=Foxconn\n");
    printf("\t model=HD1121\n");
    printf("-s, --shared_secret  <32 bytes secret>  \n");
    //TODO include set_boot_params
    printf("\t The value of shared secret should be a 32 bytes in HEX\n");
    printf("-p, --provision_status  Prints the provision status.\n");
    printf("-l, --lock_provision    Locks the provision commands.\n");
}

bool provisionAttestationIds(const char* filename) {
    CborConverter cborConverter;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_ATTEST_IDS_CMD;
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> response;
	FILE *fp;
    char tempChar;
    int tempIndex = 0;
    uint8_t buf[BUFFER_MAX_LENGTH];
	bool ret = true;
	fp = fopen(filename, "rb");

	if(fp == NULL) {
		std::cout << "Failed to open file: " << filename;
        return false;
	}
    std::vector<KeyParameter> params;
    KeyParameter parameter;
    Tag tag;
    while((tempChar = fgetc(fp))) {
        if (tempChar == '\n' || tempChar == EOF) {
            buf[tempIndex] = '\0';
            tempIndex = 0;
            if(0 != strlen((const char*)buf)) {
                std::vector<uint8_t> blob(buf, buf + strlen((const char*)buf));
                parameter.blob = std::move(blob);
                params.push_back(parameter);
            }
            parameter = KeyParameter();
            // Decide to break or continue
            if(tempChar == EOF)
                break;
            else
                continue;

        } else if (tempChar == '=') {
            buf[tempIndex] = '\0';
            tempIndex = 0;
            if(Tag::INVALID == (tag = mapAttestKeyToAttestTag((const char*)buf))) {
                ret = false;
                printf("\n Invalid TAG \n");
                break;
            }
            parameter.tag = tag;
            printf("Key: %s", buf);
            continue;
        }
        buf[tempIndex++] = tempChar;
    }
	fclose(fp);
    if(!ret) 
        return ret;

    hidl_vec<KeyParameter> attestParams(params);

    //Encode input data into CBOR.
    cborConverter.addKeyparameters(array, attestParams);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
        ret = false;
        printf("\n Failed to provision attestation ids error: %d\n", uint32_t(errorCode));
    }
	return ret;
}

bool lockProvision() {
	bool ret = true;
    cppbor::Array array;
    Instruction ins = Instruction::INS_LOCK_PROVISIONING_CMD;
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;
    printf("\n lock provision\n");


    if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
        ret = false;
        printf("\n Failed to lock provisioning error: %d\n", uint32_t(errorCode));
    }
	return ret;
}

bool getProvisionStatus() {
	bool ret = true;
    CborConverter cborConverter;
    cppbor::Array array;
    Instruction ins = Instruction::INS_GET_PROVISION_STATUS_CMD;
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> cborData;
    std::vector<uint8_t> response;
    std::unique_ptr<Item> item;
    printf("\nget provision sttus\n");


    if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
        ret = false;
        printf("\n Failed to get provision status error: %d\n", uint32_t(errorCode));
    }
    std::tie(item, errorCode) = cborConverter.decodeData(std::vector<uint8_t>(response.begin(), response.end()-2),
            true);
    if(item != NULL) {
        uint64_t status;

        if(!cborConverter.getUint64(item, 1, status)) {
            ret = false;
            printf("\n Failed to get the status value \n");
        } else {
            printf("\n Current provision status: %ld", status);
        }
    }
	return ret;
}

bool provisionSharedSecret(const uint8_t* secret) {
    bool ret = true;
    cppbor::Array array;
    Instruction ins = Instruction::INS_PROVISION_SHARED_SECRET_CMD;
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> response;
    std::string str = hex2str(secret, strlen((const char*)secret));
    //Length of the secret should be 32 bytes.
    if(32 != str.length()) {
        return false;
    }
    std::vector<uint8_t> input(str.data(), str.data() + str.length());

    //Encode input data into CBOR.
    array.add(input);
    std::vector<uint8_t> cborData = array.encode();

    if(ErrorCode::OK != (errorCode = sendProvisionData(ins, cborData, response))) {
        ret = false;
        printf("\n Failed to provision shared secret error: %d\n", uint32_t(errorCode));
    }
	return ret;
}

int main(int argc, char* argv[])
{
	int c;
	struct option longOpts[] = {
		{"attest_ids",       required_argument, NULL, 'a'},
		{"shared_secret",    required_argument, NULL, 's'},
		{"set_boot_params",  required_argument, NULL, 'b'},
		{"provision_status", no_argument,       NULL, 'p'},
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
	while ((c = getopt_long(argc, argv, ":plha:s:", longOpts, NULL)) != -1) {
		switch(c) {
			case 'a':
				printf("\n attest_ids filename:%s\n", optarg);
                provisionAttestationIds(optarg);
				break;
			case 's':
                provisionSharedSecret((const uint8_t*)optarg);
				break;
			case 'p':
                getProvisionStatus();
				break;
			case 'l':
                lockProvision();
				break;
			case 'h':
                usage();
				break;
            case 0:
                printf("\n set 0\n");
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
