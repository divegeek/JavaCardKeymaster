/*
 **
 ** Copyright 2021, The Android Open Source Project
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
#include <vector>
#include <memory>
#include <getopt.h>
#include "socket.h"
#include <json/reader.h>
#include <json/value.h>
#include <constants.h>
#include <utils.h>
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

#define SE_POWER_RESET_STATUS_FLAG (1 << 30)
// TODO keymint provision status
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

// TODO keymint provision status and lock
std::string provisionStatusApdu = hex2str("80084000000000");
std::string lockProvisionApdu = hex2str("80074000000000");

Json::Value root;
static std::string inputFileName;
using cppbor::Item;
using cppbor::Array;
using cppbor::Uint;
using cppbor::MajorType;

// static function declarations
static uint16_t getApduStatus(std::vector<uint8_t>& inputData);
static int sendData(std::shared_ptr<SocketTransport>& pSocket, std::string input, std::vector<uint8_t>& response);
static int provisionData(std::shared_ptr<SocketTransport>& pSocket, std::string apdu, std::vector<uint8_t>& response);
static int provisionData(std::shared_ptr<SocketTransport>& pSocket, const char* jsonKey);
static int getUint64(const std::unique_ptr<Item> &item, const uint32_t pos, uint64_t *value);


// Print usage.
void usage() {
    printf("Usage: Please consturcture the apdu(s) with help of construct apdu tool and pass the output file to this utility.\n");
    printf("provision_keymint [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-i, --input  jsonFile \t Input json file \n");
    printf("-s, --provision_status jsonFile \t Gets the provision status of applet. \n");
    printf("-l, --lock_provision jsonFile \t Gets the provision status of applet. \n");

}

static uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
    // Last two bytes are the status SW0SW1
    uint8_t SW0 = inputData.at(inputData.size() - 2); 
    uint8_t SW1 = inputData.at(inputData.size() - 1); 
    return (SW0 << 8 | SW1);
}

static int sendData(std::shared_ptr<SocketTransport>& pSocket, std::string input, std::vector<uint8_t>& response) {

    std::vector<uint8_t> apdu(input.begin(), input.end());

    if(!pSocket->sendData(apdu, response)) {
        std::cout << "Failed to provision attestation key" << std::endl;
        return FAILURE;
    }

    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU
    // status.
    if ((response.size() <= 2) || (getApduStatus(response) != APDU_RESP_STATUS_OK)) {
        printf("\n Received error response with error: %d\n", getApduStatus(response));
        return FAILURE;
    }
    // remove the status bytes
    response.pop_back();
    response.pop_back();
    return SUCCESS;
}

int getUint64(const std::unique_ptr<Item> &item, const uint32_t pos, uint64_t* value) {
    Array *arr = nullptr;

    if (MajorType::ARRAY != item.get()->type()) {
        return FAILURE;
    }
    arr = const_cast<Array *>(item.get()->asArray());
    if (arr->size() < (pos + 1)) {
        return FAILURE;
    }
    *value = arr->get(pos)->asUint()->value();
    return SUCCESS;
}


uint64_t unmaskPowerResetFlag(uint64_t errorCode) {
    bool isSeResetOccurred = (0 != (errorCode & SE_POWER_RESET_STATUS_FLAG));

    if (isSeResetOccurred) {
        printf("\n Secure element reset happened\n");
        errorCode &= ~SE_POWER_RESET_STATUS_FLAG;
    }
    return errorCode;
}

int provisionData(std::shared_ptr<SocketTransport>& pSocket, std::string apdu, std::vector<uint8_t>& response) {
    if (SUCCESS != sendData(pSocket, apdu, response)) {
        return FAILURE;
    }
    auto [item, pos, message] = cppbor::parse(response);
    if(item != nullptr) {
        uint64_t err;
        if(MajorType::ARRAY == item.get()->type()) {
            if(SUCCESS != getUint64(item, 0, &err)) {
                printf("\n Failed to parse the error code \n");
                return FAILURE;
            }
        } else if (MajorType::UINT == item.get()->type()) {
            const Uint* uintVal = item.get()->asUint();
            err = uintVal->value();
        }
        err = unmaskPowerResetFlag(err);
        if (err != 0) {
            printf("\n Failed with error:%ld", err);
            return FAILURE;
        }
    } else {
        printf("\n Failed to parse the response\n");
        return FAILURE;
    }
    return SUCCESS;
}

int provisionData(std::shared_ptr<SocketTransport>& pSocket, const char* jsonKey) {
    Json::Value val = root.get(jsonKey, Json::Value::nullRef);
    if (!val.isNull()) {
        if (val.isString()) {
            std::vector<uint8_t> response;
            if (SUCCESS != provisionData(pSocket, hex2str(val.asString()), response)) {
                printf("\n Error while provisioning %s \n", jsonKey);
                return FAILURE;
            }
        } else {
            printf("\n Fail: Expected (%s) tag value is string. \n", jsonKey);
            return FAILURE;
        }
    }
    printf("\n Successfully provisioned %s \n", jsonKey);
    return SUCCESS;
}

int openConnection(std::shared_ptr<SocketTransport>& pSocket) {
    if (!pSocket->isConnected()) {
        if (!pSocket->openConnection())
            return FAILURE;
    } else {
        printf("\n Socket already opened.\n");
    }
    return SUCCESS;
} 

// Parses the input json file. Sends the apdus to JCServer.
int processInputFile() {
    // Parse Json file
    if (0 != readJsonFile(root, inputFileName)) {
        return FAILURE;
    }
    std::shared_ptr<SocketTransport> pSocket = SocketTransport::getInstance();
    if (SUCCESS != openConnection(pSocket)) {
        printf("\n Failed to open connection \n");
        return FAILURE;
    }
    if (0 != provisionData(pSocket, kDeviceUniqueKey) ||
        0 != provisionData(pSocket, kAdditionalCertChain) ||
        0 != provisionData(pSocket, kAttestationIds) ||
        0 != provisionData(pSocket, kSharedSecret) ||
        0 != provisionData(pSocket, kBootParams)) {
        return FAILURE;
    }
    return SUCCESS;
}

int lockProvision() {
    std::vector<uint8_t> response;
    std::shared_ptr<SocketTransport> pSocket = SocketTransport::getInstance();
    if (SUCCESS != openConnection(pSocket)) {
        printf("\n Failed to open connection \n");
        return FAILURE;
    }
    if (SUCCESS != provisionData(pSocket, lockProvisionApdu, response)) {
        printf("\n Failed to lock provision.\n");
        return FAILURE;
    }
    printf("\n Provision lock is successfull.\n");
    return SUCCESS;
}

int getProvisionStatus() {
    std::vector<uint8_t> response;
    std::shared_ptr<SocketTransport> pSocket = SocketTransport::getInstance();
    if (SUCCESS != openConnection(pSocket)) {
        printf("\n Failed to open connection \n");
        return FAILURE;
    }

    if (SUCCESS != provisionData(pSocket, provisionStatusApdu, response)) {
        printf("\n Failed to get provision status \n");
        return FAILURE;
    }
    auto [item, pos, message] = cppbor::parse(response);
    if(item != nullptr) {
        uint64_t status;
        if(SUCCESS != getUint64(item, 1, &status)) {
            printf("\n Failed to get the provision status.\n");
            return FAILURE;
        }
        // TODO Handle Keymint Provision status once added.
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
    } else {
        printf("\n Fail to parse the response \n");
        return FAILURE;
    }
    return SUCCESS;
}

int main(int argc, char* argv[]) {
    int c;
    bool provisionStatusSet = false;
    bool lockProvisionSet = false;

    struct option longOpts[] = {
        {"input",       required_argument, NULL, 'i'},
        {"provision_status", no_argument, NULL,  's'},
        {"lock_provision", no_argument,   NULL,  'l'},
        {"help",        no_argument,       NULL, 'h'},
        {0,0,0,0}
    };

    if (argc <= 1) {
        printf("\n Invalid command \n");
        usage();
        return FAILURE;
    }

    /* getopt_long stores the option index here. */
    while ((c = getopt_long(argc, argv, ":hls:i:", longOpts, NULL)) != -1) {
        switch(c) {
            case 'i':
                // input file
                inputFileName = std::string(optarg);
                std::cout << "input file: " << inputFileName << std::endl;
                break;
            case 's':
                provisionStatusSet = true;
                break;
            case 'l':
                lockProvisionSet = true;
                break;
            case 'h':
                // help
                usage();
                return SUCCESS;
            case ':':
                printf("\n Required arguments missing.\n");
                usage();
                return FAILURE;
            case '?':
            default:
                printf("\n Invalid option\n");
                usage();
                return FAILURE;
        }
    }
    // Process input file; send apuds to JCServer over socket.
    if (argc >= 3) {
        if (SUCCESS != processInputFile()) {
            return FAILURE;
        }
    }
    if (provisionStatusSet)
        getProvisionStatus();
    if (lockProvisionSet)
        lockProvision();
    return SUCCESS;
}


