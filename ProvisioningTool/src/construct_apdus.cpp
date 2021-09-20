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
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <memory>
#include <climits>
#include <getopt.h>
#include <json/reader.h>
#include <json/writer.h>
#include <json/value.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <constants.h>
#include <utils.h>
#include "cppbor/cppbor.h"
#include "cppcose/cppcose.h"

// static globals.
static std::string inputFileName;
static std::string outputFileName;
Json::Value root;
Json::Value writerRoot;

using namespace std;
using cppbor::Array;
using cppbor::Map;
using cppbor::Bstr;
using cppcose::CoseKey;
using cppcose::EC2;
using cppcose::ES256;
using cppcose::P256;
using cppcose::SIGN;
using cppcose::bytevec;


// static function declarations
static int processInputFile();
static int ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret, 
                             std::vector<uint8_t>& pub_x, std::vector<uint8_t>& pub_y);
static int processAttestationIds();
static int processSharedSecret();
static int processSetBootParameters();
static int readDataFromFile(const char *fileName, std::vector<uint8_t>& data);
static int addApduHeader(const int ins, std::vector<uint8_t>& inputData);
static int getIntValue(Json::Value& Obj, const char* key, uint32_t *value);
static int getBlobValue(Json::Value& Obj, const char* key, std::vector<uint8_t>& blob);
static int getStringValue(Json::Value& Obj, const char* key, std::string& str);
static int processDeviceUniqueKey();
static int processAdditionalCertificateChain();
static int getDeviceUniqueKey(bytevec& privKey, bytevec& x, bytevec& y);


// Print usage.
void usage() {
    printf("Usage: Please give json files with values as input to generate the apdus command. Please refer to sample_json files available in the folder for reference. Sample json files are written using hardcode parameters to be used for testing setup on cuttlefilsh emulator and goldfish emulators\n");
    printf("construct_keymint_apdus [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-i, --input  jsonFile \t Input json file \n");
    printf("-o, --output jsonFile \t Output json file \n");
}


int ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret,
        std::vector<uint8_t>& pub_x, std::vector<uint8_t>& pub_y) {
    const uint8_t *data = pkcs8Blob.data();
    EVP_PKEY *evpkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &data, pkcs8Blob.size());
    if(!evpkey) {
        printf("\n Failed to decode private key from PKCS8, Error: %ld", ERR_peek_last_error());
        return FAILURE;
    }
    EVP_PKEY_Ptr pkey(evpkey);

    EC_KEY_Ptr ec_key(EVP_PKEY_get1_EC_KEY(pkey.get()));
    if(!ec_key.get()) {
        printf("\n Failed to create EC_KEY, Error: %ld", ERR_peek_last_error());
        return FAILURE;
    }

    //Get EC Group
    const EC_GROUP *group = EC_KEY_get0_group(ec_key.get());
    if(group == NULL) {
        printf("\n Failed to get the EC_GROUP from ec_key.");
        return FAILURE;
    }

    //Extract private key.
    const BIGNUM *privBn = EC_KEY_get0_private_key(ec_key.get());
    int privKeyLen = BN_num_bytes(privBn);
    std::unique_ptr<uint8_t[]> privKey(new uint8_t[privKeyLen]);
    BN_bn2bin(privBn, privKey.get());
    secret.insert(secret.begin(), privKey.get(), privKey.get()+privKeyLen);

    //Extract public key.
    BIGNUM_Ptr x(BN_new());
    BIGNUM_Ptr y(BN_new());
    std::vector<uint8_t> dataX(kAffinePointLength);
    std::vector<uint8_t> dataY(kAffinePointLength);
    BN_CTX_Ptr ctx(BN_CTX_new());
    if (ctx == nullptr) {
        printf("\nFailed to get BN_CTX \n");
        return FAILURE;
    }
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key.get());

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ec_key.get()), point, x.get(), 
                                             y.get(), ctx.get())) {
        printf("\nFailed to get affine coordinates\n");
        return FAILURE;
    }   
    if (BN_bn2binpad(x.get(), dataX.data(), kAffinePointLength) != kAffinePointLength) {
        printf("\nFailed to get x coordinate\n");
        return FAILURE;
    }   
    if (BN_bn2binpad(y.get(), dataY.data(), kAffinePointLength) != kAffinePointLength) {
        printf("\nFailed to get y coordinate\n");
        return FAILURE;
    }
    pub_x = dataX;
    pub_y = dataY;
    return SUCCESS;
}

int getIntValue(Json::Value& bootParamsObj, const char* key, uint32_t *value) {
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isInt())
        return FAILURE;

    *value = (uint32_t)val.asInt();

    return SUCCESS;
}

int getStringValue(Json::Value& Obj, const char* key, std::string& str) {
    Json::Value val = Obj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isString())
        return FAILURE;

    str = val.asString();

    return SUCCESS;

}

int getBlobValue(Json::Value& bootParamsObj, const char* key, std::vector<uint8_t>& blob) {
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isString())
        return FAILURE;

    std::string blobStr = hex2str(val.asString());

    for(char ch : blobStr) {
        blob.push_back((uint8_t)ch);
    }

    return SUCCESS;
}


// Parses the input json file. Prepares the apdu for each entry in the json
// file and dump all the apdus into the output json file.
int processInputFile() {

    // Parse Json file
    if (0 != readJsonFile(root, inputFileName)) {
        return FAILURE;
    }
    if (0 != processDeviceUniqueKey() ||
        0 != processAdditionalCertificateChain() ||
        0 != processAttestationIds() ||
        0 != processSharedSecret() ||
        0 != processSetBootParameters()) {
        return FAILURE;
    }
    if (SUCCESS != writeJsonFile(writerRoot, outputFileName)) {
        return FAILURE;
    }
    printf("\n Successfully written json to outfile: %s\n ", outputFileName.c_str());
    return SUCCESS;
}

int processAdditionalCertificateChain() {
    Json::Value signerInfo = root.get(kSignerInfo, Json::Value::nullRef);
    if (!signerInfo.isNull()) {
        std::string signerName;
        std::string signingKeyFile;
        std::vector<uint8_t> previousKey;
        Array array;

        if (SUCCESS != getStringValue(signerInfo, "signer_name", signerName)) {
            printf("\n Improper value for signer_name in json file \n");
            return FAILURE;
        }

        Json::Value keys = signerInfo.get("signing_keys", Json::Value::nullRef);
        if (!keys.isNull()) {
            if (!keys.isArray()) {
                printf("\n Improper value for signing_keys in json file \n");
                return FAILURE;
            }
            for(uint32_t i = 0; i < keys.size(); i++) {
                std::vector<uint8_t> data;
                std::vector<uint8_t> privateKey;
                std::vector<uint8_t> x_coord;
                std::vector<uint8_t> y_coord;

                if (!keys[i].isString()) {
                    printf("\n Improper value for signing_keys in json file \n");
                    return FAILURE;
                }

                if(SUCCESS != readDataFromFile(keys[i].asString().data(), data)) {
                    printf("\n Failed to read the attestation key from the file.\n");
                    return FAILURE;
                }
                if (SUCCESS != ecRawKeyFromPKCS8(data, privateKey, x_coord, y_coord)) {
                    return FAILURE;
                }

                if (i == 0) {
                    // self-signed.
                    previousKey = privateKey;
                }

                auto rootCoseSign =
                    cppcose::constructCoseSign1(previousKey, /* Signing key */
                            cppbor::Map() /* Payload CoseKey */
                            .add(CoseKey::KEY_TYPE, EC2)
                            .add(CoseKey::ALGORITHM, ES256)
                            .add(CoseKey::CURVE, P256)
                            .add(CoseKey::KEY_OPS, SIGN)
                            .add(CoseKey::PUBKEY_X, x_coord)
                            .add(CoseKey::PUBKEY_Y, y_coord)
                            .canonicalize()
                            .encode(),
                            {} /* AAD */);
                if (!rootCoseSign) {
                    printf("\n Failed to construct CoseSign1 %s\n", rootCoseSign.moveMessage().c_str());
                    return FAILURE;
                }

                // Add to cbor array
                array.add(rootCoseSign.moveValue());
                previousKey = privateKey;
            }
        }

        std::vector<uint8_t> dk_priv;
        std::vector<uint8_t> dk_pub_x;
        std::vector<uint8_t> dk_pub_y;
        if (SUCCESS == getDeviceUniqueKey(dk_priv, dk_pub_x, dk_pub_y)) {
            auto dkCoseSign =
                cppcose::constructCoseSign1(previousKey, /* Signing key */
                        cppbor::Map() /* Payload CoseKey */
                                .add(CoseKey::KEY_TYPE, EC2)
                                .add(CoseKey::ALGORITHM, ES256)
                                .add(CoseKey::CURVE, P256)
                                .add(CoseKey::KEY_OPS, SIGN)
                                .add(CoseKey::PUBKEY_X, dk_pub_x)
                                .add(CoseKey::PUBKEY_Y, dk_pub_y)
                                .canonicalize()
                        .encode(),
                        {} /* AAD */);
            if (!dkCoseSign) {
                printf("\n Failed to construct CoseSign1 %s\n", dkCoseSign.moveMessage().c_str());
                return FAILURE;
            }
            array.add(dkCoseSign.moveValue());
            std::vector<uint8_t> cborData = Map().add(signerName, std::move(array)).encode();
            if(SUCCESS != addApduHeader(kAdditionalCertChainCmd, cborData)) {
                return FAILURE;
            }
            // Write to json.
            writerRoot[kAdditionalCertChain] = getHexString(cborData);
        } else {
            return FAILURE;
        }

    } else {
        printf("\n Improper value for signer_info in json file \n");
        return FAILURE;
    }
    printf("\n Constructed additional cert chain APDU successfully. \n");
    return SUCCESS;
}

int getDeviceUniqueKey(bytevec& privKey, bytevec& x, bytevec& y) {
    Json::Value keyFile = root.get(kDeviceUniqueKey, Json::Value::nullRef);
    if (!keyFile.isNull()) {
        std::vector<uint8_t> data;

        std::string keyFileName = keyFile.asString();
        if(SUCCESS != readDataFromFile(keyFileName.data(), data)) {
            printf("\n Failed to read the attestation key from the file.\n");
            return FAILURE;
        }
        if (SUCCESS != ecRawKeyFromPKCS8(data, privKey, x, y)) {
            return FAILURE;
        }
    } else {
        printf("\n Improper value for device_unique_key in json file \n");
        return FAILURE;
    }
    return SUCCESS;
}

int processDeviceUniqueKey() {
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> x_coord;
    std::vector<uint8_t> y_coord;
    if (SUCCESS == getDeviceUniqueKey(privateKey, x_coord, y_coord)) {
        // Construct COSE_Key
        cppbor::Map cose_public_key_map = cppbor::Map()
                                          .add(CoseKey::KEY_TYPE, EC2)
                                          .add(CoseKey::ALGORITHM, ES256)
                                          .add(CoseKey::CURVE, P256)
                                          .add(CoseKey::KEY_OPS, SIGN)
                                          .add(CoseKey::PUBKEY_X, x_coord)
                                          .add(CoseKey::PUBKEY_Y, y_coord)
                                          .add(CoseKey::PRIVATE_KEY, privateKey);
 
        Array array;
        array.add(std::move(cose_public_key_map.canonicalize()));
        std::vector<uint8_t> cborData = array.encode();

        if(SUCCESS != addApduHeader(kDeviceUniqueKeyCmd, cborData)) {
            return FAILURE;
        }
        // Write to json.
        writerRoot[kDeviceUniqueKey] = getHexString(cborData);

    } else {
        return FAILURE;
    }
    printf("\n Constructed device unique key APDU successfully. \n");
    return SUCCESS;
}


int processAttestationIds() {
    //AttestIDParams params;
    Json::Value attestIds = root.get("attest_ids", Json::Value::nullRef);
    if (!attestIds.isNull()) {
        Json::Value value;
        Map map;
        Json::Value::Members keys = attestIds.getMemberNames();
        for(std::string key : keys) {
            value = attestIds[key];
            if(value.empty()) {
                continue;
            }
            if (!value.isString()) {
                printf("\n Fail: Value for each attest ids key should be a string in the json file \n");
                return FAILURE;
            }
            std::string idVal = value.asString();
            if (0 == key.compare("brand")) {
                map.add(kTagAttestationIdBrand, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("device")) {
                map.add(kTagAttestationIdDevice, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("product")) {
                map.add(kTagAttestationIdProduct, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("serial")) {
                map.add(kTagAttestationIdSerial, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("imei")) {
                map.add(kTagAttestationIdImei, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("meid")) {
                map.add(kTagAttestationIdMeid, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("manufacturer")) {
                map.add(kTagAttestationIdManufacturer, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else if(0 == key.compare("model")) {
                map.add(kTagAttestationIdModel, std::vector<uint8_t>(idVal.begin(), idVal.end()));
            } else {
                printf("\n unknown attestation id key:%s \n", key.c_str());
                return FAILURE;
            }
        }

        //-------------------------
        // construct cbor input.
        Array array;
        array.add(std::move(map));
        std::vector<uint8_t> cborData = array.encode();
        if (SUCCESS != addApduHeader(kAttestationIdsCmd, cborData)) {
            return FAILURE;
        }
        // Write to json.
        writerRoot[kAttestationIds] = getHexString(cborData);
        //-------------------------
    } else {
        printf("\n Fail: Improper value found for attest_ids key inside the json file \n");
        return FAILURE;
    }
    printf("\n Constructed attestation ids APDU successfully \n");
    return SUCCESS;
}

int processSharedSecret() {
    Json::Value sharedSecret = root.get("shared_secret", Json::Value::nullRef);
    if (!sharedSecret.isNull()) {

        if (!sharedSecret.isString()) {
            printf("\n Fail: Value for shared secret key should be string inside the json file\n");
            return FAILURE;
        }
        std::string secret = hex2str(sharedSecret.asString());
        std::vector<uint8_t> data(secret.begin(), secret.end());
        // --------------------------
        // Construct apdu.
        Array array;
        array.add(data);
        std::vector<uint8_t> cborData = array.encode();
        if (SUCCESS != addApduHeader(kPresharedSecretCmd, cborData)) {
            return FAILURE;
        }
        // Write to json.
        writerRoot[kSharedSecret] = getHexString(cborData);
        // --------------------------
    } else {
        printf("\n Fail: Improper value for shared_secret key inside the json file\n");
        return FAILURE;
    }
    printf("\n Constructed shared secret APDU successfully \n");
    return SUCCESS;
}

int processSetBootParameters() {
    uint32_t bootPatchLevel;
	std::vector<uint8_t> verifiedBootKey;
	std::vector<uint8_t> verifiedBootKeyHash;
	uint32_t verifiedBootState;
	uint32_t deviceLocked;
    Json::Value bootParamsObj = root.get("set_boot_params", Json::Value::nullRef);
    if (!bootParamsObj.isNull()) {

        if(SUCCESS != getIntValue(bootParamsObj, "boot_patch_level", &bootPatchLevel)) {
            printf("\n Invalid value for boot_patch_level or boot_patch_level tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getBlobValue(bootParamsObj, "verified_boot_key", verifiedBootKey)) {
            printf("\n Invalid value for verified_boot_key or verified_boot_key tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getBlobValue(bootParamsObj, "verified_boot_key_hash", verifiedBootKeyHash)) {
            printf("\n Invalid value for verified_boot_key_hash or verified_boot_key_hash tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getIntValue(bootParamsObj, "boot_state", &verifiedBootState)) {
            printf("\n Invalid value for boot_state or boot_state tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getIntValue(bootParamsObj, "device_locked", &deviceLocked)) {
            printf("\n Invalid value for device_locked or device_locked tag missing\n");
            return FAILURE;
        }

    } else {
        printf("\n Fail: Improper value found for set_boot_params key inside the json file\n");
        return FAILURE;
    }
    //---------------------------------
    // prepare cbor data.
    Array array;
    array.add(bootPatchLevel).
    add(verifiedBootKey). /* Verified Boot Key */
    add(verifiedBootKeyHash). /* Verified Boot Hash */
    add(verifiedBootState). /* boot state */
    add(deviceLocked);     /* device locked */

    std::vector<uint8_t> cborData = array.encode();
    if (SUCCESS != addApduHeader(kBootParamsCmd, cborData)) {
        return FAILURE;
    }
    // Write to json.
    writerRoot[kBootParams] = getHexString(cborData);

    //---------------------------------
    printf("\n Constructed boot paramters APDU successfully \n");
    return SUCCESS;
}



int addApduHeader(const int ins, std::vector<uint8_t>& inputData) {
    if(USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le all set to 00.
        // Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        //Extended length 3 bytes, starts with 0x00
        if (inputData.size() > 0) {
            inputData.insert(inputData.begin(), static_cast<uint8_t>(inputData.size() & 0xFF)); // LSB
            inputData.insert(inputData.begin(), static_cast<uint8_t>(inputData.size() >> 8)); // MSB
        }
        inputData.insert(inputData.begin(), static_cast<uint8_t>(0x00));
        //Expected length of output.
        //Accepting complete length of output every time.
        inputData.push_back(static_cast<uint8_t>(0x00));
        inputData.push_back(static_cast<uint8_t>(0x00));
    } else {
        printf("\n Failed to construct apdu. input data larger than USHORT_MAX.\n");
        return FAILURE;
    }

    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_P2));//P2
    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_P1));//P1
    inputData.insert(inputData.begin(), static_cast<uint8_t>(ins));//INS
    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_CLS));//CLS
    return SUCCESS;
}

int readDataFromFile(const char *filename, std::vector<uint8_t>& data) {
    FILE *fp;
    int ret = SUCCESS;
    fp = fopen(filename, "rb");
    if(fp == NULL) {
        printf("\nFailed to open file: \n");
        return FAILURE;
    }
    fseek(fp, 0L, SEEK_END);
    long int filesize = ftell(fp);
    rewind(fp);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[filesize]);
    if( 0 == fread(buf.get(), filesize, 1, fp)) {
        printf("\n No content in the file \n");
        ret = FAILURE;
        goto exit;
    }
    data.insert(data.end(), buf.get(), buf.get() + filesize);
exit:    
    fclose(fp);
    return ret;
}

int main(int argc, char* argv[]) {
    int c;
    struct option longOpts[] = {
        {"input",       required_argument, NULL, 'i'},
        {"output",       required_argument, NULL, 'o'},
        {"help",             no_argument,       NULL, 'h'},
        {0,0,0,0}
    };

    if (argc <= 1) {
        printf("\n Invalid command \n");
        usage();
        return FAILURE;
    }

    /* getopt_long stores the option index here. */
    while ((c = getopt_long(argc, argv, ":hi:o:", longOpts, NULL)) != -1) {
        switch(c) {
            case 'i':
                // input file
                inputFileName = std::string(optarg);
                std::cout << "input file: " << inputFileName << std::endl;
                break;
            case 'o':
                // output file
                outputFileName = std::string(optarg);
                std::cout << "output file: " << outputFileName << std::endl;
                break;
            case 'h':
                // help
                usage();
                return SUCCESS;
            case ':':
                printf("\n missing argument\n");
                usage();
                return FAILURE;
            case '?':
            default:
                printf("\n Invalid option\n");
                usage();
                return FAILURE;
        }
    }
    if (inputFileName.empty() || outputFileName.empty() || optind < argc) {
        printf("\n Missing mandatory arguments \n");
        usage();
        return FAILURE;
    }
    // Process input file; construct apuds and store in output json file.
    processInputFile();
    return SUCCESS;
}
