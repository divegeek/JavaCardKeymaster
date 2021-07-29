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

// static globals.
static double keymasterVersion = -1;
static std::string inputFileName;
static std::string outputFileName;
Json::Value root;
Json::Value writerRoot;

using namespace std;
using cppbor::Array;
using cppbor::Map;
using cppbor::Bstr;

// static function declarations
static int processInputFile();
static int processAttestationKey();
static int processAttestationCertificateChain();
static int processAttestationCertificateParams();
static int processAttestationIds();
static int processSharedSecret();
static int processDeviceUniqueKey();
static int processAdditionalCertificateChain();
static int processSetBootParameters();
static int readDataFromFile(const char *fileName, std::vector<uint8_t>& data);
static int addApduHeader(const int ins, std::vector<uint8_t>& inputData);
static int ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret, std::vector<uint8_t>&publicKey);
static X509* parseDerCertificate(std::vector<uint8_t>& certData);
static int getNotAfter(X509* x509, std::vector<uint8_t>& notAfterDate);
static int getDerSubjectName(X509* x509, std::vector<uint8_t>& subject);
static int getBootParameterIntValue(Json::Value& bootParamsObj, const char* key, uint32_t *value);
static int getBootParameterBlobValue(Json::Value& bootParamsObj, const char* key, std::vector<uint8_t>& blob);


// Print usage.
void usage() {
    printf("Usage: Please give jason files with values as input to generate the apdus command. Please refer to sample_json files available in the folder for reference. Sample json files are written using hardcode parameters to be used for testing setup on cuttlefilsh emulator and goldfish emulators\n");
    printf("construct_apdus [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-v, --km_version version \t Version of the keymaster (4.1 for keymaster; 5 for keymint) \n");
    printf("-i, --input  jsonFile \t Input json file \n");
    printf("-o, --output jsonFile \t Output json file \n");
}


X509* parseDerCertificate(std::vector<uint8_t>& certData) {
    X509 *x509 = nullptr;

    /* Create BIO instance from certificate data */
    BIO *bio = BIO_new_mem_buf(certData.data(), certData.size());
    if(bio == nullptr) {
        printf("\n Failed to create BIO from buffer.\n");
        return nullptr;
    }
    /* Create X509 instance from BIO */
    x509 = d2i_X509_bio(bio, NULL);
    if(x509 == nullptr) {
        printf("\n Failed to get X509 instance from BIO.\n");
        return nullptr;
    }
    BIO_free(bio);
    return x509;
}

int getDerSubjectName(X509* x509, std::vector<uint8_t>& subject) {
    uint8_t *subjectDer = NULL;
    X509_NAME* asn1Subject = X509_get_subject_name(x509);
    if(asn1Subject == NULL) {
        printf("\n Failed to read the subject.\n");
        return FAILURE;
    }
    /* Convert X509_NAME to der encoded subject */
    int len = i2d_X509_NAME(asn1Subject, &subjectDer);
    if (len < 0) {
        printf("\n Failed to get readable name from X509_NAME.\n");
        return FAILURE;
    }
    subject.insert(subject.begin(), subjectDer, subjectDer+len);
    return SUCCESS;
}

int getNotAfter(X509* x509, std::vector<uint8_t>& notAfterDate) {
    const ASN1_TIME* notAfter = X509_get0_notAfter(x509);
    if(notAfter == NULL) {
        printf("\n Failed to read expiry time.\n");
        return FAILURE;
    }
    int strNotAfterLen = ASN1_STRING_length(notAfter);
    const uint8_t *strNotAfter = ASN1_STRING_get0_data(notAfter);
    if(strNotAfter == NULL) {
        printf("\n Failed to read expiry time from ASN1 string.\n");
        return FAILURE;
    }
    notAfterDate.insert(notAfterDate.begin(), strNotAfter, strNotAfter + strNotAfterLen);
    return SUCCESS;
}


int getBootParameterIntValue(Json::Value& bootParamsObj, const char* key, uint32_t *value) {
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isInt())
        return FAILURE;

    *value = (uint32_t)val.asInt();

    return SUCCESS;
}

int getBootParameterBlobValue(Json::Value& bootParamsObj, const char* key, std::vector<uint8_t>& blob) {
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

    if (keymasterVersion == KEYMASTER_VERSION) {
        printf("\n Selected Keymaster version(%f) for provisioning \n", keymasterVersion);
        if (0 != processAttestationKey() ||
                0 != processAttestationCertificateChain() ||
                0 != processAttestationCertificateParams()) {
            return FAILURE;
        }
    } else {
        printf("\n Selected keymint version(%f) for provisioning \n", keymasterVersion);
        if ( 0 != processDeviceUniqueKey() ||
                0 != processAttestationCertificateChain()) {
            return FAILURE;
        }
    }
    if (0 != processAttestationIds() ||
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

int processAttestationKey() {
    Json::Value keyFile = root.get(kAttestKey, Json::Value::nullRef);
    if (!keyFile.isNull()) {
        std::vector<uint8_t> data;
        std::vector<uint8_t> privateKey;
        std::vector<uint8_t> publicKey;

        std::string keyFileName = keyFile.asString();
        if(SUCCESS != readDataFromFile(keyFileName.data(), data)) {
            printf("\n Failed to read the attestation key from the file.\n");
            return FAILURE;
        }
        if (SUCCESS != ecRawKeyFromPKCS8(data, privateKey, publicKey)) {
            return FAILURE;
        }

        // Prepare cbor input.
        Array input;
        Array keys;
        Map map;
        keys.add(privateKey);
        keys.add(publicKey);
        map.add(kTagAlgorithm, kAlgorithmEc);
        map.add(kTagDigest, std::vector<uint8_t>({kDigestSha256}));
        map.add(kTagCurve, kCurveP256);
        map.add(kTagPurpose, std::vector<uint8_t>({kPurposeAttest}));
        // Add elements inside cbor array.
        input.add(std::move(map));
        input.add(kKeyFormatRaw);
        input.add(keys.encode());
        std::vector<uint8_t> cborData = input.encode();

        if(SUCCESS != addApduHeader(kAttestationKeyCmd, cborData)) {
            return FAILURE;
        }
        // Write to json.
        writerRoot[kAttestKey] = getHexString(cborData);
    } else {
        printf("\n Improper value for attest_key in json file \n");
        return FAILURE;
    }
    printf("\n Constructed attestation key APDU successfully. \n");
    return SUCCESS;
}

static int processAttestationCertificateChain() {
    Json::Value certChainFiles = root.get(kAttestCertChain, Json::Value::nullRef);
    if (!certChainFiles.isNull()) {
        std::vector<uint8_t> certData;

        if(certChainFiles.isArray()) {
            for (uint32_t i = 0; i < certChainFiles.size(); i++) {
                if(certChainFiles[i].isString()) {
                    /* Read the certificates. */
                    if(SUCCESS != readDataFromFile(certChainFiles[i].asString().data(), certData)) {
                        printf("\n Failed to read the Root certificate\n");
                        return FAILURE;
                    }
                } else {
                    printf("\n Fail: Only proper certificate paths as a string is allowed inside the json file. \n");
                    return FAILURE;
                }
            }
        } else {
            printf("\n Fail: cert chain value should be an array inside the json file. \n");
            return FAILURE;
        }
        // Prepare cbor input
        std::vector<uint8_t> cborData = Bstr(certData).encode();
        if (SUCCESS != addApduHeader(kAttestCertChainCmd, cborData)) {
            return FAILURE;
        }
        // Write to json.
        writerRoot[kAttestCertChain] = getHexString(cborData);
    } else {
        printf("\n Fail: Improper value found for attest_cert_chain key inside json file \n");
        return FAILURE;
    }
    printf("\n Constructed attestation certificate chain APDU successfully. \n");
    return SUCCESS;
}

int processAttestationCertificateParams() {
    Json::Value certChainFile = root.get(kAttestCertChain, Json::Value::nullRef);
    if (!certChainFile.isNull()) {
        std::vector<std::vector<uint8_t>> certData;
        if (certChainFile.isArray()) {
            if (certChainFile.size() == 0) {
                printf("\n empty certificate.\n");
                return FAILURE;
            }
            std::vector<uint8_t> leafCertificate;
            if (SUCCESS != readDataFromFile(certChainFile[0].asString().data(), leafCertificate)) {
                printf("\n Failed to read the Root certificate\n");
                return FAILURE;
            }
            // ----------------
            // Prepare cbor data.
            Array array;
            std::vector<uint8_t> subject;
            std::vector<uint8_t> notAfter;

            /* Subject, AuthorityKeyIdentifier and Expirty time of the root certificate are required by javacard. */
            /* Get X509 certificate instance for the root certificate.*/
            X509_Ptr x509(parseDerCertificate(leafCertificate));
            if (!x509) {
                return FAILURE;
            }

            /* Get subject in DER */
            getDerSubjectName(x509.get(), subject);
            /* Get Expirty Time */
            getNotAfter(x509.get(), notAfter);

            array.add(subject);
            array.add(notAfter);
            std::vector<uint8_t> cborData = array.encode();
            if (SUCCESS != addApduHeader(kAttestCertParamsCmd, cborData)) {
                return FAILURE;
            }
            // Write to json.
            writerRoot[kAttestCertParams] = getHexString(cborData);
            //-----------------
        } else {
            printf("\n Fail: cert chain value should be an array inside the json file. \n");
            return FAILURE;
        }
    } else {
        printf("\n Fail: Improper value found for attest_cert_chain key inside json file \n");
        return FAILURE;
    }
    printf("\n Constructed attestation certificate params APDU successfully. \n");
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

        if(SUCCESS != getBootParameterIntValue(bootParamsObj, "boot_patch_level", &bootPatchLevel)) {
            printf("\n Invalid value for boot_patch_level or boot_patch_level tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getBootParameterBlobValue(bootParamsObj, "verified_boot_key", verifiedBootKey)) {
            printf("\n Invalid value for verified_boot_key or verified_boot_key tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getBootParameterBlobValue(bootParamsObj, "verified_boot_key_hash", verifiedBootKeyHash)) {
            printf("\n Invalid value for verified_boot_key_hash or verified_boot_key_hash tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getBootParameterIntValue(bootParamsObj, "boot_state", &verifiedBootState)) {
            printf("\n Invalid value for boot_state or boot_state tag missing\n");
            return FAILURE;
        }
        if(SUCCESS != getBootParameterIntValue(bootParamsObj, "device_locked", &deviceLocked)) {
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

int ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret,
        std::vector<uint8_t>&publicKey) {
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
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key.get());
    int pubKeyLen=0;
    pubKeyLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::unique_ptr<uint8_t[]> pubKey(new uint8_t[pubKeyLen]);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pubKey.get(), pubKeyLen, NULL);
    publicKey.insert(publicKey.begin(), pubKey.get(), pubKey.get()+pubKeyLen);

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
    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_P1(keymasterVersion)));//P1
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

// TODO
static int processDeviceUniqueKey() { return 0; }
static int processAdditionalCertificateChain() { return 0; }


int main(int argc, char* argv[]) {
    int c;
    struct option longOpts[] = {
        {"km_version",   required_argument, NULL, 'v'},
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
    while ((c = getopt_long(argc, argv, ":hv:i:o:", longOpts, NULL)) != -1) {
        switch(c) {
            case 'v':
                // keymaster version
                keymasterVersion = atof(optarg);
                std::cout << "Version: " << keymasterVersion << std::endl;
                break;
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
    if (keymasterVersion == -1 || inputFileName.empty() ||
            outputFileName.empty() || optind < argc) {
        printf("\n Missing mandatory arguments \n");
        usage();
        return FAILURE;
    }
    if (keymasterVersion != KEYMASTER_VERSION && keymasterVersion != KEYMINT_VERSION) {
        printf("\n Error unknown version.");
        return FAILURE;
    }
    // Process input file; construct apuds and store in output json file.
    processInputFile();
    return SUCCESS;
}
