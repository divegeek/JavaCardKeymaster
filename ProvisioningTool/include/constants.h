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
#pragma once

#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include "UniquePtr.h"

#define SUCCESS 0
#define FAILURE 1
#define KEYMASTER_VERSION 4.1
#define KEYMINT_VERSION 5
#define P1_40 0x40
#define P1_50 0x50
#define APDU_CLS 0x80
#define APDU_P1(version)  \
         (version == KEYMASTER_VERSION) ? \
         P1_40 : \
         P1_50
#define APDU_P2  0x00
#define INS_BEGIN_KM_CMD 0x00
#define APDU_RESP_STATUS_OK 0x9000
#define SE_POWER_RESET_STATUS_FLAG ( 1 << 30)



template <typename T, typename FreeFuncRet, FreeFuncRet (*FreeFunc)(T*)>
struct OpenSslObjectDeleter {
    void operator()(T* p) { FreeFunc(p); }
};

#define DEFINE_OPENSSL_OBJECT_POINTER(name)                                                        \
    typedef OpenSslObjectDeleter<name, decltype(name##_free(nullptr)), name##_free> name##_Delete; \
    typedef UniquePtr<name, name##_Delete> name##_Ptr;

DEFINE_OPENSSL_OBJECT_POINTER(EC_KEY)
DEFINE_OPENSSL_OBJECT_POINTER(EVP_PKEY)
DEFINE_OPENSSL_OBJECT_POINTER(X509)


// Tags
constexpr uint64_t kTagAlgorithm = 268435458u;
constexpr uint64_t kTagDigest = 536870917u;
constexpr uint64_t kTagCurve = 268435466u;
constexpr uint64_t kTagPurpose = 536870913u;
constexpr uint64_t kTagAttestationIdBrand = 2415919814u;
constexpr uint64_t kTagAttestationIdDevice = 2415919815u;
constexpr uint64_t kTagAttestationIdProduct = 2415919816u;
constexpr uint64_t kTagAttestationIdSerial = 2415919817u;
constexpr uint64_t kTagAttestationIdImei = 2415919818u;
constexpr uint64_t kTagAttestationIdMeid = 2415919819u;
constexpr uint64_t kTagAttestationIdManufacturer = 2415919820u;
constexpr uint64_t kTagAttestationIdModel = 2415919821u;

// Values
constexpr uint64_t kCurveP256 = 1;
constexpr uint64_t kAlgorithmEc = 3;
constexpr uint64_t kDigestSha256 = 4;
constexpr uint64_t kPurposeAttest = 0x7F;
constexpr uint64_t kKeyFormatRaw = 3;

// json keys
constexpr char kAttestKey[] = "attest_key";
constexpr char kAttestCertChain[] = "attest_cert_chain";
constexpr char kAttestCertParams[] = "attest_cert_params";
constexpr char kSharedSecret[] = "shared_secret";
constexpr char kBootParams[] = "boot_params";
constexpr char kAttestationIds[] = "attestation_ids";
constexpr char kDeviceUniqueKey[] = "device_unique_key";
constexpr char kAdditionalCertChain[] = "additional_cert_chain";
constexpr char kProvisionStatus[] = "provision_status";
constexpr char kLockProvision[] = "lock_provision";

// Instruction constatnts
constexpr int kAttestationKeyCmd = INS_BEGIN_KM_CMD + 1;
constexpr int kAttestCertChainCmd = INS_BEGIN_KM_CMD + 2;
constexpr int kAttestCertParamsCmd = INS_BEGIN_KM_CMD + 3;
constexpr int kAttestationIdsCmd = INS_BEGIN_KM_CMD + 4;
constexpr int kPresharedSecretCmd = INS_BEGIN_KM_CMD + 5;
constexpr int kBootParamsCmd = INS_BEGIN_KM_CMD + 6;
constexpr int kLockProvisionCmd = INS_BEGIN_KM_CMD + 7;
constexpr int kGetProvisionStatusCmd = INS_BEGIN_KM_CMD + 8;
constexpr int kDeviceUniqueKeyCmd = INS_BEGIN_KM_CMD + 10;
constexpr int kAdditionalCertChainCmd = INS_BEGIN_KM_CMD + 11;