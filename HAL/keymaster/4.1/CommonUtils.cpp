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

#include <CommonUtils.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/nid.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <keymaster/km_openssl/rsa_key.h>
#include <keymaster/km_openssl/ec_key.h>
#include <android-base/logging.h>

#define TAG_SEQUENCE 0x30
#define LENGTH_MASK 0x80
#define LENGTH_VALUE_MASK 0x7F

namespace keymaster {
namespace V4_1 {
namespace javacard {

hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set) {
    hidl_vec<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr)
        return result;

    result.resize(set.length);
    keymaster_key_param_t* params = set.params;
    for (size_t i = 0; i < set.length; ++i) {
        auto tag = params[i].tag;
        result[i].tag = legacy_enum_conversion(tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            result[i].f.integer = params[i].enumerated;
            break;
        case KM_UINT:
        case KM_UINT_REP:
            result[i].f.integer = params[i].integer;
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            result[i].f.longInteger = params[i].long_integer;
            break;
        case KM_DATE:
            result[i].f.dateTime = params[i].date_time;
            break;
        case KM_BOOL:
            result[i].f.boolValue = params[i].boolean;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            result[i].blob.setToExternal(const_cast<unsigned char*>(params[i].blob.data),
                                         params[i].blob.data_length);
            break;
        case KM_INVALID:
        default:
            params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }
    return result;
}

keymaster_key_param_set_t hidlKeyParams2Km(const hidl_vec<KeyParameter>& keyParams) {
    keymaster_key_param_set_t set;

    set.params = new keymaster_key_param_t[keyParams.size()];
    set.length = keyParams.size();

    for (size_t i = 0; i < keyParams.size(); ++i) {
        auto tag = legacy_enum_conversion(keyParams[i].tag);
        switch (typeFromTag(tag)) {
            case KM_ENUM:
            case KM_ENUM_REP:
                set.params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
                break;
            case KM_UINT:
            case KM_UINT_REP:
                set.params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
                break;
            case KM_ULONG:
            case KM_ULONG_REP:
                set.params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
                break;
            case KM_DATE:
                set.params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
                break;
            case KM_BOOL:
                if (keyParams[i].f.boolValue)
                    set.params[i] = keymaster_param_bool(tag);
                else
                    set.params[i].tag = KM_TAG_INVALID;
                break;
            case KM_BIGNUM:
            case KM_BYTES:
                set.params[i] =
                    keymaster_param_blob(tag, &keyParams[i].blob[0], keyParams[i].blob.size());
                break;
            case KM_INVALID:
            default:
                set.params[i].tag = KM_TAG_INVALID;
                /* just skip */
                break;
        }
    }

    return set;
}

ErrorCode getEcCurve(const EC_GROUP *group, EcCurve& ecCurve) {
    int curve = EC_GROUP_get_curve_name(group);
    switch(curve) {
        case NID_secp224r1:
            ecCurve = EcCurve::P_224;
            break;
        case NID_X9_62_prime256v1:
            ecCurve = EcCurve::P_256;
            break;
        case NID_secp384r1:
            ecCurve = EcCurve::P_384;
            break;
        case NID_secp521r1:
            ecCurve = EcCurve::P_521;
            break;
        default:
            return ErrorCode::UNSUPPORTED_EC_CURVE;
    }
    return ErrorCode::OK;
}

ErrorCode ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret, std::vector<uint8_t>&
publicKey, EcCurve& ecCurve) {
    ErrorCode errorCode = ErrorCode::INVALID_KEY_BLOB;
    EVP_PKEY *pkey = nullptr;
    const uint8_t *data = pkcs8Blob.data();

    d2i_PrivateKey(EVP_PKEY_EC, &pkey, &data, pkcs8Blob.size());
    if(!pkey) {
        return legacy_enum_conversion(TranslateLastOpenSslError());
    }

    UniquePtr<EC_KEY, EC_KEY_Delete> ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if(!ec_key.get())
        return legacy_enum_conversion(TranslateLastOpenSslError());

    //Get EC Group
    const EC_GROUP *group = EC_KEY_get0_group(ec_key.get());
    if(group == NULL)
        return errorCode;

    if(ErrorCode::OK != (errorCode = getEcCurve(group, ecCurve))) {
        return errorCode;
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

    EVP_PKEY_free(pkey);
    return ErrorCode::OK;
}

ErrorCode rsaRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& privateExp, std::vector<uint8_t>&
pubModulus) {
    ErrorCode errorCode = ErrorCode::INVALID_KEY_BLOB;
    const BIGNUM *n=NULL, *e=NULL, *d=NULL;
    EVP_PKEY *pkey = nullptr;
    const uint8_t *data = pkcs8Blob.data();

    d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &data, pkcs8Blob.size());
    if(!pkey) {
        return legacy_enum_conversion(TranslateLastOpenSslError());
    }

    UniquePtr<RSA, RsaKey::RSA_Delete> rsa_key(EVP_PKEY_get1_RSA(pkey));
    if(!rsa_key.get()) {
        return legacy_enum_conversion(TranslateLastOpenSslError());
    }

    RSA_get0_key(rsa_key.get(), &n, &e, &d);
    if(d != NULL && n != NULL) {
        /*private exponent */
        int privExpLen = BN_num_bytes(d);
        std::unique_ptr<uint8_t[]> privExp(new uint8_t[privExpLen]);
        BN_bn2bin(d, privExp.get());
        /* public modulus */
        int pubModLen = BN_num_bytes(n);
        std::unique_ptr<uint8_t[]> pubMod(new uint8_t[pubModLen]);
        BN_bn2bin(n, pubMod.get());

        privateExp.insert(privateExp.begin(), privExp.get(), privExp.get()+privExpLen);
        pubModulus.insert(pubModulus.begin(), pubMod.get(), pubMod.get()+pubModLen);
    } else {
        return errorCode;
    }
    EVP_PKEY_free(pkey);
    return ErrorCode::OK;
}

ErrorCode getCertificateChain(std::vector<uint8_t>& chainBuffer, std::vector<std::vector<uint8_t>>& certChain) {
    uint8_t *data = chainBuffer.data();
    int index = 0;
    uint32_t length = 0;
    while (index < chainBuffer.size()) {
        std::vector<uint8_t> temp;
        if(data[index] == TAG_SEQUENCE) {
            //read next byte
            if (0 == (data[index+1] & LENGTH_MASK)) {
                length = (uint32_t)data[index];
                //Add SEQ and Length fields
                length += 2;
            } else {
                int additionalBytes = data[index+1] & LENGTH_VALUE_MASK;
                if (additionalBytes == 0x01) {
                    length = data[index+2];
                    //Add SEQ and Length fields
                    length += 3;
                } else if (additionalBytes == 0x02) {
                    length = (data[index+2] << 8 | data[index+3]);
                    //Add SEQ and Length fields
                    length += 4;
                } else if (additionalBytes == 0x04) {
                    length = data[index+2] << 24;
                    length |= data[index+3] << 16;
                    length |= data[index+4] << 8;
                    length |= data[index+5];
                    //Add SEQ and Length fields
                    length += 6;
                } else {
                    //Length is larger than uint32_t max limit.
                    return ErrorCode::UNKNOWN_ERROR;
                }
            }
            temp.insert(temp.end(), (data+index), (data+index+length));
            index += length;

            certChain.push_back(std::move(temp));
        } else {
            //SEQUENCE TAG MISSING.
            return ErrorCode::UNKNOWN_ERROR;
        }
    }
    return ErrorCode::OK;
}


}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
