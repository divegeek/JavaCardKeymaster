/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/nid.h>
#include <memory>
#include <keymaster/km_openssl/asymmetric_key.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/ec_key_factory.h>
#include <keymaster/km_openssl/rsa_key_factory.h>
#include <JavacardSoftKeymasterContext.h>
#include <CborConverter.h>
#include <CommonUtils.h>
#include <keymaster/km_version.h>


using std::unique_ptr;
using ::keymaster::V4_1::javacard::KmParamSet;

namespace keymaster {

JavaCardSoftKeymasterContext::JavaCardSoftKeymasterContext(keymaster_security_level_t security_level)
    : PureSoftKeymasterContext(KmVersion::KEYMASTER_4_1, security_level) {}

JavaCardSoftKeymasterContext::~JavaCardSoftKeymasterContext() {}

EVP_PKEY* RSA_fromMaterial(const uint8_t* modulus, size_t mod_size) {
    BIGNUM *n = BN_bin2bn(modulus, mod_size, NULL);
    BIGNUM *e = BN_new();//bignum_decode(exp, 5);
    char exp[] = "65537";
    BN_dec2bn(&e, exp);

   if (!n || !e)
    return NULL;

   if (e && n) {
       EVP_PKEY* pRsaKey = EVP_PKEY_new();
       RSA* rsa = RSA_new();
       rsa->e = e;
       rsa->n = n;
       EVP_PKEY_assign_RSA(pRsaKey, rsa);
       return pRsaKey;
   } else {
       if (n) BN_free(n);
       if (e) BN_free(e);
       return NULL;
   }
}

EC_GROUP* ChooseGroup(keymaster_ec_curve_t ec_curve) {
    switch (ec_curve) {
    case KM_EC_CURVE_P_224:
        return EC_GROUP_new_by_curve_name(NID_secp224r1);
        break;
    case KM_EC_CURVE_P_256:
        return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        break;
    case KM_EC_CURVE_P_384:
        return EC_GROUP_new_by_curve_name(NID_secp384r1);
        break;
    case KM_EC_CURVE_P_521:
        return EC_GROUP_new_by_curve_name(NID_secp521r1);
        break;
    default:
        return nullptr;
        break;
    }
}

EVP_PKEY* EC_fromMaterial(const uint8_t* pub_key, size_t key_size, keymaster_ec_curve_t ec_curve) {
    
    EC_GROUP *ec_group = ChooseGroup(ec_curve);
    EC_POINT *p = EC_POINT_new(ec_group);
    EC_KEY *ec_key = EC_KEY_new();
    EVP_PKEY *pEcKey = EVP_PKEY_new();

    if((EC_KEY_set_group(ec_key, ec_group) != 1) || (EC_POINT_oct2point(ec_group, p, pub_key, key_size, NULL) != 1)
        || (EC_KEY_set_public_key(ec_key, p) != 1) || (EVP_PKEY_set1_EC_KEY(pEcKey, ec_key) != 1)) {
        return NULL;
    }

    return pEcKey;
}

keymaster_error_t JavaCardSoftKeymasterContext::LoadKey(const keymaster_algorithm_t algorithm, KeymasterKeyBlob&& key_material,
                                                AuthorizationSet&& hw_enforced,
                                                AuthorizationSet&& sw_enforced,
                                                UniquePtr<Key>* key) const {
    auto factory = (AsymmetricKeyFactory*)GetKeyFactory(algorithm);
    UniquePtr<AsymmetricKey> asym_key;
    keymaster_error_t error = KM_ERROR_OK;
    const uint8_t* tmp = key_material.key_material;
    const size_t temp_size = key_material.key_material_size;
    EVP_PKEY* pkey = NULL;

    if(algorithm == KM_ALGORITHM_RSA) {
        pkey = RSA_fromMaterial(tmp, temp_size);
    } else if(algorithm == KM_ALGORITHM_EC) {
        keymaster_ec_curve_t ec_curve;
        uint32_t keySize;
        if (!hw_enforced.GetTagValue(TAG_EC_CURVE, &ec_curve) &&
            !sw_enforced.GetTagValue(TAG_EC_CURVE, &ec_curve)) {
            if(!hw_enforced.GetTagValue(TAG_KEY_SIZE, &keySize) &&
                !sw_enforced.GetTagValue(TAG_KEY_SIZE, &keySize)) {
                return KM_ERROR_INVALID_ARGUMENT;
            }
            error = EcKeySizeToCurve(keySize, &ec_curve);
            if(error != KM_ERROR_OK)
                return error;
        }
        pkey = EC_fromMaterial(tmp, temp_size, ec_curve);
    }
    if (!pkey)
        return TranslateLastOpenSslError();
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey_deleter(pkey);

    error = factory->CreateEmptyKey(move(hw_enforced), move(sw_enforced), &asym_key);
    if (error != KM_ERROR_OK)
        return error;

    asym_key->key_material() = move(key_material);
    if (!asym_key->EvpToInternal(pkey))
        error = TranslateLastOpenSslError();
    else
        key->reset(asym_key.release());

    return error;
}

keymaster_error_t JavaCardSoftKeymasterContext::ParseKeyBlob(const KeymasterKeyBlob& blob,
                                                         const AuthorizationSet& /*additional_params*/,
                                                         UniquePtr<Key>* key) const {

    // The JavaCardSoftKeymasterContext handle a key blob generated by JavaCard keymaster for public key operations.
    //
    // 1.  A JavaCard keymaster key blob is a CborEncoded data of Secret, Nonce, AuthTag, KeyCharectristics and Public key.
    //     Here in public key operation we need only KeyCharectristics and Public key.
    //     Once these values extracted Public key is created based on parameters and returned.
    //

    AuthorizationSet hw_enforced;
    AuthorizationSet sw_enforced;
    KeymasterKeyBlob key_material;
    keymaster_error_t error = KM_ERROR_OK;

    auto constructKey = [&, this] () mutable -> keymaster_error_t {
        keymaster_algorithm_t algorithm;
        if(error != KM_ERROR_OK) {
            return error;
        }
        if (!hw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm) &&
            !sw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm)) {
            return KM_ERROR_INVALID_ARGUMENT;
        }

        if (algorithm != KM_ALGORITHM_RSA && algorithm != KM_ALGORITHM_EC) {
            return KM_ERROR_INCOMPATIBLE_ALGORITHM;
        }
        error = LoadKey(algorithm, move(key_material), move(hw_enforced),
                                move(sw_enforced), key);
        return error;
    };

    CborConverter cc;
    std::unique_ptr<Item> item;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> cborKey(blob.key_material_size);

    for(size_t i = 0; i < blob.key_material_size; i++) {
        cborKey[i] = blob.key_material[i];
    }
    std::tie(item, errorCode) = cc.decodeData(cborKey, false);
    if (item != nullptr) {
        std::vector<uint8_t> temp(0);
        if(cc.getBinaryArray(item, 4, temp)) {
            key_material = {temp.data(), temp.size()};
            temp.clear();
        }
        KeyCharacteristics keyCharacteristics;
        cc.getKeyCharacteristics(item, 3, keyCharacteristics);

        sw_enforced.Reinitialize(KmParamSet(keyCharacteristics.softwareEnforced));
        hw_enforced.Reinitialize(KmParamSet(keyCharacteristics.hardwareEnforced));
    } else {
        error =  KM_ERROR_INVALID_KEY_BLOB;
    }
    return constructKey();
}
}  // namespace keymaster
