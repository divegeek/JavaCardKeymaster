/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <cppcose/cppcose.h>

#include <iostream>
#include <stdio.h>

#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <constants.h>
#include <openssl/ecdsa.h>

namespace cppcose {

ErrMsgOr<bytevec> ecdsaDerSignatureToCose(const bytevec& ecdsaSignature) {
    const unsigned char* p = ecdsaSignature.data();
    ECDSA_SIG *sig = d2i_ECDSA_SIG(nullptr, &p, ecdsaSignature.size());
    if (sig == nullptr) {
        return "Error decoding DER signature";
    }

    bytevec ecdsaCoseSignature(64, 0);
    if (BN_bn2binpad(ECDSA_SIG_get0_r(sig), ecdsaCoseSignature.data(), 32) != 32) {
        ECDSA_SIG_free(sig);
        return "Error encoding r";
    }
    if (BN_bn2binpad(ECDSA_SIG_get0_s(sig), ecdsaCoseSignature.data() + 32, 32) != 32) {
        ECDSA_SIG_free(sig);
        return "Error encoding s";
    }
    ECDSA_SIG_free(sig);
    return ecdsaCoseSignature;
}

ErrMsgOr<bytevec> ECDSA_sign(const bytevec& key, bytevec& input) {
    EVP_PKEY_CTX* pkeyCtx = NULL;
    EVP_MD_CTX_Ptr digestCtx(EVP_MD_CTX_new());
    auto bn = BIGNUM_Ptr(BN_bin2bn(key.data(), key.size(), nullptr));
    if (bn.get() == nullptr) {
        return "Error creating BIGNUM for private key";
    }
    auto privEcKey = EC_KEY_Ptr(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (EC_KEY_set_private_key(privEcKey.get(), bn.get()) != 1) {
        return "Error setting private key from BIGNUM";
    }
    auto privPkey = EVP_PKEY_Ptr(EVP_PKEY_new());
    if (EVP_PKEY_set1_EC_KEY(privPkey.get(), privEcKey.get()) != 1) {
        return "Error setting private key";
    }

    if (EVP_DigestSignInit(digestCtx.get(), &pkeyCtx, EVP_sha256(), nullptr /* engine */, privPkey.get()) !=
        1) {
        return "Failed to do digest sign init.";
    }
    size_t outlen = EVP_PKEY_size(privPkey.get());
    bytevec signature(outlen);
    if (!EVP_DigestSign(digestCtx.get(), signature.data(), &outlen, input.data(), input.size())) {
        return "Ecdsa sign failed.";
    }
    return signature;
}

bool ECDSA_verify(const bytevec& input, const bytevec& signature, const bytevec& key) {
    EVP_PKEY_CTX* pkeyCtx = NULL;
    EVP_MD_CTX_Ptr digestCtx(EVP_MD_CTX_new());
    auto ecGroup = EC_GROUP_Ptr(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    auto ecKey = EC_KEY_Ptr(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (ecGroup.get() == nullptr) {
        return "Failed to get EC_GROUP from curve name";
    }
    auto ecPoint = EC_POINT_Ptr(EC_POINT_new(ecGroup.get()));
    if (ecPoint.get() == nullptr) {
        return "Failed to get EC_POINT from EC_GROUP";
    }
    if (EC_POINT_oct2point(ecGroup.get(), ecPoint.get(), key.data(), key.size(), nullptr) !=
        1) {
        return 0;
    }
    // set public key
    if (EC_KEY_set_public_key(ecKey.get(), ecPoint.get()) != 1) {
        return 0;
    }
    auto pkey = EVP_PKEY_Ptr(EVP_PKEY_new());
    if (EVP_PKEY_set1_EC_KEY(pkey.get(), ecKey.get()) != 1) {
        return 0;
    }
    if (EVP_DigestVerifyInit(digestCtx.get(), &pkeyCtx, EVP_sha256(), nullptr /* engine */, pkey.get()) !=
        1) {
        return 0;
    }
    return EVP_DigestVerify(digestCtx.get(), signature.data(), signature.size(), input.data(), input.size());
}

ErrMsgOr<bytevec> getEcPointFromAffineCoordinates(const bytevec& pubx, const bytevec& puby) {
    auto ecGroup = EC_GROUP_Ptr(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (ecGroup.get() == nullptr) {
        return "Failed to get EC_GROUP from curve name";
    }
    auto ecPoint = EC_POINT_Ptr(EC_POINT_new(ecGroup.get()));
    if (ecPoint.get() == nullptr) {
        return "Failed to get EC_POINT from EC_GROUP";
    }
    auto bn_x = BIGNUM_Ptr(BN_bin2bn(pubx.data(), pubx.size(), nullptr));
    if (bn_x.get() == nullptr) {
        return "Error creating BIGNUM for peer public key X coordinate";
    }
    auto bn_y = BIGNUM_Ptr(BN_bin2bn(puby.data(), puby.size(), nullptr));
    if (bn_y.get() == nullptr) {
        return "Error creating BIGNUM for peer public key Y coordinate";
    }
    if (!EC_POINT_set_affine_coordinates(ecGroup.get(), ecPoint.get(), bn_x.get(), bn_y.get(),
                                         nullptr)) {
        return "Failed to set affine coordinates";
    }
    size_t pubKeyLen;
    pubKeyLen = EC_POINT_point2oct(ecGroup.get(), ecPoint.get(), POINT_CONVERSION_UNCOMPRESSED,
                                   nullptr, 0, nullptr);
    if (pubKeyLen == 0) {
        return "Failed to convert EC_POINT to buffer.";
    }
    bytevec pubkey(pubKeyLen);
    EC_POINT_point2oct(ecGroup.get(), ecPoint.get(), POINT_CONVERSION_UNCOMPRESSED, pubkey.data(),
                       pubKeyLen, nullptr);
    return pubkey;
}

ErrMsgOr<bytevec> createCoseSign1Signature(const bytevec& key, const bytevec& protectedParams,
        const bytevec& payload, const bytevec& aad) {
    bytevec signatureInput = cppbor::Array()
        .add("Signature1")  //
        .add(protectedParams)
        .add(aad)
        .add(payload)
        .encode();
    auto signature = ECDSA_sign(key, signatureInput);
    if (!signature) return "Signing failed";
    return ecdsaDerSignatureToCose(*signature);
}

ErrMsgOr<cppbor::Array> constructCoseSign1(const bytevec& key, cppbor::Map protectedParams,
                                           const bytevec& payload, const bytevec& aad) {
    bytevec protParms = protectedParams.add(ALGORITHM, ES256).canonicalize().encode();
    auto signature = createCoseSign1Signature(key, protParms, payload, aad);
    if (!signature) return signature.moveMessage();

    return cppbor::Array()
        .add(std::move(protParms))
        .add(cppbor::Map() /* unprotected parameters */)
        .add(std::move(payload))
        .add(std::move(*signature));
}

ErrMsgOr<cppbor::Array> constructCoseSign1(const bytevec& key, const bytevec& payload,
                                           const bytevec& aad) {
    return constructCoseSign1(key, {} /* protectedParams */, payload, aad);
}

ErrMsgOr<bytevec> verifyAndParseCoseSign1(bool ignoreSignature, const cppbor::Array* coseSign1,
                                          const bytevec& signingCoseKey, const bytevec& aad) {
    if (!coseSign1 || coseSign1->size() != kCoseSign1EntryCount) {
        return "Invalid COSE_Sign1";
    }

    const cppbor::Bstr* protectedParams = coseSign1->get(kCoseSign1ProtectedParams)->asBstr();
    const cppbor::Map* unprotectedParams = coseSign1->get(kCoseSign1UnprotectedParams)->asMap();
    const cppbor::Bstr* payload = coseSign1->get(kCoseSign1Payload)->asBstr();

    if (!protectedParams || !unprotectedParams || !payload) {
        return "Missing input parameters";
    }

    auto [parsedProtParams, _, errMsg] = cppbor::parse(protectedParams);
    if (!parsedProtParams) {
        return errMsg + " when parsing protected params.";
    }
    if (!parsedProtParams->asMap()) {
        return "Protected params must be a map";
    }

    auto& algorithm = parsedProtParams->asMap()->get(ALGORITHM);
    if (!algorithm || !algorithm->asInt() || algorithm->asInt()->value() != EDDSA) {
        return "Unsupported signature algorithm";
    }

	if (!ignoreSignature) {
		const cppbor::Bstr* signature = coseSign1->get(kCoseSign1Signature)->asBstr();
		if (!signature || signature->value().empty()) {
			return "Missing signature input";
		}

		bool selfSigned = signingCoseKey.empty();

		bytevec signatureInput =
			cppbor::Array().add("Signature1").add(*protectedParams).add(aad).add(*payload).encode();

		auto key =
			CoseKey::parseP256(selfSigned ? payload->value() : signingCoseKey);
		if (!key) return "Bad signing key: " + key.moveMessage();


		auto pubkey = getEcPointFromAffineCoordinates(
				*key->getBstrValue(CoseKey::PUBKEY_X), *key->getBstrValue(CoseKey::PUBKEY_Y));
		if (!pubkey) return pubkey.moveMessage();

		if (!ECDSA_verify(signatureInput, signature->value(), *pubkey)) {
			return "Signature verification failed";
		}
	}

    return payload->value();
}
}  // namespace cppcose
