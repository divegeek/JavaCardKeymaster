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


#ifndef KEYMASTER_V4_1_JAVACARD_PROVISION_H_
#define KEYMASTER_V4_1_JAVACARD_PROVISION_H_

#include "TransportFactory.h"

namespace keymaster {
namespace V4_1 {
namespace javacard {

typedef struct SystemProperties__ {
	uint32_t osVersion;
	uint32_t osPatchLevel;
	uint32_t vendorPatchLevel;
} SystemProperties;

typedef struct BootParams_ {
	uint32_t bootPatchLevel;
	std::vector<uint8_t> verifiedBootKey;
	std::vector<uint8_t> verifiedBootKeyHash;
	uint32_t verifiedBootState;
	uint32_t deviceLocked;
} BootParams;

typedef struct AttestIDParams_ {
	std::string brand;
	std::string device;
	std::string product;
	std::string serial;
	std::string imei;
	std::string meid;
	std::string manufacturer;
	std::string model;
} AttestIDParams;

class Provision {
public:
    /**
     * Initalizes the transport layer.
     */
	ErrorCode init();
    /**
     * Provision the Attestation key.
     */
	ErrorCode provisionAttestationKey(std::vector<uint8_t>& batchKey);
    /**
     * Provision the Attestation certificate chain.
     */
	ErrorCode provisionAtestationCertificateChain(std::vector<std::vector<uint8_t>>& CertChain);
    /**
     * Provision the Attestation certificate paramters.
     */
	ErrorCode provisionAttestationCertificateParams(std::vector<uint8_t>& batchCertificate);
    /**
     * Provision the Attestation ID.
     */
	ErrorCode provisionAttestationID(AttestIDParams& attestParams);
    /**
     * Provision the pre-shared secret.
     */
	ErrorCode provisionPreSharedSecret(std::vector<uint8_t>& preSharedSecret);
    /**
     * Provision the boot parameters.
     */
	ErrorCode provisionBootParameters(BootParams& bootParams );
    /**
     * Set system properties.
     */
	ErrorCode setAndroidSystemProperties();

    /**
     * Locks the provision. After this no more provision commanands are allowed.
     */
    ErrorCode lockProvision();
    /**
     * Get the provision status.
     */
    ErrorCode getProvisionStatus(uint64_t&);
    /**
     * Uninitialize the transport layer.
     */
    ErrorCode uninit();

private:
    std::unique_ptr<se_transport::TransportFactory> pTransportFactory;
};

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
#endif //KEYMASTER_V4_1_JAVACARD_PROVISION_H_
