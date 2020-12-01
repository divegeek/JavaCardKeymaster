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

/**
 * Provisions the SE.
 */
ErrorCode provision(std::unique_ptr<se_transport::TransportFactory>& transport);

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
#endif //KEYMASTER_V4_1_JAVACARD_PROVISION_H_
