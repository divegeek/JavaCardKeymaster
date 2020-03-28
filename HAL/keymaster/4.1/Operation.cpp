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


#include <Operation.h>
#define UNUSED(a) a=a

namespace android {
namespace hardware {
namespace keymaster {
namespace V4_1 {

// Methods from ::android::hardware::keymaster::V4_1::IOperation follow.
::android::hardware::Return<void> Operation::getOperationChallenge(getOperationChallenge_cb _hidl_cb) {
    // TODO implement
    UNUSED(_hidl_cb);
    return Void();
}


} // namespace V4_1
} // namespace keymaster
}  // namespace hardware
}  // namespace android
