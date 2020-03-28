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

#ifndef ANDROID_HARDWARE_KEYMASTER_V4_1_OPERATION_H_
#define ANDROID_HARDWARE_KEYMASTER_V4_1_OPERATION_H_

#include <android/hardware/keymaster/4.1/IOperation.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V4_1 {


using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

class Operation : public IOperation {
    public:
    // Methods from ::android::hardware::keymaster::V4_1::IOperation follow.
    ::android::hardware::Return<void> getOperationChallenge(getOperationChallenge_cb _hidl_cb) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

};

} // namespace V4_1
} // namespace keymaster
}  // namespace hardware
}  // namespace android

#endif /* ANDROID_HARDWARE_KEYMASTER_V4_1_OPERATION_H_ */
