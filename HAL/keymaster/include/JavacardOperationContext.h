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

#ifndef KEYMASTER_V4_1_JAVACARD_OPERATIONCONTEXT_H_
#define KEYMASTER_V4_1_JAVACARD_OPERATIONCONTEXT_H_

#include <iostream>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>

#define MAX_BUF_SIZE 32

namespace keymaster {
namespace V4_1 {
namespace javacard {

using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::Algorithm;
using ::android::hardware::keymaster::V4_0::KeyPurpose;
using ::android::hardware::keymaster::V4_0::Digest;
using ::android::hardware::keymaster::V4_0::PaddingMode;

using sendDataToSE_cb = std::function<ErrorCode(std::vector<uint8_t>& data)>;

enum class Operation;

struct BufferedData {
    uint8_t buf[MAX_BUF_SIZE];
    int buf_len;
};

struct OperationInfo {
    Algorithm alg;
    KeyPurpose purpose;
    Digest digest;
    PaddingMode pad;
};

struct OperationData {
    OperationInfo info;
    BufferedData data;
};

class OperationContext {

public:
    OperationContext(){}
    ~OperationContext() {}
    ErrorCode setOperationInfo(uint64_t operationHandle, OperationInfo& oeprInfo);
    ErrorCode getOperationInfo(uint64_t operHandle, OperationInfo& operInfo);
    ErrorCode clearOperationData(uint64_t operationHandle);
    ErrorCode update(uint64_t operHandle, std::vector<uint8_t>& input, sendDataToSE_cb cb);
    ErrorCode finish(uint64_t operHandle, std::vector<uint8_t>& input, sendDataToSE_cb cb);

private:
    std::map<uint64_t, OperationData> operationTable;

    inline ErrorCode getOperationData(uint64_t operHandle, OperationData& oprData) {
        auto itr = operationTable.find(operHandle);
        if(itr != operationTable.end()) {
            oprData = itr->second;
            return ErrorCode::OK;
        }
        return ErrorCode::INVALID_OPERATION_HANDLE;
    }

    ErrorCode validateInputData(uint64_t operHandle, Operation opr, std::vector<uint8_t>& actualInput,
    std::vector<uint8_t>& input);
    ErrorCode internalUpdate(uint64_t operHandle, uint8_t* input, size_t input_len, Operation opr, std::vector<uint8_t>&
    out);
    inline ErrorCode handleInternalUpdate(uint64_t operHandle, uint8_t* data, size_t len, Operation opr,
            sendDataToSE_cb cb) {
        ErrorCode errorCode = ErrorCode::OK;
        std::vector<uint8_t> out;
        OperationData oprData;

        if(ErrorCode::OK != (errorCode = getOperationData(operHandle, oprData))) {
            return errorCode;
        }

        if(Algorithm::AES == oprData.info.alg || Algorithm::TRIPLE_DES == oprData.info.alg) {
            if(ErrorCode::OK != (errorCode = internalUpdate(operHandle, data, len,
                            opr, out))) {
                return errorCode;
            }
        } else {
            /* Other algorithms no buffering required */
            for(int i = 0; i < len; i++) {
                out.push_back(data[i]);
            }
        }
        if(ErrorCode::OK != (errorCode = cb(out))) {
            return errorCode;
        }
        return errorCode;
    }
};

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster

#endif  // KEYMASTER_V4_1_JAVACARD_OPERATIONCONTEXT_H_
