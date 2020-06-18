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

#define MAX_BUF_SIZE 256

namespace keymaster {
namespace V4_1 {
namespace javacard {

using ::android::hardware::hidl_vec;
using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::Algorithm;
using ::android::hardware::keymaster::V4_0::KeyPurpose;
using ::android::hardware::keymaster::V4_0::Digest;
using ::android::hardware::keymaster::V4_0::PaddingMode;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::Tag;

using sendDataToSE_cb = std::function<ErrorCode(std::vector<uint8_t>& data, bool finish)>;

enum class Operation;

struct BufferedData {
    uint8_t buf[MAX_BUF_SIZE];
    size_t buf_len;
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
    ErrorCode setOperationInfo(uint64_t operationHandle, KeyPurpose purpose, const hidl_vec<KeyParameter>& params);
    ErrorCode getOperationInfo(uint64_t operHandle, OperationInfo& operInfo);
    ErrorCode clearOperationData(uint64_t operationHandle);
    ErrorCode update(uint64_t operHandle, const std::vector<uint8_t>& input, sendDataToSE_cb cb);
    ErrorCode finish(uint64_t operHandle, const std::vector<uint8_t>& input, sendDataToSE_cb cb);

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

    ErrorCode validateInputData(uint64_t operHandle, Operation opr, const std::vector<uint8_t>& actualInput,
    std::vector<uint8_t>& input);
    ErrorCode internalUpdate(uint64_t operHandle, uint8_t* input, size_t input_len, Operation opr, std::vector<uint8_t>&
    out);
     ErrorCode handleInternalUpdate(uint64_t operHandle, uint8_t* data, size_t len, Operation opr,
             sendDataToSE_cb cb, bool finish=false) {
         ErrorCode errorCode = ErrorCode::OK;
         std::vector<uint8_t> out;

         if(Algorithm::AES == operationTable[operHandle].info.alg ||
                 Algorithm::TRIPLE_DES == operationTable[operHandle].info.alg) {
             if(ErrorCode::OK != (errorCode = internalUpdate(operHandle, data, len,
                             opr, out))) {
                 return errorCode;
             }

             if(ErrorCode::OK != (errorCode = cb(out, finish))) {
                 return errorCode;
             }
         } else {
             /* Asymmetric */
             if(operationTable[operHandle].info.purpose == KeyPurpose::DECRYPT ||
                 operationTable[operHandle].info.digest == Digest::NONE) {
                 /* In case of Decrypt, sign with no digest cases buffer the data in
                  * update call and send data to SE in finish call.
                  */
                 if(finish) {
                     for(size_t i = 0; i < operationTable[operHandle].data.buf_len; ++i) {
                         out.push_back(operationTable[operHandle].data.buf[i]);
                     }
                     if(ErrorCode::OK != (errorCode = cb(out, finish))) {
                         return errorCode;
                     }
                 } else {
                      //Input message length should not be more than the MAX_BUF_SIZE.
                     if(operationTable[operHandle].data.buf_len <= MAX_BUF_SIZE) {
                         size_t bufIndex = operationTable[operHandle].data.buf_len;
                         size_t pos = 0;
                         for(; (pos < len) && (pos < (MAX_BUF_SIZE-bufIndex)); pos++)
                         {
                             operationTable[operHandle].data.buf[bufIndex+pos] = data[pos];
                         }
                         operationTable[operHandle].data.buf_len += pos;
                     }
                 }
             } else {
                 for(size_t j=0; j < len; ++j)
                 {
                     out.push_back(data[j]);
                 }
                 /* if len=0, then no need to call the callback, since there is no information to be send to javacard,
                  * but if finish flag is true irrespective of length the callback should be called.
                  */
                 if(len != 0 || finish) {
                     if(ErrorCode::OK != (errorCode = cb(out, finish))) {
                         return errorCode;
                     }
                 }
             }
         }
         return errorCode;
     }
};

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster

#endif  // KEYMASTER_V4_1_JAVACARD_OPERATIONCONTEXT_H_
