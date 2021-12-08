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
using ::android::hardware::keymaster::V4_0::BlockMode;
using ::android::hardware::keymaster::V4_0::Tag;

/**
 * Callback function to send data back to the caller.
 */
using sendDataToSE_cb = std::function<ErrorCode(std::vector<uint8_t>& data, bool finish)>;

enum class Operation;

/**
 * This struct is used to store the buffered data.
 */
struct BufferedData {
    uint8_t buf[MAX_BUF_SIZE];
    size_t buf_len;
};

/**
 * This struct is used to store the operation info.
 */
struct OperationInfo {
    Algorithm alg;
    KeyPurpose purpose;
    Digest digest;
    PaddingMode pad;
    BlockMode mode;
};

/**
 * OperationContext uses this struct to store the buffered data and the correspoding operation info.
 */
struct OperationData {
    OperationInfo info;
    BufferedData data;
};

/**
 * This class manages the data that is send for any crypto operation.
 *
 * For Symmetric operations, update function sends only block aligned data and stores the remaining data in the buffer
 * so at any point the buffer may contain data ranging from 0 to a maximum of block size, where as finish function sends
 * all the data (input data + buffered data) to the caller and clears the buffer. To support PKCS#7 padding removal,
 * the last block size from the input is always buffered in update operation and this last block is sent in finish
 * operation.
 *
 * For Asymmetric operations, if the operation is with Digest then the input data is not buffered, where as if the
 * operation is with no Digest then update function buffers the input data and finish function extracts the data from
 * buffer and sends to the caller. Update and finish functions does validation on the input data based on the algorithm.
 *
 * In General, the maximum allowed input data that is sent is limited to MAX_ALLOWED_INPUT_SIZE. If the input data
 * exceeds this limit each update or finish function divides the input data into chunks of MAX_ALLOWED_INPUT_SIZE and
 * sends each chunk back to the caller through update callback.
 */
class OperationContext {

public:
    OperationContext(){}
    ~OperationContext() {}
    /**
     * In Begin operation caller has to call this function to store the operation data corresponding to the operation
     * handle.
     */
    ErrorCode setOperationInfo(uint64_t operationHandle, KeyPurpose purpose, Algorithm alg, const hidl_vec<KeyParameter>& params);
    /**
     * This function clears the operation data from the map. Caller has to call this function once the operation is done
     * or if there is any error while processing the operation.
     */
    ErrorCode clearOperationData(uint64_t operationHandle);
    /**
     * This function validaes the input data based on the algorithm and does process on the data to either store it or
     * send back to the caller. The data is sent using sendDataTOSE_cb callback.
     */
    ErrorCode update(uint64_t operHandle, const std::vector<uint8_t>& input, sendDataToSE_cb cb);
    /**
     * This function validaes the input data based on the algorithm and send all the input data along with buffered data
     * to the caller. The data is sent using sendDataTOSE_cb callback.
     */
    ErrorCode finish(uint64_t operHandle, const std::vector<uint8_t>& input, sendDataToSE_cb cb);

private:
    /**
     * This is used to store the operation related info and the buffered data. Key is the operation handle and the value
     * is OperationData.
     */
    std::map<uint64_t, OperationData> operationTable;

    /* Helper functions */

    /**
     * This fucntion validates the input data based on the algorithm and the operation info parameters. This function
     * also does a processing on the input data if either the algorithm is EC or if it is a Finish operation. For EC
     * operations it truncates the input data if it exceeds 32 bytes for No Digest case. In case of finish operations
     * this function combines both the buffered data and input data if both exceeds MAX_ALLOWED_INPUT_SIZE.
     */
    ErrorCode validateInputData(uint64_t operHandle, Operation opr, const std::vector<uint8_t>& actualInput,
            std::vector<uint8_t>& input);
    /**
     * This function is used for Symmetric operations. It extracts the block sized data from the input and buffers the
     * reamining data for update calls only. For finish calls it extracts all the buffered data combines it with
     * input data.
     */
    ErrorCode getBlockAlignedData(uint64_t operHandle, uint8_t* input, size_t input_len, Operation opr, std::vector<uint8_t>&
            out);
    /**
     * This function sends the data back to the caller using callback functions. It does some processing on input data
     * for Asymmetic operations.
     */
    ErrorCode handleInternalUpdate(uint64_t operHandle, uint8_t* data, size_t len, Operation opr,
        sendDataToSE_cb cb, bool finish=false);

};

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster

#endif  // KEYMASTER_V4_1_JAVACARD_OPERATIONCONTEXT_H_
