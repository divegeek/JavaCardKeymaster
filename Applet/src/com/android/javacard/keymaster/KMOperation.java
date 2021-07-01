/*
 * Copyright(C) 2020 The Android Open Source Project
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
package com.android.javacard.keymaster;

/**
 * KMOperation represents a persistent operation started by keymaster hal's beginOperation function.
 * This operation is persistent i.e. it will be stored in non volatile memory of se card. It will be
 * returned back to KMSEProvider for the reuse when the operation is finished.
 */
public interface KMOperation {

  // Used for cipher operations
  short update(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart);

  // Used for signature operations
  short update(byte[] inputDataBuf, short inputDataStart, short inputDataLength);

  // Used for finishing cipher operations.
  short finish(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart);

  // Used for finishing signing operations.
  short sign(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] signBuf, short signStart);

  // Used for finishing verifying operations.
  boolean verify(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] signBuf, short signStart, short signLength);

  // Used for aborting the ongoing operations.
  void abort();

  // Used for AES GCM cipher operation.
  void updateAAD(byte[] dataBuf, short dataStart, short dataLength);

  // Used for getting output size before finishing a AES GCM cipher operation. For encryption this will
  // include the auth tag which is appended at the end of the encrypted data. For decryption this will be
  // size of the decrypted data only.
  short getAESGCMOutputSize(short dataSize, short macLength);
}
