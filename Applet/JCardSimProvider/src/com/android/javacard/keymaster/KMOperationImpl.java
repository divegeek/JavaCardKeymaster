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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import javacard.security.Signature;

public class KMOperationImpl implements KMOperation {

  private KMCipher cipher;
  private Signature signature;

  public KMOperationImpl(KMCipher cipher) {
    this.cipher = cipher;
    this.signature = null;
  }

  public KMOperationImpl(Signature sign) {
    this.cipher = null;
    this.signature = sign;
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    return cipher
        .update(inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart, short inputDataLength) {
    signature.update(inputDataBuf, inputDataStart, inputDataLength);
    return 0;
  }

  @Override
  public short finish(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    return cipher
        .doFinal(inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public short sign(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] signBuf, short signStart) {
    return signature.sign(inputDataBuf, inputDataStart, inputDataLength, signBuf, signStart);
  }

  @Override
  public boolean verify(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] signBuf, short signStart, short signLength) {
    return signature
        .verify(inputDataBuf, inputDataStart, inputDataLength, signBuf, signStart, signLength);
  }

  @Override
  public void abort() {
    // do nothing
  }

  @Override
  public void updateAAD(byte[] dataBuf, short dataStart, short dataLength) {
    cipher.updateAAD(dataBuf, dataStart, dataLength);
  }

  @Override
  public short getAESGCMOutputSize(short dataSize, short macLength) {
    return cipher.getAesGcmOutputSize(dataSize, macLength);
  }
}
