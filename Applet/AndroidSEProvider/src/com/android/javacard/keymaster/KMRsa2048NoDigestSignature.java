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

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class KMRsa2048NoDigestSignature extends Signature {

  public static final byte ALG_RSA_SIGN_NOPAD = (byte) 0x65;
  public static final byte ALG_RSA_PKCS1_NODIGEST = (byte) 0x66;
  private byte algorithm;
  private Cipher inst;

  public KMRsa2048NoDigestSignature(byte alg) {
    algorithm = alg;
    inst = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
  }

  @Override
  public void init(Key key, byte b) throws CryptoException {
    inst.init(key, b);
  }

  @Override
  public void init(Key key, byte b, byte[] bytes, short i, short i1)
      throws CryptoException {
    inst.init(key, b, bytes, i, i1);
  }

  @Override
  public void setInitialDigest(byte[] bytes, short i, short i1, byte[] bytes1,
      short i2, short i3) throws CryptoException {
  }

  @Override
  public byte getAlgorithm() {
    return algorithm;
  }

  @Override
  public byte getMessageDigestAlgorithm() {
    return MessageDigest.ALG_NULL;
  }

  @Override
  public byte getCipherAlgorithm() {
    return algorithm;
  }

  @Override
  public byte getPaddingAlgorithm() {
    return Cipher.PAD_NULL;
  }

  @Override
  public short getLength() throws CryptoException {
    return 0;
  }

  @Override
  public void update(byte[] bytes, short i, short i1) throws CryptoException {
    // HAL accumulates the data and send it at finish operation.
  }

  @Override
  public short sign(byte[] bytes, short i, short i1, byte[] bytes1, short i2)
      throws CryptoException {
    padData(bytes, i, i1, KMAndroidSEProvider.getInstance().tmpArray, (short) 0);
    return inst.doFinal(KMAndroidSEProvider.getInstance().tmpArray, (short) 0,
        (short) 256, bytes1, i2);
  }

  @Override
  public short signPreComputedHash(byte[] bytes, short i, short i1,
      byte[] bytes1, short i2) throws CryptoException {
    return 0;
  }

  @Override
  public boolean verify(byte[] bytes, short i, short i1, byte[] bytes1,
      short i2, short i3) throws CryptoException {
    //Verification is handled inside HAL
    return false;
  }

  @Override
  public boolean verifyPreComputedHash(byte[] bytes, short i, short i1,
      byte[] bytes1, short i2, short i3) throws CryptoException {
    //Verification is handled inside HAL
    return false;
  }

  private void padData(byte[] buf, short start, short len, byte[] outBuf,
      short outBufStart) {
    if (!isValidData(buf, start, len)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    Util.arrayFillNonAtomic(outBuf, (short) outBufStart, (short) 256,
        (byte) 0x00);
    if (algorithm == ALG_RSA_SIGN_NOPAD) { // add zero to right
    } else if (algorithm == ALG_RSA_PKCS1_NODIGEST) {// 0x00||0x01||PS||0x00
      outBuf[0] = 0x00;
      outBuf[1] = 0x01;
      Util.arrayFillNonAtomic(outBuf, (short) 2, (short) (256 - len - 3),
          (byte) 0xFF);
      outBuf[(short) (256 - len - 1)] = 0x00;
    } else {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }
    Util.arrayCopyNonAtomic(buf, start, outBuf, (short) (256 - len), len);
  }

  private boolean isValidData(byte[] buf, short start, short len) {
    if (algorithm == ALG_RSA_SIGN_NOPAD) {
      if (len > 256) {
        return false;
      }
    } else { // ALG_RSA_PKCS1_NODIGEST
      if (len > 245) {
        return false;
      }
    }
    return true;
  }
}
