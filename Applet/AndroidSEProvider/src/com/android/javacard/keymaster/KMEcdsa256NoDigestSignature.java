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

import javacard.security.CryptoException;
import javacard.framework.Util;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class KMEcdsa256NoDigestSignature extends Signature {

  public static final byte ALG_ECDSA_NODIGEST = (byte) 0x67;
  public static final short MAX_NO_DIGEST_MSG_LEN = 32;
  private byte algorithm;
  private Signature inst;

  public KMEcdsa256NoDigestSignature(byte alg) {
    algorithm = alg;
    inst = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
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
    return 0;
  }

  @Override
  public byte getPaddingAlgorithm() {
    return Cipher.PAD_NULL;
  }

  @Override
  public short getLength() throws CryptoException {
    return inst.getLength();
  }

  @Override
  public void update(byte[] message, short msgStart, short messageLength)
      throws CryptoException {
    // HAL accumulates the data and send it at finish operation.
  }

  @Override
  public short sign(byte[] bytes, short i, short i1, byte[] bytes1, short i2)
      throws CryptoException {
    try {
      if (i1 > MAX_NO_DIGEST_MSG_LEN) {
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
      }
      // add zeros to the left
      if (i1 < MAX_NO_DIGEST_MSG_LEN) {
        Util.arrayFillNonAtomic(KMAndroidSEProvider.getInstance().tmpArray,
            (short) 0, (short) MAX_NO_DIGEST_MSG_LEN, (byte) 0);
      }
      Util.arrayCopyNonAtomic(bytes, i,
          KMAndroidSEProvider.getInstance().tmpArray,
          (short) (MAX_NO_DIGEST_MSG_LEN - i1), i1);
      return inst.signPreComputedHash(KMAndroidSEProvider.getInstance().tmpArray,
          (short) 0, (short) MAX_NO_DIGEST_MSG_LEN, bytes1, i2);
    } finally {
      KMAndroidSEProvider.getInstance().clean();
    }
  }

  @Override
  public short signPreComputedHash(byte[] bytes, short i, short i1,
      byte[] bytes1, short i2) throws CryptoException {
    return inst.sign(bytes, i, i1, bytes1, i2);
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
}