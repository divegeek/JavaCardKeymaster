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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.Signature;


public class KMEcdsa256NoDigestSignature extends Signature {

  private java.security.Signature sunSigner;

  public KMEcdsa256NoDigestSignature(byte mode, byte[] key, short keyStart, short keyLength) {
    KeyFactory kf;
    try {
      sunSigner = java.security.Signature.getInstance("NONEwithECDSA", "SunEC");
      kf = KeyFactory.getInstance("EC");
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
      //Supported curve secp256r1
      parameters.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
      if (mode == Signature.MODE_SIGN) {
        byte[] privKey = new byte[keyLength];
        for (short i = 0; i < keyLength; i++) {
          privKey[i] = key[keyStart + i];
        }
        BigInteger bI = new BigInteger(privKey);
        ECPrivateKeySpec prikeyspec = new ECPrivateKeySpec(bI, ecParameters);
        ECPrivateKey privkey = (ECPrivateKey) kf.generatePrivate(prikeyspec);
        sunSigner.initSign(privkey);
      } else {
        //Check if  the first byte is 04 and remove it.
        if (key[keyStart] == 0x04) {
          //uncompressed format.
          keyStart++;
          keyLength--;
        }
        short i = 0;
        byte[] pubx = new byte[keyLength / 2];
        for (; i < keyLength / 2; i++) {
          pubx[i] = key[keyStart + i];
        }
        byte[] puby = new byte[keyLength / 2];
        for (i = 0; i < keyLength / 2; i++) {
          puby[i] = key[keyStart + keyLength / 2 + i];
        }
        BigInteger bIX = new BigInteger(pubx);
        BigInteger bIY = new BigInteger(puby);
        ECPoint point = new ECPoint(bIX, bIY);
        ECPublicKeySpec pubkeyspec = new ECPublicKeySpec(point, ecParameters);
        ECPublicKey pubkey = (ECPublicKey) kf.generatePublic(pubkeyspec);
        sunSigner.initVerify(pubkey);
      }
    } catch (NoSuchAlgorithmException e) {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (InvalidParameterSpecException e) {
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidKeySpecException e) {
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidKeyException e) {
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    }
  }

  @Override
  public void init(Key key, byte b) throws CryptoException {

  }

  @Override
  public void init(Key key, byte b, byte[] bytes, short i, short i1) throws CryptoException {

  }

  @Override
  public void setInitialDigest(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3)
      throws CryptoException {

  }

  @Override
  public byte getAlgorithm() {
    return 0;
  }

  @Override
  public byte getMessageDigestAlgorithm() {
    return 0;
  }

  @Override
  public byte getCipherAlgorithm() {
    return 0;
  }

  @Override
  public byte getPaddingAlgorithm() {
    return 0;
  }

  @Override
  public short getLength() throws CryptoException {
    return 0;
  }

  @Override
  public void update(byte[] message, short msgStart, short messageLength) throws CryptoException {
    byte[] msgBytes = new byte[messageLength];
    for (int i = 0; i < messageLength; i++) {
      msgBytes[i] = message[msgStart + i];
    }
    try {
      if (messageLength > 0) {
        sunSigner.update(msgBytes);
      }
    } catch (SignatureException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
  }

  @Override
  public short sign(byte[] bytes, short i, short i1, byte[] bytes1, short i2)
      throws CryptoException {
    short len = 0;
    try {
      update(bytes, i, i1);
      byte[] sig = sunSigner.sign();
      Util.arrayCopyNonAtomic(sig, (short) 0, bytes1, i2, (short) sig.length);
      return (short) sig.length;
    } catch (SignatureException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    return len;
  }

  @Override
  public short signPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2)
      throws CryptoException {
    return 0;
  }

  @Override
  public boolean verify(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3)
      throws CryptoException {
    // Public key operations not handled here.
    return false;
  }

  @Override
  public boolean verifyPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2,
      short i3) throws CryptoException {
    return false;
  }
}
