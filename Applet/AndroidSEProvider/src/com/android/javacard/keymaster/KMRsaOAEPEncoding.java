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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

public class KMRsaOAEPEncoding extends Cipher {

  public static final byte ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1 = (byte) 0x1E;
  public static final byte ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256 = (byte) 0x1F;

  final short MGF1_BUF_SIZE = 256;
  static byte[] mgf1Buf;
  private Cipher cipher;
  private byte hash;
  private byte mgf1Hash;
  private byte algorithm;

  public KMRsaOAEPEncoding(byte alg) {
    setDigests(alg);
    cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    algorithm = alg;
    if (null == mgf1Buf) {
      mgf1Buf = JCSystem.makeTransientByteArray(MGF1_BUF_SIZE,
          JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    }
  }

  private void setDigests(byte alg) {
    switch (alg) {
      case ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1:
        hash = MessageDigest.ALG_SHA_256;
        mgf1Hash = MessageDigest.ALG_SHA;
        break;
      case ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256:
        hash = MessageDigest.ALG_SHA_256;
        mgf1Hash = MessageDigest.ALG_SHA_256;
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
  }

  private short getDigestLength() {
    switch (hash) {
      case MessageDigest.ALG_SHA:
        return MessageDigest.LENGTH_SHA;
      case MessageDigest.ALG_SHA_224:
        return MessageDigest.LENGTH_SHA_224;
      case MessageDigest.ALG_SHA_256:
        return MessageDigest.LENGTH_SHA_256;
      case MessageDigest.ALG_SHA_384:
        return MessageDigest.LENGTH_SHA_384;
      case MessageDigest.ALG_SHA3_512:
        return MessageDigest.LENGTH_SHA_512;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    return 0;
  }

  @Override
  public void init(Key theKey, byte theMode) throws CryptoException {
    cipher.init(theKey, theMode);

  }

  @Override
  public void init(Key theKey, byte theMode, byte[] bArray, short bOff,
      short bLen) throws CryptoException {
    cipher.init(theKey, theMode, bArray, bOff, bLen);
  }

  @Override
  public byte getAlgorithm() {
    return algorithm;
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
  public short doFinal(byte[] inBuff, short inOffset, short inLength,
      byte[] outBuff, short outOffset) throws CryptoException {
    short len = cipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);

    // https://tools.ietf.org/html/rfc8017#section-7.1
    // https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf
    // RSA OAEP Encoding and Decoding Mechanism for a 2048 bit RSA Key.
    // Msg -> RSA-OAEP-ENCODE -> RSAEncryption -> RSADecryption ->
    // RSA-OAEP-DECODE -> Msg
    // RSA-OAEP-ENCODE generates an output length of 255, but RSAEncryption
    // requires and input of length 256 so we pad 0 to the left of the input
    // message and make the length equal to 256 and pass to RSAEncryption.
    // RSADecryption takes input length equal to 256 and generates an
    // output of length 256. After decryption the first byte of the output
    // should be 0(left padding we did in encryption).
    // RSA-OAEP-DECODE takes input of length 255 so remove the left padding of 1
    // byte.
    if (len != 256 || outBuff[0] != 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    inBuff = outBuff;
    inOffset = (short) (outOffset + 1);
    return rsaOAEPDecode(inBuff, inOffset, (short) (len - 1), outBuff,
        outOffset);

  }

  @Override
  public short update(byte[] inBuff, short inOffset, short inLength,
      byte[] outBuff, short outOffset) throws CryptoException {
    return cipher.update(inBuff, inOffset, inLength, outBuff, outOffset);
  }

  private void maskGenerationFunction1(byte[] input, short inputOffset,
      short inputLen, short expectedOutLen, byte[] outBuf, short outOffset) {
    short counter = 0;
    MessageDigest.OneShot md = null;
    try {
      md = MessageDigest.OneShot.open(mgf1Hash);
      short digestLen = md.getLength();

      Util.arrayCopyNonAtomic(input, inputOffset, mgf1Buf, (short) 0, inputLen);
      while (counter < (short) (expectedOutLen / digestLen)) {
        I2OS(counter, mgf1Buf, (short) inputLen);
        md.doFinal(mgf1Buf, (short) 0, (short) (4 + inputLen), outBuf,
            (short) (outOffset + (counter * digestLen)));
        counter++;
      }

      if ((short) (counter * digestLen) < expectedOutLen) {
        I2OS(counter, mgf1Buf, (short) inputLen);
        md.doFinal(mgf1Buf, (short) 0, (short) (4 + inputLen), outBuf,
            (short) (outOffset + (counter * digestLen)));
      }

    } finally {
      if (md != null) {
        md.close();
      }
      Util.arrayFillNonAtomic(mgf1Buf, (short) 0, (short) MGF1_BUF_SIZE,
          (byte) 0);
    }
  }

  // Integer to Octet String conversion.
  private void I2OS(short i, byte[] out, short offset) {
    Util.arrayFillNonAtomic(out, (short) offset, (short) 4, (byte) 0);
    out[(short) (offset + 3)] = (byte) (i >>> 0);
    out[(short) (offset + 2)] = (byte) (i >>> 8);
  }

  private short rsaOAEPDecode(byte[] encodedMsg, short encodedMsgOff,
      short encodedMsgLen, byte[] msg, short offset) {
    MessageDigest.OneShot md = null;
    byte[] tmpArray = KMAndroidSEProvider.getInstance().tmpArray;

    try {
      short hLen = getDigestLength();

      if (encodedMsgLen < (short) (2 * hLen + 1)) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      // encodedMsg will be in the format of maskedSeed||maskedDB.
      // maskedSeed length is hLen and maskedDB length is (encodedMsgLen - hLen)
      // Now retrieve the seedMask by calling MGF(maskedDB, hLen). The length
      // of the seedMask is hLen.
      // seedMask = MGF(maskedDB, hLen)
      maskGenerationFunction1(encodedMsg, (short) (encodedMsgOff + hLen),
          (short) (encodedMsgLen - hLen), hLen, tmpArray, (short) 0);

      // Get the seed by doing XOR of (maskedSeed ^ seedMask).
      // seed = (maskedSeed ^ seedMask)
      for (short i = 0; i < hLen; i++) {
        // Store the seed in encodeMsg itself.
        encodedMsg[(short) (encodedMsgOff + i)] ^= tmpArray[i];
      }

      // Now get the dbMask by calling MGF(seed , (emLen-hLen)).
      // dbMask = MGF(seed , (emLen-hLen)).
      maskGenerationFunction1(encodedMsg, (short) encodedMsgOff, hLen,
          (short) (encodedMsgLen - hLen), tmpArray, (short) 0);

      // Get the DB value. DB = (maskedDB ^ dbMask)
      // DB = Hash(P)||00||01||Msg, where P is encoding parameters. (P = NULL)
      for (short i = 0; i < (short) (encodedMsgLen - hLen); i++) {
        // Store the DB inside encodeMsg itself.
        encodedMsg[(short) (encodedMsgOff + i + hLen)] ^= tmpArray[i];
      }

      // Verify Hash.
      md = MessageDigest.OneShot.open(hash);
      Util.arrayFillNonAtomic(tmpArray, (short) 0, (short) 256, (byte) 0);
      md.doFinal(tmpArray, (short) 0, (short) 0, tmpArray, (short) 0);
      if (0 != Util.arrayCompare(encodedMsg, (short) (encodedMsgOff + hLen),
          tmpArray, (short) 0, hLen)) {
        // Verification failed.
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }

      // Find the Message block in DB.
      // DB = Hash(P)||00||01||Msg, where P is encoding parameters. (P = NULL)
      // The message will be located at the end of the Data block (DB).
      // The DB block is first constructed by keeping the message at the end and
      // to the message 0x01 byte is prepended. The hash of the
      // encoding parameters is calculated and then copied from the
      // starting of the block and a variable length of 0's are
      // appended to the end of the hash till the 0x01 byte.
      short start = 0;
      for (short i = (short) (encodedMsgOff + 2 * hLen);
          i < (short) (encodedMsgOff + encodedMsgLen); i++) {
        if (i == (short) ((encodedMsgOff + encodedMsgLen) - 1)) {
          // Bad Padding.
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (encodedMsg[i] != 0) {
          start = i;
          break;
        }
      }
      // Copy the message
      Util.arrayCopyNonAtomic(encodedMsg, (short) (start + 1), msg, offset,
          (short) (encodedMsgLen - ((start - encodedMsgOff) + 1)));
      return (short) (encodedMsgLen - ((start - encodedMsgOff) + 1));

    } finally {
      if (md != null) {
        md.close();
      }
      Util.arrayFillNonAtomic(tmpArray, (short) 0,
          KMAndroidSEProvider.TMP_ARRAY_SIZE, (byte) 0);
    }
  }
}