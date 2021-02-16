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
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

public class KMOperationImpl implements KMOperation {

  private Cipher cipher;
  private Signature signature;
  private short cipherAlg;
  private short padding;
  private short mode;
  private short blockMode;
  private short macLength;
  //This will hold the length of the buffer stored inside the
  //Java Card after the GCM update operation.
  private short aesGcmUpdatedLen;

  public KMOperationImpl() {
  }

  public short getMode() {
    return mode;
  }

  public void setMode(short mode) {
    this.mode = mode;
  }

  public short getMacLength() {
    return macLength;
  }

  public void setMacLength(short macLength) {
    this.macLength = macLength;
  }

  public short getPaddingAlgorithm() {
    return padding;
  }

  public void setPaddingAlgorithm(short alg) {
    padding = alg;
  }

  public void setBlockMode(short mode) {
    blockMode = mode;
  }

  public short getBlockMode() {
    return blockMode;
  }

  public short getCipherAlgorithm() {
    return cipherAlg;
  }

  public void setCipherAlgorithm(short cipherAlg) {
    this.cipherAlg = cipherAlg;
  }

  public void setCipher(Cipher cipher) {
    this.cipher = cipher;
  }

  public void setSignature(Signature signer) {
    this.signature = signer;
  }

  private void resetCipher() {
    JCSystem.beginTransaction();
    cipher = null;
    macLength = 0;
    aesGcmUpdatedLen = 0;
    blockMode = 0;
    mode = 0;
    cipherAlg = 0;
    JCSystem.commitTransaction();
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength, byte[] outputDataBuf, short outputDataStart) {
    short len = cipher.update(inputDataBuf, inputDataStart, inputDataLength,
        outputDataBuf, outputDataStart);
    if (cipherAlg == KMType.AES && blockMode == KMType.GCM) {
      // Every time Block size data is stored as intermediate result.
      aesGcmUpdatedLen += (short) (inputDataLength - len);
    }
    return len;
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength) {
    signature.update(inputDataBuf, inputDataStart, inputDataLength);
    return 0;
  }

  @Override
  public short finish(byte[] inputDataBuf, short inputDataStart,
      short inputDataLen, byte[] outputDataBuf, short outputDataStart) {
    byte[] tmpArray = KMAndroidSEProvider.getInstance().tmpArray;
    short len = 0;
    try {
      if (cipherAlg == KMType.AES && blockMode == KMType.GCM) {
        if (mode == KMType.DECRYPT) {
          inputDataLen = (short) (inputDataLen - macLength);
        }
      } else if ((cipherAlg == KMType.DES || cipherAlg == KMType.AES) &&
          padding == KMType.PKCS7 && mode == KMType.ENCRYPT) {
        byte blkSize = 16;
        byte paddingBytes;
        short inputlen = inputDataLen;
        if (cipherAlg == KMType.DES) {
          blkSize = 8;
        }
        // padding bytes
        if (inputlen % blkSize == 0) {
          paddingBytes = blkSize;
        } else {
          paddingBytes = (byte) (blkSize - (inputlen % blkSize));
        }
        // final len with padding
        inputlen = (short) (inputlen + paddingBytes);
        // intermediate buffer to copy input data+padding
        // fill in the padding
        Util.arrayFillNonAtomic(tmpArray, (short) 0, inputlen, paddingBytes);
        // copy the input data
        Util.arrayCopyNonAtomic(inputDataBuf, inputDataStart, tmpArray,
            (short) 0, inputDataLen);
        inputDataBuf = tmpArray;
        inputDataLen = inputlen;
        inputDataStart = 0;
      }
      len = cipher.doFinal(inputDataBuf, inputDataStart, inputDataLen,
          outputDataBuf, outputDataStart);
      if ((cipherAlg == KMType.AES || cipherAlg == KMType.DES) &&
          padding == KMType.PKCS7 && mode == KMType.DECRYPT) {
        byte blkSize = 16;
        if (cipherAlg == KMType.DES) {
          blkSize = 8;
        }
        if (len > 0) {
          // verify if padding is corrupted.
          byte paddingByte = outputDataBuf[(short) (outputDataStart + len - 1)];
          // padding byte always should be <= block size
          if ((short) paddingByte > blkSize || (short) paddingByte <= 0) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }

          for (short j = 1; j <= paddingByte; ++j) {
            if (outputDataBuf[(short) (outputDataStart + len - j)] != paddingByte) {
              KMException.throwIt(KMError.INVALID_ARGUMENT);
            }
          }
          len = (short) (len - (short) paddingByte);// remove the padding bytes
        }
      } else if (cipherAlg == KMType.AES && blockMode == KMType.GCM) {
        if (mode == KMType.ENCRYPT) {
          len += ((AEADCipher) cipher).retrieveTag(outputDataBuf,
              (short) (outputDataStart + len), macLength);
        } else {
          boolean verified = ((AEADCipher) cipher).verifyTag(inputDataBuf,
              (short) (inputDataStart + inputDataLen), macLength, macLength);
          if (!verified) {
            KMException.throwIt(KMError.VERIFICATION_FAILED);
          }
        }
      }
    } finally {
      KMAndroidSEProvider.getInstance().clean();
      KMAndroidSEProvider.getInstance().releaseCipherInstance(cipher);
      resetCipher();
    }
    return len;
  }

  @Override
  public short sign(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength, byte[] signBuf, short signStart) {
    short len = 0;
    try {
      len = signature.sign(inputDataBuf, inputDataStart, inputDataLength,
          signBuf, signStart);
    } finally {
      KMAndroidSEProvider.getInstance().releaseSignatureInstance(signature);
      signature = null;
    }
    return len;
  }

  @Override
  public boolean verify(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength, byte[] signBuf, short signStart, short signLength) {
    boolean ret = false;
    try {
      ret = signature.verify(inputDataBuf, inputDataStart, inputDataLength,
          signBuf, signStart, signLength);
    } finally {
      KMAndroidSEProvider.getInstance().releaseSignatureInstance(signature);
      signature = null;
    }
    return ret;
  }

  @Override
  public void abort() {
    // do nothing
    if (cipher != null) {
      KMAndroidSEProvider.getInstance().releaseCipherInstance(cipher);
      resetCipher();
    }
    if (signature != null) {
      KMAndroidSEProvider.getInstance().releaseSignatureInstance(signature);
      signature = null;
    }
    KMAndroidSEProvider.getInstance().releaseOperationInstance(this);
  }

  @Override
  public void updateAAD(byte[] dataBuf, short dataStart, short dataLength) {
    ((AEADCipher) cipher).updateAAD(dataBuf, dataStart, dataLength);
  }

  @Override
  public short getAESGCMOutputSize(short dataSize, short macLength) {
    if (mode == KMType.ENCRYPT) {
      return (short) (aesGcmUpdatedLen + dataSize + macLength);
    } else {
      return (short) (aesGcmUpdatedLen + dataSize - macLength);
    }
  }
}
