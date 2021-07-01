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
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


public class KMCipherImpl extends KMCipher {

  private Cipher cipher;
  private javax.crypto.Cipher sunCipher;
  private short cipherAlg;
  private short padding;
  private short mode;
  private short blockMode;

  KMCipherImpl(Cipher c) {
    cipher = c;
  }

  KMCipherImpl(javax.crypto.Cipher c) {
    sunCipher = c;
  }

  @Override
  public short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad, short i) {
    if (cipherAlg == KMType.RSA && padding == KMType.RSA_OAEP) {
      try {
        return (short) sunCipher.doFinal(buffer, startOff, length, scratchPad, i);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (IllegalBlockSizeException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (BadPaddingException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else if (cipherAlg == KMType.AES && blockMode == KMType.GCM) {
      try {
        return (short) sunCipher.doFinal(buffer, startOff, length, scratchPad, i);
      } catch (AEADBadTagException e) {
        e.printStackTrace();
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (IllegalBlockSizeException e) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (BadPaddingException e) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else if (cipherAlg == KMType.AES && blockMode == KMType.CTR) {
      try {
        return (short) sunCipher.doFinal(buffer, startOff, length, scratchPad, i);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (IllegalBlockSizeException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (BadPaddingException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else {
      if ((cipherAlg == KMType.DES || cipherAlg == KMType.AES) && padding == KMType.PKCS7
          && mode == KMType.ENCRYPT) {
        byte blkSize = 16;
        byte paddingBytes;
        short len = length;
        if (cipherAlg == KMType.DES) {
          blkSize = 8;
        }
        // padding bytes
        if (len % blkSize == 0) {
          paddingBytes = blkSize;
        } else {
          paddingBytes = (byte) (blkSize - (len % blkSize));
        }
        // final len with padding
        len = (short) (len + paddingBytes);
        // intermediate buffer to copy input data+padding
        byte[] tmp = new byte[len];
        // fill in the padding
        Util.arrayFillNonAtomic(tmp, (short) 0, len, paddingBytes);
        // copy the input data
        Util.arrayCopyNonAtomic(buffer, startOff, tmp, (short) 0, length);
        buffer = tmp;
        length = len;
        startOff = 0;
      }
      short len = cipher.doFinal(buffer, startOff, length, scratchPad, i);
      // JCard Sim removes leading zeros during decryption in case of no padding - so add that back.
      if (cipherAlg == KMType.RSA && padding == KMType.PADDING_NONE && mode == KMType.DECRYPT
          && len < 256) {
        byte[] tempBuf = new byte[256];
        Util.arrayFillNonAtomic(tempBuf, (short) 0, (short) 256, (byte) 0);
        Util.arrayCopyNonAtomic(scratchPad, (short) 0, tempBuf, (short) (i + 256 - len), len);
        Util.arrayCopyNonAtomic(tempBuf, (short) 0, scratchPad, i, (short) 256);
        len = 256;
      } else if ((cipherAlg == KMType.AES || cipherAlg == KMType.DES) // PKCS7
          && padding == KMType.PKCS7
          && mode == KMType.DECRYPT) {
        byte blkSize = 16;
        if (cipherAlg == KMType.DES) {
          blkSize = 8;
        }
        if (len > 0) {
          //verify if padding is corrupted.
          byte paddingByte = scratchPad[i + len - 1];
          //padding byte always should be <= block size
          if ((short) paddingByte > blkSize ||
              (short) paddingByte <= 0) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }

          for (short j = 1; j <= paddingByte; ++j) {
            if (scratchPad[i + len - j] != paddingByte) {
              KMException.throwIt(KMError.INVALID_ARGUMENT);
            }
          }
          len = (short) (len - (short) paddingByte);// remove the padding bytes
        }
      }
      return len;
    }
    return KMType.INVALID_VALUE;
  }

  @Override
  public short getCipherAlgorithm() {
    return cipherAlg;
  }

  @Override
  public void setCipherAlgorithm(short alg) {
    cipherAlg = alg;
  }

  @Override
  public short update(byte[] buffer, short startOff, short length, byte[] scratchPad, short i) {
    if (cipherAlg == KMType.AES && (blockMode == KMType.GCM || blockMode == KMType.CTR)) {
      try {
        return (short) sunCipher.update(buffer, startOff, length, scratchPad, i);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (IllegalStateException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else {
      return cipher.update(buffer, startOff, length, scratchPad, i);
    }
    return KMType.INVALID_VALUE;
  }

  @Override
  public void updateAAD(byte[] buffer, short startOff, short length) {
    try {
      sunCipher.updateAAD(buffer, startOff, length);
    } catch (IllegalArgumentException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalStateException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (UnsupportedOperationException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }
  }

  @Override
  public short getPaddingAlgorithm() {
    return padding;
  }

  @Override
  public void setPaddingAlgorithm(short alg) {
    padding = alg;
  }

  @Override
  public void setBlockMode(short mode) {
    blockMode = mode;
  }

  @Override
  public short getBlockMode() {
    return blockMode;
  }

  public short getMode() {
    return mode;
  }

  public void setMode(short mode) {
    this.mode = mode;
  }

  @Override
  public short getCipherProvider() {
    return KMCipher.SUN_JCE;
  }

  @Override
  public short getAesGcmOutputSize(short len, short macLength) {
    if (sunCipher != null) {
      return (short) sunCipher.getOutputSize(len);
    } else {
      if (mode == KMType.ENCRYPT) {
        return (short) (len + macLength);
      } else {
        return (short) (len - macLength);
      }
    }
  }

}
