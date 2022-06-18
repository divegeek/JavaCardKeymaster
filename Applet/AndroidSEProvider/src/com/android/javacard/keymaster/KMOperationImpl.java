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

  private static final short CIPHER_ALG_OFFSET = 0x00;
  private static final short PADDING_OFFSET = 0x01;
  private static final short OPER_MODE_OFFSET = 0x02;
  private static final short BLOCK_MODE_OFFSET = 0x03;
  private static final short MAC_LENGTH_OFFSET = 0x04;
  private static final byte[] EMPTY = {};
  //This will hold the length of the buffer stored inside the
  //Java Card after the GCM update operation.
  private static final short AES_GCM_UPDATE_LEN_OFFSET = 0x05;
  private short[] parameters;
  // Either one of Cipher/Signature instance is stored.
  private Object[] operationInst;

  public KMOperationImpl() {
    parameters = JCSystem.makeTransientShortArray((short) 6, JCSystem.CLEAR_ON_RESET);
    operationInst = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_RESET);
  }

  public short getMode() {
    return parameters[OPER_MODE_OFFSET];
  }

  public void setMode(short mode) {
    parameters[OPER_MODE_OFFSET] = mode;
  }

  public short getMacLength() {
    return parameters[MAC_LENGTH_OFFSET];
  }

  public void setMacLength(short macLength) {
    parameters[MAC_LENGTH_OFFSET] = macLength;
  }

  public short getPaddingAlgorithm() {
    return parameters[PADDING_OFFSET];
  }

  public void setPaddingAlgorithm(short alg) {
    parameters[PADDING_OFFSET] = alg;
  }

  public void setBlockMode(short mode) {
    parameters[BLOCK_MODE_OFFSET] = mode;
  }

  public short getBlockMode() {
    return parameters[BLOCK_MODE_OFFSET];
  }

  public short getCipherAlgorithm() {
    return parameters[CIPHER_ALG_OFFSET];
  }

  public void setCipherAlgorithm(short cipherAlg) {
    parameters[CIPHER_ALG_OFFSET] = cipherAlg;
  }

  public void setCipher(Cipher cipher) {
    operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO] = cipher;
  }

  public void setSignature(Signature signer) {
    operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO] = signer;
  }
  
  public void setKeyObject(KMKeyObject keyObject) {
    operationInst[KMAndroidSEProvider.RESOURCE_TYPE_KEY] = keyObject;
  }

  public KMKeyObject getKeyObject() {
    return (KMKeyObject) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_KEY];
  }
  
  public boolean isResourceMatches(Object object, byte resourceType) {
    return operationInst[resourceType] == object;
  }

  private void reset() {
    operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO] = null;
    operationInst[KMAndroidSEProvider.RESOURCE_TYPE_KEY] = null;
    parameters[MAC_LENGTH_OFFSET] = KMType.INVALID_VALUE;
    parameters[AES_GCM_UPDATE_LEN_OFFSET] = 0;
    parameters[BLOCK_MODE_OFFSET] = KMType.INVALID_VALUE;;
    parameters[OPER_MODE_OFFSET] = KMType.INVALID_VALUE;;
    parameters[CIPHER_ALG_OFFSET] = KMType.INVALID_VALUE;;
    parameters[PADDING_OFFSET] = KMType.INVALID_VALUE;;
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart,
                      short inputDataLength, byte[] outputDataBuf, short outputDataStart) {
    short len = ((Cipher) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO]).update(inputDataBuf, inputDataStart, inputDataLength,
      outputDataBuf, outputDataStart);
    if (parameters[CIPHER_ALG_OFFSET] == KMType.AES && parameters[BLOCK_MODE_OFFSET] == KMType.GCM) {
      // Every time Block size data is stored as intermediate result.
      parameters[AES_GCM_UPDATE_LEN_OFFSET] += (short) (inputDataLength - len);
    }
    return len;
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart,
                      short inputDataLength) {
    ((Signature) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO]).update(inputDataBuf, inputDataStart, inputDataLength);
    return 0;
  }

  @Override
  public short finish(byte[] inputDataBuf, short inputDataStart,
                      short inputDataLen, byte[] outputDataBuf, short outputDataStart) {
    byte[] tmpArray = KMAndroidSEProvider.getInstance().tmpArray;
    Cipher cipher = (Cipher) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO];
    short cipherAlg = parameters[CIPHER_ALG_OFFSET];
    short blockMode = parameters[BLOCK_MODE_OFFSET];
    short mode = parameters[OPER_MODE_OFFSET];
    short macLength = parameters[MAC_LENGTH_OFFSET];
    short padding = parameters[PADDING_OFFSET];
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
      reset();
    }
    return len;
  }

  @Override
  public short sign(byte[] inputDataBuf, short inputDataStart,
                    short inputDataLength, byte[] signBuf, short signStart) {
    short len = 0;
    try {
      len = ((Signature) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO]).sign(inputDataBuf, inputDataStart, inputDataLength,
        signBuf, signStart);
    } finally {
      reset();
    }
    return len;
  }

  @Override
  public boolean verify(byte[] inputDataBuf, short inputDataStart,
                        short inputDataLength, byte[] signBuf, short signStart, short signLength) {
    boolean ret = false;
    try {
      ret = ((Signature) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO]).verify(inputDataBuf, inputDataStart, inputDataLength,
        signBuf, signStart, signLength);
    } finally {
      reset();
    }
    return ret;
  }

  @Override
  public void abort() {
    // Few simulators does not reset the Hmac signer instance on init so as
    // a workaround to reset the hmac signer instance in case of abort/failure of the operation
    // the corresponding sign / verify function is called.
    if (operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO] != null) {
      if ((parameters[OPER_MODE_OFFSET] == KMType.SIGN || parameters[OPER_MODE_OFFSET] == KMType.VERIFY) &&
          (((Signature) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO]).getAlgorithm() == Signature.ALG_HMAC_SHA_256)) {
        Signature signer = (Signature) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO];
        try {
          if (parameters[OPER_MODE_OFFSET] == KMType.SIGN) {
            signer.sign(EMPTY, (short) 0, (short) 0, EMPTY, (short) 0);
          } else {
            signer.verify(EMPTY, (short) 0, (short) 0, EMPTY, (short) 0, (short) 0);
          }
        } catch(Exception e) {
          // Ignore.
        }
      }
    }
    reset();
  }

  @Override
  public void updateAAD(byte[] dataBuf, short dataStart, short dataLength) {
    ((AEADCipher) operationInst[KMAndroidSEProvider.RESOURCE_TYPE_CRYPTO]).updateAAD(dataBuf, dataStart, dataLength);
  }

  @Override
  public short getAESGCMOutputSize(short dataSize, short macLength) {
    if (parameters[OPER_MODE_OFFSET] == KMType.ENCRYPT) {
      return (short) (parameters[AES_GCM_UPDATE_LEN_OFFSET] + dataSize + macLength);
    } else {
      return (short) (parameters[AES_GCM_UPDATE_LEN_OFFSET] + dataSize - macLength);
    }
  }
}
