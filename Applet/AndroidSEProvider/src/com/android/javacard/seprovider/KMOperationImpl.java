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
package com.android.javacard.seprovider;

import com.android.javacard.kmdevice.KMException;
import com.android.javacard.kmdevice.KMOperation;
import com.android.javacard.seprovider.KMError;
import com.android.javacard.seprovider.KMType;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.PrivateKey;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;
import javacard.security.CryptoException;
import javacard.security.Key;

public class KMOperationImpl implements KMOperation {

  private static final short ALG_TYPE_OFFSET = 0x00;
  private static final short PADDING_OFFSET = 0x01;
  private static final short PURPOSE_OFFSET = 0x02;
  private static final short BLOCK_MODE_OFFSET = 0x03;
  private static final short MAC_LENGTH_OFFSET = 0x04;
  private final byte[] EMPTY = {};
  //This will hold the length of the buffer stored inside the
  //Java Card after the GCM update operation.
  private static final short AES_GCM_UPDATE_LEN_OFFSET = 0x05;
  private static final short PARAMETERS_LENGTH = 6;
  private short[] parameters;
  // Either one of Cipher/Signature instance is stored.
  private Object[] operationInst;

  public KMOperationImpl() {
    parameters = JCSystem.makeTransientShortArray(PARAMETERS_LENGTH, JCSystem.CLEAR_ON_RESET);
    operationInst = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    reset();
  }

  public short getPurpose() {
    return parameters[PURPOSE_OFFSET];
  }

  public void setPurpose(short mode) {
    parameters[PURPOSE_OFFSET] = mode;
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

  public short getAlgorithmType() {
    return parameters[ALG_TYPE_OFFSET];
  }

  public void setAlgorithmType(short cipherAlg) {
    parameters[ALG_TYPE_OFFSET] = cipherAlg;
  }

  public void setCipher(Cipher cipher) {
    operationInst[0] = cipher;
  }

  public void setSignature(Signature signer) {
    operationInst[0] = signer;
  }

  public void setKeyAgreement(KeyAgreement keyAgreement) {
    operationInst[0] = keyAgreement;
  }

  public boolean isResourceMatches(Object object) {
    return operationInst[0] == object;
  }

  private void reset() {
    operationInst[0] = null;
    parameters[MAC_LENGTH_OFFSET] = KMType.INVALID_VALUE;
    parameters[AES_GCM_UPDATE_LEN_OFFSET] = 0;
    parameters[BLOCK_MODE_OFFSET] = KMType.INVALID_VALUE;
    parameters[PURPOSE_OFFSET] = KMType.INVALID_VALUE;
    parameters[ALG_TYPE_OFFSET] = KMType.INVALID_VALUE;
    parameters[PADDING_OFFSET] = KMType.INVALID_VALUE;
  }

  private byte mapPurpose(short purpose) {
    switch (purpose) {
      case KMType.ENCRYPT:
        return Cipher.MODE_ENCRYPT;
      case KMType.DECRYPT:
        return Cipher.MODE_DECRYPT;
      case KMType.SIGN:
        return Signature.MODE_SIGN;
      case KMType.VERIFY:
        return Signature.MODE_VERIFY;
    }
    return -1;
  }

  private void initSymmetricCipher(Key key, byte[] ivBuffer, short ivStart, short ivLength) {
    Cipher symmCipher = (Cipher) operationInst[0];
    byte cipherAlg = symmCipher.getAlgorithm();
    switch (cipherAlg) {
      case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
      case Cipher.ALG_AES_CTR:
        symmCipher.init(key, mapPurpose(getPurpose()), ivBuffer, ivStart, ivLength);
        break;
      case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
      case Cipher.ALG_DES_ECB_NOPAD:
        symmCipher.init(key, mapPurpose(getPurpose()));
        break;
      case Cipher.ALG_DES_CBC_NOPAD:
        // Consume only 8 bytes of iv. the random number for iv is of 16 bytes.
        // While sending back the iv, send only 8 bytes.
        symmCipher.init(key, mapPurpose(getPurpose()), ivBuffer, ivStart, (short) 8);
        break;
      case AEADCipher.ALG_AES_GCM:
        ((AEADCipher) symmCipher).init(key, mapPurpose(getPurpose()), ivBuffer,
            ivStart, ivLength);
        break;
      default:// This should never happen
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
  }

  private void initRsa(Key key, short digest) {
    if (KMType.SIGN == getPurpose()) {
      byte mode;
      if (getPaddingAlgorithm() == KMType.PADDING_NONE ||
          (getPaddingAlgorithm() == KMType.RSA_PKCS1_1_5_SIGN &&
              digest == KMType.DIGEST_NONE)) {
        mode = Cipher.MODE_DECRYPT;
      } else {
        mode = Signature.MODE_SIGN;
      }
      ((Signature) operationInst[0]).init((PrivateKey) key, mode);
    } else { // RSA Cipher
      ((Cipher) operationInst[0]).init((PrivateKey) key, mapPurpose(getPurpose()));
    }
  }

  private void initEc(Key key) {
    if (KMType.AGREE_KEY == getPurpose()) {
      ((KeyAgreement) operationInst[0]).init((PrivateKey) key);
    } else {
      ((Signature) operationInst[0]).init((PrivateKey) key, mapPurpose(getPurpose()));
    }
  }

  public void init(Key key, short digest, byte[] buf, short start, short length) {
    switch (getAlgorithmType()) {
      case KMType.AES:
      case KMType.DES:
        initSymmetricCipher(key, buf, start, length);
        break;
      case KMType.HMAC:
        ((Signature) operationInst[0]).init(key, mapPurpose(getPurpose()));
        break;
      case KMType.RSA:
        initRsa(key, digest);
        break;
      case KMType.EC:
        initEc(key);
        break;
      default:// This should never happen
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength, byte[] outputDataBuf, short outputDataStart) {
    short len = ((Cipher) operationInst[0]).update(inputDataBuf, inputDataStart, inputDataLength,
        outputDataBuf, outputDataStart);
    if (parameters[ALG_TYPE_OFFSET] == KMType.AES
        && parameters[BLOCK_MODE_OFFSET] == KMType.GCM) {
      // Every time Block size data is stored as intermediate result.
      parameters[AES_GCM_UPDATE_LEN_OFFSET] += (short) (inputDataLength - len);
    }
    return len;
  }

  @Override
  public short update(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength) {
    ((Signature) operationInst[0]).update(inputDataBuf, inputDataStart, inputDataLength);
    return 0;
  }

  private short finishKeyAgreement(byte[] publicKey, short start, short len, byte[] output,
      short outputStart) {
    return ((KeyAgreement) operationInst[0]).generateSecret(publicKey, start, len,
        output, outputStart);
  }

  private short finishCipher(byte[] inputDataBuf, short inputDataStart, short inputDataLen,
      byte[] outputDataBuf,
      short outputDataStart) {
    short len = 0;
    try {
      byte[] tmpArray = KMAndroidSEProvider.getInstance().tmpArray;
      Cipher cipher = (Cipher) operationInst[0];
      short cipherAlg = parameters[ALG_TYPE_OFFSET];
      short blockMode = parameters[BLOCK_MODE_OFFSET];
      short mode = parameters[PURPOSE_OFFSET];
      short macLength = parameters[MAC_LENGTH_OFFSET];
      short padding = parameters[PADDING_OFFSET];

      if (cipherAlg == KMType.AES && blockMode == KMType.GCM) {
        if (mode == KMType.DECRYPT) {
          inputDataLen = (short) (inputDataLen - macLength);
        }
      } else if ((cipherAlg == KMType.DES || cipherAlg == KMType.AES) && padding == KMType.PKCS7
          && mode == KMType.ENCRYPT) {
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
        Util.arrayCopyNonAtomic(inputDataBuf, inputDataStart, tmpArray, (short) 0, inputDataLen);
        inputDataBuf = tmpArray;
        inputDataLen = inputlen;
        inputDataStart = 0;
      }
      len = cipher
          .doFinal(inputDataBuf, inputDataStart, inputDataLen, outputDataBuf, outputDataStart);
      if ((cipherAlg == KMType.AES || cipherAlg == KMType.DES) && padding == KMType.PKCS7
          && mode == KMType.DECRYPT) {
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
          len += ((AEADCipher) cipher)
              .retrieveTag(outputDataBuf, (short) (outputDataStart + len), macLength);
        } else {
          boolean verified = ((AEADCipher) cipher)
              .verifyTag(inputDataBuf, (short) (inputDataStart + inputDataLen),
                  macLength, macLength);
          if (!verified) {
            KMException.throwIt(KMError.VERIFICATION_FAILED);
          }
        }
      }
    } finally {
      KMAndroidSEProvider.getInstance().clean();
    }
    return len;
  }

  @Override
  public short finish(byte[] inputDataBuf, short inputDataStart, short inputDataLen,
      byte[] outputDataBuf,
      short outputDataStart) {
    if (parameters[PURPOSE_OFFSET] == KMType.AGREE_KEY) {
      return finishKeyAgreement(inputDataBuf, inputDataStart, inputDataLen, outputDataBuf,
          outputDataStart);
    } else {
      return finishCipher(inputDataBuf, inputDataStart, inputDataLen, outputDataBuf,
          outputDataStart);
    }
  }

  @Override
  public short sign(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength, byte[] signBuf, short signStart) {
    return ((Signature) operationInst[0]).sign(inputDataBuf, inputDataStart, inputDataLength,
        signBuf, signStart);
  }

  @Override
  public boolean verify(byte[] inputDataBuf, short inputDataStart,
      short inputDataLength, byte[] signBuf, short signStart, short signLength) {
    return ((Signature) operationInst[0]).verify(inputDataBuf, inputDataStart, inputDataLength,
        signBuf, signStart, signLength);
  }

  @Override
  public void abort() {
    // Few simulators does not reset the Hmac signer instance on init so as
    // a workaround to reset the hmac signer instance in case of abort/failure of the operation
    // the corresponding sign / verify function is called.
    if (operationInst[0] != null) {
      if ((parameters[PURPOSE_OFFSET] == KMType.SIGN || parameters[PURPOSE_OFFSET] == KMType.VERIFY)
          &&
          (((Signature) operationInst[0]).getAlgorithm() == Signature.ALG_HMAC_SHA_256)) {
        Signature signer = (Signature) operationInst[0];
        try {
          if (parameters[PURPOSE_OFFSET] == KMType.SIGN) {
            signer.sign(EMPTY, (short) 0, (short) 0, EMPTY, (short) 0);
          } else {
            signer.verify(EMPTY, (short) 0, (short) 0, EMPTY, (short) 0, (short) 0);
          }
        } catch (Exception e) {
          // Ignore.
        }
      }
    }
    reset();
  }

  @Override
  public void updateAAD(byte[] dataBuf, short dataStart, short dataLength) {
    ((AEADCipher) operationInst[0]).updateAAD(dataBuf, dataStart, dataLength);
  }

  @Override
  public short getAESGCMOutputSize(short dataSize, short macLength) {
    if (parameters[PURPOSE_OFFSET] == KMType.ENCRYPT) {
      return (short) (parameters[AES_GCM_UPDATE_LEN_OFFSET] + dataSize + macLength);
    } else {
      return (short) (parameters[AES_GCM_UPDATE_LEN_OFFSET] + dataSize - macLength);
    }
  }
}
