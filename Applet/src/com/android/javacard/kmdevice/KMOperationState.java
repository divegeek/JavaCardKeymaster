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

package com.android.javacard.kmdevice;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * KMOperationState is the container of an active operation started by beginOperation function. This
 * operation state is persisted by the applet in non volatile memory. However, this state is not
 * retained if applet is upgraded. There will be four operation state records maintained i.e. only
 * four active operations are supported at any given time.
 */
public class KMOperationState {

  // byte type
  private static final byte ALG = 0;
  private static final byte PURPOSE = 1;
  private static final byte PADDING = 2;
  private static final byte BLOCK_MODE = 3;
  private static final byte DIGEST = 4;
  private static final byte FLAGS = 5;
  private static final byte KEY_SIZE = 6;
  private static final byte MAC_LENGTH = 7;
  private static final byte MGF_DIGEST = 8;
  private static final byte AUTH_TYPE = 9;
  // sizes
  public static final byte OPERATION_HANDLE_SIZE = 8;
  public static final byte DATA_SIZE = 10;
  public static final byte AUTH_TIME_SIZE = 8;
  // Secure user ids 5 * 8 = 40 bytes ( Considering Maximum 5 SECURE USER IDs)
  // First two bytes are reserved to store number of secure ids. So total 42 bytes.
  public static final byte USER_SECURE_IDS_SIZE = 42;

  private static final byte OPERATION = 0;
  private static final byte HMAC_SIGNER_OPERATION = 1;
  // Flag masks
  private static final short AUTH_PER_OP_REQD = 1;
  private static final short SECURE_USER_ID_REQD = 2;
  private static final short AUTH_TIMEOUT_VALIDATED = 4;
  private static final short AES_GCM_UPDATE_ALLOWED = 8;
  // Max user secure ids.
  private static final byte MAX_SECURE_USER_IDS = 5;

  // Object References
  private byte[] opHandle;
  private byte[] authTime;
  private byte[] userSecureIds;
  private short[] data;
  private Object[] operations;


  public KMOperationState() {
    opHandle = JCSystem.makeTransientByteArray(OPERATION_HANDLE_SIZE, JCSystem.CLEAR_ON_RESET);
    authTime = JCSystem.makeTransientByteArray(AUTH_TIME_SIZE, JCSystem.CLEAR_ON_RESET);
    data = JCSystem.makeTransientShortArray(DATA_SIZE, JCSystem.CLEAR_ON_RESET);
    operations = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_RESET);
    userSecureIds = JCSystem.makeTransientByteArray(USER_SECURE_IDS_SIZE, JCSystem.CLEAR_ON_RESET);
    reset();
  }

  public void reset() {
    byte index = 0;
    while (index < DATA_SIZE) {
      data[index] = KMType.INVALID_VALUE;
      index++;
    }
    Util.arrayFillNonAtomic(opHandle, (short) 0, OPERATION_HANDLE_SIZE, (byte) 0);
    Util.arrayFillNonAtomic(authTime, (short) 0, AUTH_TIME_SIZE, (byte) 0);

    if (null != operations[OPERATION]) {
      ((KMOperation) operations[OPERATION]).abort();
    }
    operations[OPERATION] = null;

    if (null != operations[HMAC_SIGNER_OPERATION]) {
      ((KMOperation) operations[HMAC_SIGNER_OPERATION]).abort();
    }
    operations[HMAC_SIGNER_OPERATION] = null;
  }

  public short compare(byte[] handle, short start, short len) {
    return Util.arrayCompare(handle, start, opHandle, (short) 0, (short) opHandle.length);
  }

  public void setKeySize(short keySize) {
    data[KEY_SIZE] = keySize;
  }

  public short getKeySize() {
    return data[KEY_SIZE];
  }

  public short getHandle() {
    return KMInteger.uint_64(opHandle, (short) 0);
  }

  public void setHandle(byte[] buf, short start, short len) {
    Util.arrayCopyNonAtomic(buf, start, opHandle, (short) 0, (short) opHandle.length);
  }

  public short getPurpose() {
    return data[PURPOSE];
  }

  public void setPurpose(short purpose) {
    data[PURPOSE] = purpose;
  }

  public void setOperation(KMOperation op) {
    operations[OPERATION] = op;
  }

  public KMOperation getOperation() {
    return (KMOperation) operations[OPERATION];
  }

  public boolean isAuthPerOperationReqd() {
    return (data[FLAGS] & AUTH_PER_OP_REQD) != 0;
  }

  public boolean isAuthTimeoutValidated() {
    return (data[FLAGS] & AUTH_TIMEOUT_VALIDATED) != 0;
  }

  public boolean isSecureUserIdReqd() {
    return (data[FLAGS] & SECURE_USER_ID_REQD) != 0;
  }

  public short getAuthTime() {
    return KMInteger.uint_64(authTime, (short) 0);
  }

  public void setAuthTime(byte[] timeBuf, short start) {
    Util.arrayCopyNonAtomic(timeBuf, start, authTime, (short) 0, AUTH_TIME_SIZE);
  }

  public void setOneTimeAuthReqd(boolean flag) {
    if (flag) {
      data[FLAGS] = (short) (data[FLAGS] | SECURE_USER_ID_REQD);
    } else {
      data[FLAGS] = (short) (data[FLAGS] & (~SECURE_USER_ID_REQD));
    }
  }

  public void setAuthTimeoutValidated(boolean flag) {
    if (flag) {
      data[FLAGS] = (byte) (data[FLAGS] | AUTH_TIMEOUT_VALIDATED);
    } else {
      data[FLAGS] = (byte) (data[FLAGS] & (~AUTH_TIMEOUT_VALIDATED));
    }
  }

  public void setAuthType(byte authType) {
    data[AUTH_TYPE] = authType;
  }

  public short getAuthType() {
    return data[AUTH_TYPE];
  }

  public short getUserSecureId() {
    short offset = 0;
    short length = Util.getShort(userSecureIds, offset);
    offset += 2;
    if (length == 0) {
      return KMType.INVALID_VALUE;
    }
    short arrObj = KMArray.instance(length);
    short index = 0;
    short obj;
    while (index < length) {
      obj = KMInteger.instance(userSecureIds, (short) (offset + index * 8), (short) 8);
      KMArray.add(arrObj, index, obj);
      index++;
    }
    return KMIntegerArrayTag.instance(KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, arrObj);
  }

  public void setUserSecureId(short integerArrayPtr) {
    short length = KMIntegerArrayTag.length(integerArrayPtr);
    if (length > MAX_SECURE_USER_IDS) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    Util.arrayFillNonAtomic(userSecureIds, (short) 0, USER_SECURE_IDS_SIZE, (byte) 0);
    short index = 0;
    short obj;
    short offset = 0;
    offset = Util.setShort(userSecureIds, offset, length);
    while (index < length) {
      obj = KMIntegerArrayTag.get(integerArrayPtr, index);
      Util.arrayCopyNonAtomic(
          KMInteger.getBuffer(obj),
          KMInteger.getStartOff(obj),
          userSecureIds,
          (short) (8 - KMInteger.length(obj) + offset + 8 * index),
          KMInteger.length(obj)
      );
      index++;
    }
  }

  public void setAuthPerOperationReqd(boolean flag) {
    if (flag) {
      data[FLAGS] = (short) (data[FLAGS] | AUTH_PER_OP_REQD);
    } else {
      data[FLAGS] = (short) (data[FLAGS] & (~AUTH_PER_OP_REQD));
    }
  }

  public short getAlgorithm() {
    return data[ALG];
  }

  public void setAlgorithm(short algorithm) {
    data[ALG] = algorithm;
  }

  public short getPadding() {
    return data[PADDING];
  }

  public void setPadding(short padding) {
    data[PADDING] = padding;
  }

  public short getBlockMode() {
    return data[BLOCK_MODE];
  }

  public void setBlockMode(short blockMode) {
    data[BLOCK_MODE] = blockMode;
  }

  public short getDigest() {
    return data[DIGEST];
  }

  public short getMgfDigest() {
    return data[MGF_DIGEST];
  }

  public void setDigest(byte digest) {
    data[DIGEST] = digest;
  }

  public void setMgfDigest(byte mgfDigest) {
    data[MGF_DIGEST] = mgfDigest;
  }

  public boolean isAesGcmUpdateAllowed() {
    return (data[FLAGS] & AES_GCM_UPDATE_ALLOWED) != 0;
  }

  public void setAesGcmUpdateComplete() {
    data[FLAGS] = (byte) (data[FLAGS] & (~AES_GCM_UPDATE_ALLOWED));
  }

  public void setAesGcmUpdateStart() {
    data[FLAGS] = (byte) (data[FLAGS] | AES_GCM_UPDATE_ALLOWED);
  }

  public void setMacLength(short length) {
    data[MAC_LENGTH] = length;
  }

  public short getMacLength() {
    return data[MAC_LENGTH];
  }

  public byte getBufferingMode() {
    short alg = getAlgorithm();
    short purpose = getPurpose();
    short digest = getDigest();
    short padding = getPadding();
    short blockMode = getBlockMode();

    if (alg == KMType.RSA && digest == KMType.DIGEST_NONE && purpose == KMType.SIGN) {
      return KMType.BUF_RSA_NO_DIGEST;
    }

    if (alg == KMType.EC && digest == KMType.DIGEST_NONE && purpose == KMType.SIGN) {
      return KMType.BUF_EC_NO_DIGEST;
    }

    switch (alg) {
      case KMType.AES:
        if (purpose == KMType.ENCRYPT && padding == KMType.PKCS7) {
          return KMType.BUF_AES_ENCRYPT_PKCS7_BLOCK_ALIGN;
        } else if (purpose == KMType.DECRYPT && padding == KMType.PKCS7) {
          return KMType.BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGN;
        } else if (purpose == KMType.DECRYPT && blockMode == KMType.GCM) {
          return KMType.BUF_AES_GCM_DECRYPT_BLOCK_ALIGN;
        }
        break;
      case KMType.DES:
        if (purpose == KMType.ENCRYPT && padding == KMType.PKCS7) {
          return KMType.BUF_DES_ENCRYPT_PKCS7_BLOCK_ALIGN;
        } else if (purpose == KMType.DECRYPT && padding == KMType.PKCS7) {
          return KMType.BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGN;
        }
    }
    return KMType.BUF_NONE;
  }

  public void setTrustedConfirmationSigner(KMOperation hmacSignerOp) {
    operations[HMAC_SIGNER_OPERATION] = hmacSignerOp;
  }

  public KMOperation getTrustedConfirmationSigner() {
    return (KMOperation) operations[HMAC_SIGNER_OPERATION];
  }

  public boolean isTrustedConfirmationRequired() {
    return operations[HMAC_SIGNER_OPERATION] != null;
  }
}
