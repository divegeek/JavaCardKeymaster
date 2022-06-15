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

package com.android.javacard.keymaster;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * KMOperationState is the container of an active operation started by beginOperation function. This
 * operation state is persisted by the applet in non volatile memory. However, this state is not
 * retained if applet is upgraded. There will be four operation state records maintained i.e. only
 * four active operations are supported at any given time.
 */
public class KMOperationState {

  public static final byte MAX_DATA = 63;
  private static final byte OPERATION = 0;
  private static final byte HMAC_SIGNER_OPERATION = 1;
  private static final byte TRUE = 1;
  private static final byte FALSE = 0;
  // byte type
  private static final byte ALG = 0;
  private static final byte PURPOSE = 1;
  private static final byte PADDING = 2;
  private static final byte BLOCKMODE = 3;
  private static final byte DIGEST = 4;
  private static final byte FLAGS = 5;
  private static final byte AUTH_TYPE = 6;
  // short type
  private static final byte KEY_SIZE = 7;
  private static final byte MAC_LENGTH = 9;
  // Handle - currently this is short
  private static final byte OP_HANDLE = 11;
  // Auth time 64 bits
  private static final byte AUTH_TIME = 13;
  // Secure user ids 5 * 8 = 40 bytes ( Considering Maximum 5 SECURE USER IDs)
  // First two bytes are reserved to store number of secure ids. SO total 42 bytes.
  private static final byte USER_SECURE_ID = 21;
  // Flag masks
  private static final byte AUTH_PER_OP_REQD = 1;
  private static final byte SECURE_USER_ID_REQD = 2;
  private static final byte AUTH_TIMEOUT_VALIDATED = 4;
  private static final byte AES_GCM_UPDATE_ALLOWED = 8;
  private static final byte PROCESSED_INPUT_MSG = 16;
  private static final byte MAX_SECURE_USER_IDS = 5;

  // Object References
  private byte[] data;
  private Object[] objRefs;
  private static KMOperationState prototype;
  private byte[] isDataUpdated;

  private KMOperationState() {
    data = JCSystem.makeTransientByteArray(MAX_DATA, JCSystem.CLEAR_ON_RESET);
    objRefs = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_RESET);
    isDataUpdated = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
  }

  private static KMOperationState proto() {
    if (prototype == null) {
      prototype = new KMOperationState();
    }
    return prototype;
  }

  public static KMOperationState instance(short opHandle) {
    KMOperationState opState = proto();
    opState.reset();
    Util.setShort(prototype.data, OP_HANDLE, opHandle);
    return opState;
  }

  public static KMOperationState read(byte[] oprHandle, short off, byte[] data, short dataOff, Object opr, Object hmacSignerOpr) {
    KMOperationState opState = proto();
    opState.reset();
    Util.arrayCopyNonAtomic(data, dataOff, prototype.data, (short) 0, (short) prototype.data.length);
    prototype.objRefs[OPERATION] = opr;
    prototype.objRefs[HMAC_SIGNER_OPERATION] = hmacSignerOpr;
    Util.setShort(prototype.data, OP_HANDLE, KMInteger.uint_64(oprHandle, off));
    return opState;
  }

  public void persist() {
    if (FALSE == isDataUpdated[0]) {
      return;
    }
    KMRepository.instance().persistOperation(data,
        Util.getShort(data, OP_HANDLE),
        (KMOperation) objRefs[OPERATION],
        (KMOperation) objRefs[HMAC_SIGNER_OPERATION]);
    isDataUpdated[0] = FALSE;
  }

  public void setKeySize(short keySize) {
    Util.setShort(data, KEY_SIZE, keySize);
  }

  public short getKeySize() {
    return Util.getShort(data, KEY_SIZE);
  }

  public void reset() {
    isDataUpdated[0] = FALSE;
    objRefs[OPERATION] = null;
    objRefs[HMAC_SIGNER_OPERATION] = null;
    Util.arrayFillNonAtomic(
        data, (short) 0, (short) data.length, (byte) 0);
  }

  private void dataUpdated() {
    isDataUpdated[0] = TRUE;
  }

  public void release() {
    if (objRefs[OPERATION] != null) {
      ((KMOperation) objRefs[OPERATION]).abort();
    }
    if (objRefs[HMAC_SIGNER_OPERATION] != null) {
      ((KMOperation) objRefs[HMAC_SIGNER_OPERATION]).abort();
    }
    reset();
  }

  public short getHandle() {
    return Util.getShort(data, OP_HANDLE);
  }

  public short getPurpose() {
    return data[PURPOSE];
  }

  public void setPurpose(byte purpose) {
    data[PURPOSE] = purpose;
    dataUpdated();
  }

  public void setOperation(KMOperation opr) {
    objRefs[OPERATION] = opr;
    dataUpdated();
    persist();
  }

  public boolean isInputMsgProcessed() {
    return (data[FLAGS] & PROCESSED_INPUT_MSG) != 0;
  }

  public KMOperation getOperation() {
    return (KMOperation) objRefs[OPERATION];
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
    return KMInteger.uint_64(data, (short) AUTH_TIME);
  }

  public void setAuthTime(byte[] timeBuf, short start) {
    Util.arrayCopyNonAtomic(timeBuf, start, data, (short) AUTH_TIME, (short) 8);
    dataUpdated();
  }

  public void setAuthType(byte authType) {
    data[AUTH_TYPE] = authType;
    dataUpdated();
  }

  public short getAuthType() {
    return data[AUTH_TYPE];
  }

  public short getUserSecureId() {
    short offset = USER_SECURE_ID;
    short length = Util.getShort(data, USER_SECURE_ID);
    if (length == 0) {
      return KMType.INVALID_VALUE;
    }
    short arrObj = KMArray.instance(length);
    short index = 0;
    short obj;
    offset = (short) (2 + USER_SECURE_ID);
    while (index < length) {
      obj = KMInteger.instance(data, (short) (offset + index * 8), (short) 8);
      KMArray.cast(arrObj).add(index, obj);
      index++;
    }
    return KMIntegerArrayTag.instance(KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, arrObj);
  }

  public void setUserSecureId(short integerArrayPtr) {
    short length = KMIntegerArrayTag.cast(integerArrayPtr).length();
    if (length > MAX_SECURE_USER_IDS) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    Util.arrayFillNonAtomic(data, USER_SECURE_ID, (short) (MAX_SECURE_USER_IDS * 8) , (byte) 0);
    short index = 0;
    short obj;
    short offset = USER_SECURE_ID;
    Util.setShort(data, offset, length);
    offset += 2;
    while (index < length) {
      obj = KMIntegerArrayTag.cast(integerArrayPtr).get(index);
      Util.arrayCopyNonAtomic(
          KMInteger.cast(obj).getBuffer(),
          KMInteger.cast(obj).getStartOff(),
          data,
          (short) (8 - KMInteger.cast(obj).length() + offset + 8 * index),
          KMInteger.cast(obj).length()
      );
      index++;
    }
    dataUpdated();
  }

  public void setProcessedInputMsg(boolean flag) {
    if (flag) {
      data[FLAGS] = (byte) (data[FLAGS] | PROCESSED_INPUT_MSG);
    } else {
      data[FLAGS] = (byte) (data[FLAGS] & (~PROCESSED_INPUT_MSG));
    }
    dataUpdated();
  }

  public void setOneTimeAuthReqd(boolean flag) {
    if (flag) {
      data[FLAGS] = (byte) (data[FLAGS] | SECURE_USER_ID_REQD);
    } else {
      data[FLAGS] = (byte) (data[FLAGS] & (~SECURE_USER_ID_REQD));
    }
    dataUpdated();
  }

  public void setAuthTimeoutValidated(boolean flag) {
    if (flag) {
      data[FLAGS] = (byte) (data[FLAGS] | AUTH_TIMEOUT_VALIDATED);
    } else {
      data[FLAGS] = (byte) (data[FLAGS] & (~AUTH_TIMEOUT_VALIDATED));
    }
    dataUpdated();
  }

  public void setAuthPerOperationReqd(boolean flag) {
    if (flag) {
      data[FLAGS] = (byte) (data[FLAGS] | AUTH_PER_OP_REQD);
    } else {
      data[FLAGS] = (byte) (data[FLAGS] & (~AUTH_PER_OP_REQD));
    }
    dataUpdated();
  }

  public byte getAlgorithm() {
    return data[ALG];
  }

  public void setAlgorithm(byte algorithm) {
    data[ALG] = algorithm;
    dataUpdated();
  }

  public byte getPadding() {
    return data[PADDING];
  }

  public void setPadding(byte padding) {
    data[PADDING] = padding;
    dataUpdated();
  }

  public byte getBlockMode() {
    return data[BLOCKMODE];
  }

  public void setBlockMode(byte blockMode) {
    data[BLOCKMODE] = blockMode;
    dataUpdated();
  }

  public byte getDigest() {
    return data[DIGEST];
  }

  public void setDigest(byte digest) {
    data[DIGEST] = digest;
    dataUpdated();
  }

  public boolean isAesGcmUpdateAllowed() {
    return (data[FLAGS] & AES_GCM_UPDATE_ALLOWED) != 0;
  }

  public void setAesGcmUpdateComplete() {
    data[FLAGS] = (byte) (data[FLAGS] & (~AES_GCM_UPDATE_ALLOWED));
    dataUpdated();
  }

  public void setAesGcmUpdateStart() {
    data[FLAGS] = (byte) (data[FLAGS] | AES_GCM_UPDATE_ALLOWED);
    dataUpdated();
  }

  public void setMacLength(short length) {
    Util.setShort(data, MAC_LENGTH, length);
    dataUpdated();
  }

  public short getMacLength() {
    return Util.getShort(data, MAC_LENGTH);
  }

  public void setTrustedConfirmationSigner(KMOperation hmacSignerOp) {
    objRefs[HMAC_SIGNER_OPERATION] = hmacSignerOp;
    dataUpdated();
  }

  public KMOperation getTrustedConfirmationSigner() {
    return (KMOperation)objRefs[HMAC_SIGNER_OPERATION];
  }

  public boolean isTrustedConfirmationRequired() {
    return objRefs[HMAC_SIGNER_OPERATION] != null;
  }
  
}
