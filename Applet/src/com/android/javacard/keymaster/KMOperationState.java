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

  public static final byte MAX_DATA = 20;
  private static final byte OPERATION = 0;
  private static final byte TRUE = 1;
  private static final byte FALSE = 0;
  // byte type
  private static final byte ALG = 0;
  private static final byte PURPOSE = 1;
  private static final byte PADDING = 2;
  private static final byte BLOCKMODE = 3;
  private static final byte DIGEST = 4;
  private static final byte FLAGS = 5;
  // short type
  private static final byte KEY_SIZE = 6;
  private static final byte MAC_LENGTH = 8;
  // Handle - currently this is short
  private static final byte OP_HANDLE = 10;
  // Auth time 64 bits
  private static final byte AUTH_TIME = 12;
  // Flag masks
  private static final byte AUTH_PER_OP_REQD = 1;
  private static final byte SECURE_USER_ID_REQD = 2;
  private static final byte AUTH_TIMEOUT_VALIDATED = 4;
  private static final byte AES_GCM_UPDATE_ALLOWED = 8;

  // Object References
  private byte[] data;
  private Object[] objRefs;
  private static KMOperationState prototype;
  private byte[] isDataUpdated;

  private KMOperationState() {
    data = JCSystem.makeTransientByteArray(MAX_DATA, JCSystem.CLEAR_ON_RESET);
    objRefs = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
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

  public static KMOperationState read(byte[] oprHandle, short off, byte[] data, short dataOff, Object opr) {
    KMOperationState opState = proto();
    opState.reset();
    Util.arrayCopy(data, dataOff, prototype.data, (short) 0, (short) prototype.data.length);
    prototype.objRefs[OPERATION] = opr;
    Util.setShort(prototype.data, OP_HANDLE, KMInteger.uint_64(oprHandle, off));
    return opState;
  }

  public void persist() {
    if (FALSE == isDataUpdated[0]) {
      return;
    }
    KMRepository.instance().persistOperation(data,
        Util.getShort(data, OP_HANDLE),
        (KMOperation) objRefs[OPERATION]);
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
    Util.arrayFillNonAtomic(
        data, (short) 0, (short) data.length, (byte) 0);
  }

  private void dataUpdated() {
    isDataUpdated[0] = TRUE;
  }

  public void release() {
    if (objRefs[OPERATION] != null)
      ((KMOperation) objRefs[OPERATION]).abort();
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
    Util.arrayCopy(timeBuf, start, data, (short) AUTH_TIME, (short) 8);
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
}
