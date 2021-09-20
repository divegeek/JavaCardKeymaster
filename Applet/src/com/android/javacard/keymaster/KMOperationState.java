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
  public static final byte MAX_REFS = 1;
  private static final byte DATA = 0;
  private static final byte REFS = 1;
  // byte type
  private static final byte ALG = 0;
  private static final byte PURPOSE = 1;
  private static final byte PADDING = 2;
  private static final byte BLOCK_MODE = 3;
  private static final byte DIGEST = 4;
  private static final byte FLAGS = 5;
  private static final byte KEY_SIZE = 6;
  private static final byte MAC_LENGTH = 7 ;
  private static final byte MGF_DIGEST = 8;
  public static final byte OPERATION_HANDLE_SIZE = 8;
  public static final byte DATA_SIZE = 9;
  public static final byte AUTH_TIME_SIZE = 8;

  // short type

  //private static final byte KEY_SIZE = 6;
  //private static final byte MAC_LENGTH = 8;
  // Handle - currently this is short
  private static final byte OP_HANDLE = 10;
  // Auth time 64 bits
  private static final byte AUTH_TIME = 12;

  // Flag masks
  private static final short AUTH_PER_OP_REQD = 1;
  private static final short SECURE_USER_ID_REQD = 2;
  private static final short AUTH_TIMEOUT_VALIDATED = 4;
  private static final short AES_GCM_UPDATE_ALLOWED = 8;
  private static final byte ACTIVE = 1;
  private static final byte INACTIVE = 0;

  // Object References
  private byte[] opHandle;
  private byte[] authTime;
  private short[] data;
  private Object[] operation;

  /*
  private static final byte OPERATION = 0;
  private static KMOperation op;
  private static Object[] slot;
  private static KMOperationState prototype;
  private static boolean dFlag;
*/

  public KMOperationState() {
  //  data = JCSystem.makeTransientByteArray(MAX_DATA, JCSystem.CLEAR_ON_RESET);
    opHandle = JCSystem.makeTransientByteArray(OPERATION_HANDLE_SIZE, JCSystem.CLEAR_ON_RESET);
    authTime = JCSystem.makeTransientByteArray(AUTH_TIME_SIZE, JCSystem.CLEAR_ON_RESET);
    data = JCSystem.makeTransientShortArray(DATA_SIZE, JCSystem.CLEAR_ON_RESET);
    operation = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_RESET);
    reset();
  }
/*
  private static KMOperationState proto() {
    if (prototype == null) {
      prototype = new KMOperationState();
    }
    return prototype;
  }

  public static KMOperationState instance(short opHandle, Object[] slot) {
    KMOperationState opState = proto();
    opState.reset();
    Util.setShort(data, OP_HANDLE, opHandle);
    KMOperationState.slot = slot;
    return opState;
  }

  public static KMOperationState read(byte[] oprHandle, short off, Object[] slot) {
    KMOperationState opState = proto();
    opState.reset();
    Util.arrayCopy((byte[]) slot[DATA], (short) 0, data, (short) 0, (short) data.length);
    Object[] ops = ((Object[]) slot[REFS]);
    op = (KMOperation) ops[OPERATION];
    Util.setShort(data, OP_HANDLE, KMInteger.uint_64(oprHandle, off));
    KMOperationState.slot = slot;
    return opState;
  }

  public void persist() {
    if (!dFlag) {
      return;
    }
    KMRepository.instance().persistOperation(data, Util.getShort(data, OP_HANDLE), op);
    dFlag = false;
  }

  private void dataUpdated() {
    dFlag = true;
  }

 public void release() {
    Object[] ops = ((Object[]) slot[REFS]);
    ((KMOperation) ops[OPERATION]).abort();
    JCSystem.beginTransaction();
    Util.arrayFillNonAtomic(
        (byte[]) slot[0], (short) 0, (short) ((byte[]) slot[0]).length, (byte) 0);
    ops[OPERATION] = null;
    JCSystem.commitTransaction();
    reset();
  }

*/
  public void reset() {
    byte index = 0;
    while(index < DATA_SIZE){
      data[index] = KMType.INVALID_VALUE;
      index++;
    }
    Util.arrayFillNonAtomic(opHandle, (short) 0, OPERATION_HANDLE_SIZE, (byte) 0);
    Util.arrayFillNonAtomic(authTime, (short) 0, AUTH_TIME_SIZE, (byte) 0);
    
    if(null != operation[0])
    	((KMOperation)operation[0]).abort();
    
    operation[0] = null;
    /*
    dFlag = false;
    op = null;
    slot = null;

    Util.arrayFillNonAtomic(
        data, (short) 0, (short) data.length, (byte) 0);

     */
}
  public short compare(byte[] handle, short start, short len){
    return Util.arrayCompare(handle, start, opHandle, (short)0, (short)opHandle.length);
  }
  public void setKeySize(short keySize) {
  //  Util.setShort(data, KEY_SIZE, keySize);
    data[KEY_SIZE] = keySize;
  }

  public short getKeySize() {
  //  return Util.getShort(data, KEY_SIZE);
    return data[KEY_SIZE];
  }

  public short getHandle(){
    return KMInteger.uint_64(opHandle,(short)0);
  }
  public void setHandle(short handle){
    setHandle(KMInteger.cast(handle).getBuffer(),
        KMInteger.cast(handle).getStartOff(),
        KMInteger.cast(handle).length());
  }
  public short getHandle(byte[] buf, short start) {
    //return Util.getShort(KMOperationState.data, OP_HANDLE);
    Util.arrayCopyNonAtomic(opHandle,(short)0, buf, start, (short)opHandle.length);
    return (short) opHandle.length;
  }

  public void setHandle(byte[] buf, short start, short len) {
    Util.arrayCopyNonAtomic(buf,start, opHandle, (short)0, (short) opHandle.length);
    //return KMByteBlob.instance(opHandle,(short)0, (short)8);
  }
  public short getPurpose() {
    return data[PURPOSE];
  }

  public void setPurpose(short purpose) {
    data[PURPOSE] = purpose;
//    dataUpdated();
  }

  public void setOperation(KMOperation op) {
    operation[0] = op;
    /*(op = operation;
    dataUpdated();
    persist();
     */
  }

  public KMOperation getOperation() {
    return (KMOperation) operation[0];
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
    return KMInteger.uint_64(authTime,(short) 0);
   // return KMInteger.uint_64(data, (short) AUTH_TIME);
  }

  public void setAuthTime(short time){
    setAuthTime(KMInteger.cast(time).getBuffer(), KMInteger.cast(time).getStartOff());
  }
  public void setAuthTime(byte[] timeBuf, short start) {
    Util.arrayCopyNonAtomic(timeBuf,start,authTime,(short)0, AUTH_TIME_SIZE);
    /*Util.arrayCopy(timeBuf, start, data, (short) AUTH_TIME, (short) 8);
    dataUpdated();
     */
  }

  public void setOneTimeAuthReqd(boolean flag) {
    if (flag) {
      data[FLAGS] = (short) (data[FLAGS] | SECURE_USER_ID_REQD);
    } else {
      data[FLAGS] = (short) (data[FLAGS] & (~SECURE_USER_ID_REQD));
    }
   // dataUpdated();
  }

  public void setAuthTimeoutValidated(boolean flag) {
    if (flag) {
      data[FLAGS] = (byte) (data[FLAGS] | AUTH_TIMEOUT_VALIDATED);
    } else {
      data[FLAGS] = (byte) (data[FLAGS] & (~AUTH_TIMEOUT_VALIDATED));
    }
    //dataUpdated();
  }

  public void setAuthPerOperationReqd(boolean flag) {
    if (flag) {
      data[FLAGS] = (short) (data[FLAGS] | AUTH_PER_OP_REQD);
    } else {
      data[FLAGS] = (short) (data[FLAGS] & (~AUTH_PER_OP_REQD));
    }
    //dataUpdated();
  }

  public short getAlgorithm() {
    return data[ALG];
  }

  public void setAlgorithm(short algorithm) {
    data[ALG] = algorithm;
    //dataUpdated();
  }

  public short getPadding() {
    return data[PADDING];
  }

  public void setPadding(short padding) {
    data[PADDING] = padding;
    //dataUpdated();
  }

  public short getBlockMode() {
    return data[BLOCK_MODE];
  }

  public void setBlockMode(short blockMode) {
    data[BLOCK_MODE] = blockMode;
   // dataUpdated();
  }

  public short getDigest() {
    return data[DIGEST];
  }

  public short getMgfDigest() {
    return data[MGF_DIGEST];
  }

  public void setDigest(byte digest) {
    data[DIGEST] = digest;
   // dataUpdated();
  }

  public void setMgfDigest(byte mgfDigest) {
    data[MGF_DIGEST] = mgfDigest;
  }

  public boolean isAesGcmUpdateAllowed() {
    return (data[FLAGS] & AES_GCM_UPDATE_ALLOWED) != 0;
  }

  public void setAesGcmUpdateComplete() {
    data[FLAGS] = (byte) (data[FLAGS] & (~AES_GCM_UPDATE_ALLOWED));
    //dataUpdated();
  }

  public void setAesGcmUpdateStart() {
    data[FLAGS] = (byte) (data[FLAGS] | AES_GCM_UPDATE_ALLOWED);
    //dataUpdated();
  }

  public void setMacLength(short length) {
    data[MAC_LENGTH] = length;
    //Util.setShort(data, MAC_LENGTH, length);
    //dataUpdated();
  }

  public short getMacLength() {
    return data[MAC_LENGTH];
    //return Util.getShort(data, MAC_LENGTH);
  }
  public byte getBufferingMode(){
    short alg = getAlgorithm();
    short purpose = getPurpose();
    short digest = getDigest();

    if(alg == KMType.RSA && digest == KMType.DIGEST_NONE && purpose == KMType.SIGN){
      return KMType.BUF_RSA_NO_DIGEST;
    }
    if(alg == KMType.EC && digest == KMType.DIGEST_NONE && purpose == KMType.SIGN){
      return KMType.BUF_EC_NO_DIGEST;
    }
    if(alg == KMType.AES || alg == KMType.DES){
      return KMType.BUF_BLOCK_ALIGN;
    }
    return KMType.BUF_NONE;
  }
}
