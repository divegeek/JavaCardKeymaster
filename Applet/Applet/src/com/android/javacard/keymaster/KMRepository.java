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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class KMRepository {
  // Data table configuration
  public static final short DATA_INDEX_SIZE = 32;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_MEM_SIZE = 2048;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;

  // Data table offsets
  public static final byte MASTER_KEY = 8;
  public static final byte SHARED_KEY = 9;
  public static final byte COMPUTED_HMAC_KEY = 10;
  public static final byte HMAC_NONCE = 11;
  public static final byte ATT_ID_BRAND = 0;
  public static final byte ATT_ID_DEVICE = 1;
  public static final byte ATT_ID_PRODUCT = 2;
  public static final byte ATT_ID_SERIAL = 3;
  public static final byte ATT_ID_IMEI = 4;
  public static final byte ATT_ID_MEID = 5;
  public static final byte ATT_ID_MANUFACTURER = 6;
  public static final byte ATT_ID_MODEL = 7;
  public static final byte ATT_EXPONENT = 12;
  public static final byte ATT_MODULUS = 13;
  public static final byte CERT_AUTH_KEY_ID = 14;
  public static final byte CERT_ISSUER = 15;
  public static final byte CERT_EXPIRY_TIME = 16;
  public static final byte BOOT_OS_VERSION = 17;
  public static final byte BOOT_OS_PATCH = 18;
  public static final byte BOOT_VERIFIED_BOOT_KEY = 19;
  public static final byte BOOT_VERIFIED_BOOT_HASH = 20;
  public static final byte BOOT_VERIFIED_BOOT_STATE = 21;
  public static final byte BOOT_DEVICE_LOCKED_STATUS = 22;
  public static final byte BOOT_DEVICE_LOCKED_TIME = 23;
  public static final byte AUTH_TAG_1 = 24;
  public static final byte AUTH_TAG_2 = 25;
  public static final byte AUTH_TAG_3 = 26;
  public static final byte AUTH_TAG_4 = 27;
  public static final byte AUTH_TAG_5 = 28;
  public static final byte AUTH_TAG_6 = 29;
  public static final byte AUTH_TAG_7 = 30;
  public static final byte AUTH_TAG_8 = 31;

  // Data Item sizes
  public static final short MASTER_KEY_SIZE = 16;
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final short ATT_KEY_MOD_SIZE = 256;
  public static final short ATT_KEY_EXP_SIZE = 256;
  public static final short HMAC_SEED_NONCE_SIZE = 32;
  public static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short OS_VERSION_SIZE = 4;
  public static final short OS_PATCH_SIZE = 4;
  public static final short DEVICE_LOCK_TS_SIZE = 8;
  public static final short DEVICE_LOCK_FLAG_SIZE = 1;
  public static final short BOOT_STATE_SIZE = 1;
  public static final short MAX_BLOB_STORAGE = 8;
  public static final short AUTH_TAG_LENGTH = 12;
  public static final short AUTH_TAG_ENTRY_SIZE = 14;
  public static final short HEAP_SIZE = 10000;
  public static final short MAX_OPS = 4;

  // Operation State Table
  private Object[] operationStateTable;
  private static short opIdCounter;

  // Boot params constants
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;

  // Volatile memory heap
  private byte[] heap;
  private short heapIndex;
  private byte[] dataTable;
  private short dataIndex;

  private static KMRepository repository;

  public static KMRepository instance() {
    return repository;
  }

  public KMRepository() {
    newDataTable();
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = 0;
    operationStateTable = new Object[MAX_OPS];
    byte index = 0;
    while(index < MAX_OPS){
      operationStateTable[index] = new Object[]{new byte[2],
        new Object[] {new byte[KMOperationState.MAX_DATA],
        new Object[KMOperationState.MAX_REFS]}};
      index++;
    }
    repository = this;
  }

  public KMOperationState findOperation(short opHandle) {
    short index = 0;
    byte[] opId;
    while(index < MAX_OPS){
      opId = ((byte[])((Object[])operationStateTable[index])[0]);
      if(Util.getShort(opId,(short)0) == opHandle)return KMOperationState.read((Object[])((Object[])operationStateTable[index])[1]);
      index++;
    }
    return null;
  }

  public KMOperationState reserveOperation(){
    short index = 0;
    byte[] opId;
    while(index < MAX_OPS){
      opId = (byte[])((Object[])operationStateTable[index])[0];
      if(Util.getShort(opId,(short)0) == 0){
        return KMOperationState.instance(/*Util.getShort(opId,(short)0)*/getOpId(),(Object[])((Object[])operationStateTable[index])[1]);
      }
      index++;
    }
    return null;
  }

  //TODO refactor following method
  public void persistOperation(byte[] data, short opHandle, KMOperation op, KMOperation hmacSigner) {
  	short index = 0;
    byte[] opId;
    //Update an existing operation state.
    while(index < MAX_OPS){
    	opId = (byte[])((Object[])operationStateTable[index])[0];
    	if(Util.getShort(opId,(short)0) == opHandle){
    		Object[] slot = (Object[])((Object[])operationStateTable[index])[1];
      	JCSystem.beginTransaction();
        Util.arrayCopy(data, (short) 0, (byte[]) slot[0], (short) 0, (short) ((byte[]) slot[0]).length);
        Object[] ops = ((Object[]) slot[1]);
        ops[0] = op;
        ops[1] = hmacSigner;
        JCSystem.commitTransaction();
        return;
    	}
    	index++;
    }

    index = 0;
    //Persist a new operation.
  	while(index < MAX_OPS){
      opId = (byte[])((Object[])operationStateTable[index])[0];
      if(Util.getShort(opId,(short)0) == 0){
      	Util.setShort(opId, (short)0, opHandle);
      	Object[] slot = (Object[])((Object[])operationStateTable[index])[1];
      	JCSystem.beginTransaction();
        Util.arrayCopy(data, (short) 0, (byte[]) slot[0], (short) 0, (short) ((byte[]) slot[0]).length);
        Object[] ops = ((Object[]) slot[1]);
        ops[0] = op;
        ops[1] = hmacSigner;
        JCSystem.commitTransaction();
      	break;
      }
      index++;
    }
  }

  private short getOpId() {
    byte index = 0;
    opIdCounter++;
    while (index < MAX_OPS) {
      if (Util.getShort((byte[]) ((Object[]) operationStateTable[index])[0], (short) 0)
          == opIdCounter) {
        opIdCounter++;
        index = 0;
        continue;
      }
      index++;
    }
    return opIdCounter;
  }

  public void releaseOperation(KMOperationState op){
    short index = 0;
    byte[] var;
    while(index < MAX_OPS){
      var = ((byte[])((Object[])operationStateTable[index])[0]);
      if(Util.getShort(var,(short)0) == op.handle()){
        Util.arrayFillNonAtomic(var,(short)0,(short)var.length,(byte)0);
        op.release();
        break;
      }
      index++;
    }
  }

  public void initMasterKey(byte[] key, short len) {
    if(len != MASTER_KEY_SIZE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    writeDataEntry(MASTER_KEY,key, (short)0, len);
  }

  public void initHmacSharedSecretKey(byte[] key, short start, short len) {
    if(len != SHARED_SECRET_KEY_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(SHARED_KEY,key,start,len);
  }


  public void initComputedHmac(byte[] key, short start, short len) {
    if(len != COMPUTED_HMAC_KEY_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(COMPUTED_HMAC_KEY,key,start,len);
  }

  public void initHmacNonce(byte[] nonce, short offset, short len) {
      if (len != HMAC_SEED_NONCE_SIZE) { KMException.throwIt(KMError.INVALID_INPUT_LENGTH);}
      writeDataEntry(HMAC_NONCE,nonce,offset,len);
    }

  public void onUninstall() {
    // Javacard Runtime environment cleans up the data.

  }

  public void onProcess() {}

  public void clean() {
    Util.arrayFillNonAtomic(heap, (short) 0, heapIndex, (byte) 0);
    heapIndex = 0;
  }

  public void onDeselect() {}

  public void onSelect() {
    // If write through caching is implemented then this method will restore the data into cache
  }

  public short getMasterKeySecret() {
    return readData(MASTER_KEY);
  }

  public short alloc(short length) {
    if (((short) (heapIndex + length)) > heap.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex += length;
    return (short) (heapIndex - length);
  }

  private short dataAlloc(short length) {
    if (((short) (dataIndex + length)) > dataTable.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    dataIndex += length;
    return (short) (dataIndex - length);
  }


  private void newDataTable(){
    if(dataTable == null) {
      dataTable = new byte[DATA_MEM_SIZE];
      dataIndex = (short)(DATA_INDEX_SIZE*DATA_INDEX_ENTRY_SIZE);
    }
  }

  public void restoreData(short blob){
    JCSystem.beginTransaction();
    Util.arrayCopy(
      KMByteBlob.cast(blob).getBuffer(),KMByteBlob.cast(blob).getStartOff(),dataTable,(short)0,
      KMByteBlob.cast(blob).length()
    );
    JCSystem.commitTransaction();
  }

  public byte[] getDataTable(){
    return dataTable;
  }

  private void clearDataEntry(short id){
    JCSystem.beginTransaction();
    id = (short)(id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable,(short)(id+DATA_INDEX_ENTRY_LENGTH));
    if (dataLen != 0) {
      short dataPtr = Util.getShort(dataTable,(short)(id+DATA_INDEX_ENTRY_OFFSET));
      Util.arrayFillNonAtomic(dataTable, dataPtr,dataLen,(byte)0);
      Util.arrayFillNonAtomic(dataTable, id,DATA_INDEX_ENTRY_SIZE,(byte)0);
    }
    JCSystem.commitTransaction();
  }

  private void writeDataEntry(short id, byte[] buf, short offset, short len) {
    JCSystem.beginTransaction();
    short dataPtr;
    id = (short)(id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable,(short)(id+DATA_INDEX_ENTRY_LENGTH));
    if (dataLen == 0) {
      dataPtr = dataAlloc(len);
      Util.setShort(dataTable,(short)(id+DATA_INDEX_ENTRY_OFFSET),dataPtr);
      Util.setShort(dataTable,(short)(id+DATA_INDEX_ENTRY_LENGTH),len);
      Util.arrayCopyNonAtomic(buf, offset,dataTable,dataPtr, len);
    } else {
      if(len != dataLen) KMException.throwIt(KMError.UNKNOWN_ERROR);
      dataPtr = Util.getShort(dataTable,(short)(id+DATA_INDEX_ENTRY_OFFSET));
      Util.arrayCopyNonAtomic(buf, offset,dataTable,dataPtr, len);
    }
    JCSystem.commitTransaction();
  }

  private short readDataEntry(short id, byte[] buf, short offset){
    id = (short)(id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable,(short)(id+DATA_INDEX_ENTRY_LENGTH));
    if (len != 0) {
      Util.arrayCopyNonAtomic(
          dataTable,
          Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)),
          buf,
          offset,
          len);
    }
    return len;
  }

  private short dataLength(short id){
    id = (short)(id * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(dataTable,(short)(id+DATA_INDEX_ENTRY_LENGTH));
  }

  public byte[] getHeap() {
    return heap;
  }


  public short getSharedKey() {
    return readData(SHARED_KEY);
  }

  public short getHmacNonce() {
    return readData(HMAC_NONCE);
  }

  public short getComputedHmacKey() {
    return readData(COMPUTED_HMAC_KEY);
  }

  public void persistAuthTag(short authTag) {
    if(KMByteBlob.cast(authTag).length() != AUTH_TAG_LENGTH)KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    short authTagEntry = alloc(AUTH_TAG_ENTRY_SIZE);
    Util.arrayCopyNonAtomic(
      KMByteBlob.cast(authTag).getBuffer(),
      KMByteBlob.cast(authTag).getStartOff(),
      getHeap(),authTagEntry, AUTH_TAG_LENGTH);
    Util.setShort(getHeap(),(short)(authTagEntry+AUTH_TAG_LENGTH),(short)0);
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      if(dataLength((short)(index+AUTH_TAG_1)) == 0){
        JCSystem.beginTransaction();
        writeDataEntry((short)(index+AUTH_TAG_1),
          KMByteBlob.cast(authTagEntry).getBuffer(),
          KMByteBlob.cast(authTagEntry).getStartOff(),
          AUTH_TAG_ENTRY_SIZE);
        JCSystem.commitTransaction();
      }
      index++;
    }
  }

  public boolean validateAuthTag(short authTag) {
    short tag = findTag(authTag);
    return tag !=KMType.INVALID_VALUE;
  }

  public void removeAuthTag(short authTag) {
    short tag = findTag(authTag);
    if(tag ==KMType.INVALID_VALUE) KMException.throwIt(KMError.UNKNOWN_ERROR);
    clearDataEntry(tag);
  }

  public void removeAllAuthTags() {
    JCSystem.beginTransaction();
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      clearDataEntry((short)(index+AUTH_TAG_1));
      index++;
    }
  }

  private short findTag(short authTag) {
    if(KMByteBlob.cast(authTag).length() != AUTH_TAG_LENGTH)KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    short index = 0;
    short authTagEntry;
    short found;
    while (index < MAX_BLOB_STORAGE) {
      if (dataLength((short)(index+AUTH_TAG_1)) != 0) {
        authTagEntry = readData((short)(index+AUTH_TAG_1));
        found =
          Util.arrayCompare(
            KMByteBlob.cast(authTagEntry).getBuffer(),
            KMByteBlob.cast(authTagEntry).getStartOff(),
            KMByteBlob.cast(authTag).getBuffer(),
            KMByteBlob.cast(authTag).getStartOff(),
            AUTH_TAG_LENGTH);
        if(found == 0)return (short)(index+AUTH_TAG_1);
      }
      index++;
    }
    return KMType.INVALID_VALUE;
  }

  public short getRateLimitedKeyCount(short authTag) {
    short tag = findTag(authTag);
    short blob;
    if (tag != KMType.INVALID_VALUE) {
      blob = readData(tag);
      return Util.getShort(KMByteBlob.cast(blob).getBuffer(),
        (short)(KMByteBlob.cast(blob).getStartOff()+AUTH_TAG_LENGTH));
    }
    return KMType.INVALID_VALUE;
  }

  public void setRateLimitedKeyCount(short authTag, short val) {
    short tag = findTag(authTag);
    short blob;
    if (tag != KMType.INVALID_VALUE) {
      blob = alloc((short)2);
      Util.setShort(getHeap(),blob,val);
      writeDataEntry(tag,getHeap(), blob,(short)2);
    }
  }


  public void persistAttestationKey(short mod, short exp) {
    if(KMByteBlob.cast(mod).length() != ATT_KEY_MOD_SIZE ||
      KMByteBlob.cast(exp).length() != ATT_KEY_EXP_SIZE) KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    writeDataEntry(ATT_MODULUS,
      KMByteBlob.cast(mod).getBuffer(),
      KMByteBlob.cast(mod).getStartOff(),
      KMByteBlob.cast(mod).length());
    writeDataEntry(ATT_EXPONENT,
      KMByteBlob.cast(exp).getBuffer(),
      KMByteBlob.cast(exp).getStartOff(),
      KMByteBlob.cast(exp).length());
  }

  public short getAttKeyModulus() {
    return readData(ATT_MODULUS);
  }

  public short getAttKeyExponent() {
    return readData(ATT_EXPONENT);
  }

  public void persistAttId(byte id, byte[] buf, short start, short len){
    writeDataEntry(id, buf,start,len);
  }

  public short getAttId(byte id){
    return readData(id);
  }

  public void deleteAttIds(){
    clearDataEntry(ATT_ID_BRAND);
    clearDataEntry(ATT_ID_MEID);
    clearDataEntry(ATT_ID_DEVICE);
    clearDataEntry(ATT_ID_IMEI);
    clearDataEntry(ATT_ID_MODEL);
    clearDataEntry(ATT_ID_PRODUCT);
    clearDataEntry(ATT_ID_SERIAL);
    clearDataEntry(ATT_ID_MANUFACTURER);
  }

  public short getIssuer() {
    return readData(CERT_ISSUER);
  }

  public short readData(short id){
    short blob = KMByteBlob.instance(dataLength(id));
    if(readDataEntry(id,KMByteBlob.cast(blob).getBuffer(),KMByteBlob.cast(blob).getStartOff())== 0){
      return 0;
    }
    return blob;
  }
  public void setIssuer(byte[] buf, short start, short len) {
    writeDataEntry(CERT_ISSUER,buf,start,len);
  }


  public short getCertExpiryTime() {
    return readData(CERT_EXPIRY_TIME);
  }

  public void setCertExpiryTime(byte[] buf, short start, short len) {
    writeDataEntry(CERT_EXPIRY_TIME, buf,start,len);
  }

  public short getAuthKeyId() {
    return readData(CERT_AUTH_KEY_ID);
  }

  public void setAuthKeyId(byte[] buf, short start, short len) {
    writeDataEntry(CERT_AUTH_KEY_ID,buf,start,len);
  }
  private static final byte[] zero = {0,0,0,0,0,0,0,0};

  public short getOsVersion(){
    short blob = readData(BOOT_OS_VERSION);
    if (blob != 0) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    }else{
      return KMInteger.uint_32(zero,(short)0);
    }
  }

  public short getOsPatch(){
    short blob = readData(BOOT_OS_PATCH);
    if (blob != 0) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    }else{
      return KMInteger.uint_32(zero,(short)0);
    }
  }

  public short getVerifiedBootKey(){
    return readData(BOOT_VERIFIED_BOOT_KEY);
  }

  public short getVerifiedBootHash(){
    return readData(BOOT_VERIFIED_BOOT_HASH);
  }

  public boolean getDeviceLock(){
    short blob = readData(BOOT_DEVICE_LOCKED_STATUS);
    return (byte)((getHeap())[KMByteBlob.cast(blob).getStartOff()] & 0xFE) != 0;
  }

  public byte getBootState(){
    short blob = readData(BOOT_VERIFIED_BOOT_STATE);
    return (getHeap())[KMByteBlob.cast(blob).getStartOff()];
  }

  public boolean getDeviceLockPasswordOnly(){
    short blob = readData(BOOT_DEVICE_LOCKED_STATUS);
    return (byte)((getHeap())[KMByteBlob.cast(blob).getStartOff()] & 0xFD) != 0;
  }

  public short getDeviceTimeStamp(){
    short blob = readData(BOOT_DEVICE_LOCKED_TIME);
    if(blob != 0){
    return KMInteger.uint_64(KMByteBlob.cast(blob).getBuffer(),
      KMByteBlob.cast(blob).getStartOff());
    }else{
      return KMInteger.uint_64(zero,(short)0);
    }
  }

  public void setOsVersion(byte[] buf, short start, short len){
    if(len != OS_VERSION_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(BOOT_OS_VERSION,buf,start,len);
  }

  public void setDeviceLock(boolean flag){
    short start = alloc(DEVICE_LOCK_FLAG_SIZE);
    if(flag) (getHeap())[start] = (byte)((getHeap())[start] | 0x01);
    else (getHeap())[start] = (byte)((getHeap())[start] & 0xFE);
    writeDataEntry(BOOT_DEVICE_LOCKED_STATUS,getHeap(),start,DEVICE_LOCK_FLAG_SIZE);
  }

  public void setDeviceLockPasswordOnly(boolean flag){
    short start = alloc(DEVICE_LOCK_FLAG_SIZE);
    if(flag) (getHeap())[start] = (byte)((getHeap())[start] | 0x02);
    else (getHeap())[start] = (byte)((getHeap())[start] & 0xFD);
    writeDataEntry(BOOT_DEVICE_LOCKED_STATUS,getHeap(),start,DEVICE_LOCK_FLAG_SIZE);
  }

  public void setDeviceLockTimestamp(byte[] buf, short start, short len){
    if(len != DEVICE_LOCK_TS_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(BOOT_DEVICE_LOCKED_TIME, buf, start,len);
  }

  public void clearDeviceLockTimeStamp(){
    clearDataEntry(BOOT_DEVICE_LOCKED_TIME);
  }

  public void setOsPatch(byte[] buf, short start, short len){
    if(len != OS_PATCH_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(BOOT_OS_PATCH,buf,start,len);
  }

  public void setVerifiedBootKey(byte[] buf, short start, short len){
    if(len > BOOT_KEY_MAX_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(BOOT_VERIFIED_BOOT_KEY,buf,start,len);
  }

  public void setVerifiedBootHash(byte[] buf, short start, short len){
    if(len > BOOT_HASH_MAX_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    writeDataEntry(BOOT_VERIFIED_BOOT_HASH,buf,start,len);
  }

  public void setBootState(byte state){
    short start = alloc(BOOT_STATE_SIZE);
    (getHeap())[start] = state;
    writeDataEntry(BOOT_VERIFIED_BOOT_STATE,getHeap(),start,BOOT_STATE_SIZE);
  }

  public short getKeyBlobCount(){
    byte index = 0;
    byte count = 0;
    while(index < MAX_BLOB_STORAGE){
      if(dataLength((short)(index+AUTH_TAG_1)) != 0) count++;
      index++;
    }
    return count;
  }
}
