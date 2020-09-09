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
  //TODO make the sizes configurable
  public static final short INVALID_VALUE = (short) 0x8000;
  public static final short HEAP_SIZE = 10000;
  public static final short MAX_BLOB_STORAGE = 8;
  public static final short AES_GCM_AUTH_TAG_LENGTH = 12;
  public static final short MASTER_KEY_SIZE = 16;
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final short HMAC_SEED_NONCE_SIZE = 32;
  public static final short MAX_OPS = 4;
  public static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short ATT_ID_HEAP_SIZE = 160;
  public static final short CERT_DATA_MEM_SIZE = 256;
  // Key Attestation related constants
  public static final byte ATT_ID_TABLE_SIZE = 8;
  public static final byte ATT_ID_HEADER_SIZE = 3;
  public static final short ATT_KEY_MOD_SIZE = 256;
  public static final short ATT_KEY_EXP_SIZE = 256;
  public static final byte ATT_ID_OFFSET = 0x02;
  public static final byte ATT_ID_LENGTH = 0x01;
  public static final byte ATT_ID_TAG = 0x00;
  public static final byte ATT_ID_BRAND = 0x00;
  public static final byte ATT_ID_DEVICE = 0x01;
  public static final byte ATT_ID_PRODUCT = 0x02;
  public static final byte ATT_ID_SERIAL = 0x03;
  public static final byte ATT_ID_IMEI = 0x04;
  public static final byte ATT_ID_MEID = 0x05;
  public static final byte ATT_ID_MANUFACTURER = 0x06;
  public static final byte ATT_ID_MODEL = 0x07;
  final short[] attIdTags ={
    KMType.ATTESTATION_ID_BRAND,
    KMType.ATTESTATION_ID_DEVICE,
    KMType.ATTESTATION_ID_PRODUCT,
    KMType.ATTESTATION_ID_SERIAL,
    KMType.ATTESTATION_ID_IMEI,
    KMType.ATTESTATION_ID_MEID,
    KMType.ATTESTATION_ID_MANUFACTURER,
    KMType.ATTESTATION_ID_MODEL};
  public byte[] attestCertIssuer;
  public byte[] attestCertAuthKeyId;
  // Boot params constants
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;
  // Repository attributes
  private static KMRepository repository;
  public boolean deviceUnlockPasswordOnly;
  private byte[] masterKey;
  private byte[] sharedKey;
  private byte[] computedHmacKey;
  private byte[] hmacNonce;
  // Volatile memory heap
  private byte[] heap;
  private short heapIndex;

  //Attestation Id Table;
  private Object[] attIdTable;

  // Operation State Table
  private Object[] operationStateTable;
  private static short opIdCounter;

  // boot parameters
  //TODO change the following into private
  public Object[] authTagRepo;
  public short keyBlobCount;
  public byte[] osVersion;
  public byte[] osPatch;
  public byte[] verifiedBootKey;
  public short actualBootKeyLength;
  public byte[] verifiedBootHash;
  public short actualBootHashLength;
  public boolean verifiedBootFlag;
  public boolean selfSignedBootFlag;
  public boolean deviceLockedFlag;
  public byte[] deviceLockedTimestamp;
  // attestation
  private byte[] attKeyModulus;
  private byte[] attKeyExponent;
  private byte[] attIdMem;
  private short attIdMemIndex;
  // attestation cert data
  private byte[] certData;
  private short issuer;
  private short issuerLen;
  private short certExpiryTime;
  private short certExpiryTimeLen;
  private short authKeyId;
  private short authKeyIdLen;
  private short certDataIndex;
  private boolean attIdSupported;

  public static KMRepository instance() {
    return repository;
  }

  public KMRepository() {
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = 0;
    attIdMem = new byte[ATT_ID_HEAP_SIZE];
    attIdMemIndex = 0;

    authTagRepo = new Object[MAX_BLOB_STORAGE];
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      authTagRepo[index] = new KMAuthTag();
      ((KMAuthTag) authTagRepo[index]).reserved = false;
      ((KMAuthTag) authTagRepo[index]).authTag = new byte[AES_GCM_AUTH_TAG_LENGTH];
      ((KMAuthTag) authTagRepo[index]).usageCount = 0;
      index++;
    }

    osVersion = new byte[4];
    osPatch = new byte[4];
    verifiedBootKey = new byte[BOOT_KEY_MAX_SIZE];
    verifiedBootHash = new byte[BOOT_HASH_MAX_SIZE];
    operationStateTable = new Object[MAX_OPS];
    index = 0;
    while(index < MAX_OPS){
      operationStateTable[index] = new Object[]{new byte[2],
        new Object[] {new byte[KMOperationState.MAX_DATA],
        new Object[KMOperationState.MAX_REFS]}};
      index++;
    }
    deviceLockedFlag = false;
    deviceLockedTimestamp = new byte[8];
    deviceUnlockPasswordOnly = false;
    Util.arrayFillNonAtomic(deviceLockedTimestamp,(short)0,(short)8,(byte)0);

    attKeyModulus = new byte[ATT_KEY_MOD_SIZE];
    attKeyExponent = new byte[ATT_KEY_EXP_SIZE];
    attIdTable = new Object[ATT_ID_TABLE_SIZE];
    attIdSupported = false;
    index = 0;
    while(index < ATT_ID_TABLE_SIZE){
      attIdTable[index] = new short[ATT_ID_HEADER_SIZE];
      ((short[])attIdTable[index])[ATT_ID_TAG] = attIdTags[index];
      ((short[])attIdTable[index])[ATT_ID_LENGTH] = 0;
      index++;
    }
    certData = new byte[CERT_DATA_MEM_SIZE];
    certDataIndex = 0;
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
        //Util.setShort(opId, (short)0,getOpId());
        return KMOperationState.instance(/*Util.getShort(opId,(short)0)*/getOpId(),(Object[])((Object[])operationStateTable[index])[1]);
      }
      index++;
    }
    return null;
  }

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
    if (masterKey == null) {
      masterKey = new byte[MASTER_KEY_SIZE];
      if(len != MASTER_KEY_SIZE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      Util.arrayCopy(key, (short) 0, masterKey, (short) 0, len);
    }
  }

  public void initHmacSharedSecretKey(byte[] key, short start, short len) {
    if (sharedKey == null) {
      sharedKey = new byte[SHARED_SECRET_KEY_SIZE];
    }
    if(len != SHARED_SECRET_KEY_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    Util.arrayCopy(key, start, sharedKey, (short) 0, len);
  }


  public void initComputedHmac(byte[] key, short start, short len) {
    if (computedHmacKey == null) {
      computedHmacKey = new byte[COMPUTED_HMAC_KEY_SIZE];
    }
    if(len != COMPUTED_HMAC_KEY_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    Util.arrayCopy(key, (short) 0, computedHmacKey, start, len);
  }

  public void initHmacNonce(byte[] nonce, short offset, short len) {
    if (hmacNonce == null) {
      hmacNonce = new byte[HMAC_SEED_NONCE_SIZE];
    }
    if (len != HMAC_SEED_NONCE_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    Util.arrayCopy(nonce, offset, hmacNonce, (short) 0, len);
  }
  /* TODO according to hal specs seed should always be empty.
      Confirm this before removing the code as it is also specified that keymasterdevice with storage
      must store and return the seed.
  public void initHmacSeed(byte[] seed, short len) {
    if (hmacSeed == null) {
      hmacSeed = new byte[HMAC_SEED_NONCE_SIZE];
    }
    if(len != HMAC_SEED_NONCE_SIZE) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    Util.arrayCopy(seed, (short) 0, hmacSeed, (short) 0, len);
  }
*/
  public void onUninstall() {
    // TODO change this
    Util.arrayFillNonAtomic(masterKey, (short) 0, (short) masterKey.length, (byte) 0);
  }

  public void onProcess() {}

  public void clean() {
    Util.arrayFillNonAtomic(heap, (short) 0, heapIndex, (byte) 0);
    heapIndex = 0;
  }

  public void onDeselect() {}

  public void onSelect() {}

  public byte[] getMasterKeySecret() {
    return masterKey;
  }

  public short alloc(short length) {
    if (((short) (heapIndex + length)) > heap.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex += length;
    return (short) (heapIndex - length);
  }

  public byte[] getHeap() {
    return heap;
  }

  public byte[] getSharedKey() {
    return sharedKey;
  }

  public byte[] getHmacNonce() {
    return hmacNonce;
  }

  public void setHmacNonce(byte[] hmacNonce) {
    Util.arrayCopy(hmacNonce, (short) 0, this.hmacNonce, (short) 0, HMAC_SEED_NONCE_SIZE);
  }
  public byte[] getComputedHmacKey() {
    return computedHmacKey;
  }

  public void setComputedHmacKey(byte[] computedHmacKey) {
    Util.arrayCopy( computedHmacKey, (short) 0, this.computedHmacKey, (short) 0, COMPUTED_HMAC_KEY_SIZE);
  }

  public void persistAuthTag(short authTag) {
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      if (!((KMAuthTag) authTagRepo[index]).reserved) {
        JCSystem.beginTransaction();
        ((KMAuthTag) authTagRepo[index]).reserved = true;
        Util.arrayCopy(
            KMByteBlob.cast(authTag).getBuffer(),
            KMByteBlob.cast(authTag).getStartOff(),
            ((KMAuthTag) authTagRepo[index]).authTag ,
            (short) 0,
            AES_GCM_AUTH_TAG_LENGTH);
        keyBlobCount++;
        JCSystem.commitTransaction();
        break;
      }
      index++;
    }
  }

  public boolean validateAuthTag(short authTag) {
    KMAuthTag tag = findTag(authTag);
    return tag != null;
  }

  public void removeAuthTag(short authTag) {
    KMAuthTag tag = findTag(authTag);
    if(tag == null){
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }
    JCSystem.beginTransaction();
    tag.reserved = false;
    short index = 0;
    while(index < AES_GCM_AUTH_TAG_LENGTH){
      tag.authTag[index] = 0;
      index++;
    }
    tag.usageCount = 0;
    keyBlobCount--;
    JCSystem.commitTransaction();
  }

  public void removeAllAuthTags() {
    JCSystem.beginTransaction();
    KMAuthTag tag;
    short index = 0;
    short i;
    while (index < MAX_BLOB_STORAGE) {
      tag = (KMAuthTag) authTagRepo[index];
      tag.reserved = false;
      i = 0;
      while(i < AES_GCM_AUTH_TAG_LENGTH){
        tag.authTag[i] = 0;
        i++;
      }
      tag.usageCount = 0;
      index++;
    }
    keyBlobCount = 0;
    JCSystem.commitTransaction();
  }

  private KMAuthTag findTag(short authTag) {
    short index = 0;
    short found;
    while (index < MAX_BLOB_STORAGE) {
      if (((KMAuthTag) authTagRepo[index]).reserved) {
        found =
            Util.arrayCompare(
                ((KMAuthTag) authTagRepo[index]).authTag,
                (short) 0,
                KMByteBlob.cast(authTag).getBuffer(),
                KMByteBlob.cast(authTag).getStartOff(),
                AES_GCM_AUTH_TAG_LENGTH);
        if (found == 0) {
          return (KMAuthTag) authTagRepo[index];
        }
      }
      index++;
    }
    return null;
  }

  public short getRateLimitedKeyCount(short authTag) {
    KMAuthTag tag = findTag(authTag);
    if (tag != null) {
      return tag.usageCount;
    }
    return KMType.INVALID_VALUE;
  }

  public void setRateLimitedKeyCount(short authTag, short val) {
    KMAuthTag tag = findTag(authTag);
    JCSystem.beginTransaction();
    if (tag != null) {
      tag.usageCount = val;
    }
    JCSystem.commitTransaction();
  }


  public void persistAttestationKey(short mod, short exp) {
    JCSystem.beginTransaction();
    if(KMByteBlob.cast(mod).length() != ATT_KEY_MOD_SIZE) KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    Util.arrayCopy(
      KMByteBlob.cast(mod).getBuffer(),
      KMByteBlob.cast(mod).getStartOff(),
      attKeyModulus,
      (short)0,
      KMByteBlob.cast(mod).length());

    if(KMByteBlob.cast(exp).length() != ATT_KEY_EXP_SIZE) KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    Util.arrayCopy(
      KMByteBlob.cast(exp).getBuffer(),
      KMByteBlob.cast(exp).getStartOff(),
      attKeyExponent,
      (short)0,
      KMByteBlob.cast(exp).length());
    JCSystem.commitTransaction();
  }

  public byte[] getAttKeyModulus() {
    return attKeyModulus;
  }

  public byte[] getAttKeyExponent() {
    return attKeyExponent;
  }

  public void persistAttId(byte id, byte[] buf, short start, short len){
    JCSystem.beginTransaction();
    short[] attId = (short[])attIdTable[id];
    attId[ATT_ID_OFFSET] = allocAttIdMemory(len);
    attId[ATT_ID_LENGTH] = len;
    Util.arrayCopy(buf,start, attIdMem,attId[ATT_ID_OFFSET],len);
    attIdSupported = true;
    JCSystem.commitTransaction();
  }

  public short getAttId(byte id, byte[] buf, short start){
    short[] attId = (short[])attIdTable[id];
    Util.arrayCopy(attIdMem,attId[ATT_ID_OFFSET],buf,start,attId[ATT_ID_LENGTH]);
    return attId[ATT_ID_LENGTH];
  }

  public short getAttIdOffset(byte id){
    short[] attId = (short[])attIdTable[id];
    return attId[ATT_ID_OFFSET];
  }

  public byte[] getAttIdBuffer(byte id){
    return attIdMem;
  }

  public short getAttIdLen(byte id){
    short[] attId = (short[])attIdTable[id];
    return attId[ATT_ID_LENGTH];
  }
  public short getAttIdTag(byte id){
    short[] attId = (short[])attIdTable[id];
    return attId[ATT_ID_TAG];
  }

  private short allocAttIdMemory(short len){
    if (((short) (attIdMemIndex + len)) > attIdMem.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    attIdMemIndex += len;
    return (short) (attIdMemIndex - len);
  }

  public void deleteAttIds(){
    JCSystem.beginTransaction();
    Util.arrayFillNonAtomic(attIdMem,(short)0,(short)attIdMem.length,(byte)0);
    short index = 0;
    while(index < ATT_ID_TABLE_SIZE){
      short[] attId = (short[])attIdTable[index];
      attId[ATT_ID_OFFSET] = 0;
      attId[ATT_ID_LENGTH] = 0;
      index++;
    }
    attIdSupported = false;
    JCSystem.commitTransaction();
  }
  public boolean isAttIdSupported(){
    return attIdSupported;
  }
  public short getIssuer() {
    return issuer;
  }

  public void setIssuer(byte[] buf, short start, short len) {
    this.issuer = allocCertData(len);
    this.issuerLen = len;
    Util.arrayCopy(buf,start,certData, issuer,len);
  }

  public short getIssuerLen() {
    return issuerLen;
  }

  public short getCertExpiryTime() {
    return certExpiryTime;
  }

  public void setCertExpiryTime(byte[] buf, short start, short len) {
    this.certExpiryTime = allocCertData(len);
    this.certExpiryTimeLen = len;
    Util.arrayCopy(buf,start,certData, certExpiryTime,len);
  }

  public short getCertExpiryTimeLen() {
    return certExpiryTimeLen;
  }


  public short getAuthKeyId() {
    return authKeyId;
  }

  public void setAuthKeyId(byte[] buf, short start, short len) {
    this.authKeyId = allocCertData(len);
    this.authKeyIdLen = len;
    Util.arrayCopy(buf,start,certData,authKeyId,len);
  }

  public short getAuthKeyIdLen() {
    return authKeyIdLen;
  }
  public byte[] getCertDataBuffer(){
    return certData;
  }
  private short allocCertData(short len){
    if (((short) (certDataIndex + len)) > certData.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    certDataIndex += len;
    return (short) (certDataIndex - len);
  }
}
