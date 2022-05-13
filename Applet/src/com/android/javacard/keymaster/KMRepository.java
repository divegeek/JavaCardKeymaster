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

import org.globalplatform.upgrade.Element;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * KMRepository class manages persistent and volatile memory usage by the applet. Note the
 * repository is only used by applet and it is not intended to be used by seProvider.
 */
public class KMRepository implements KMUpgradable {

  // Data table configuration
  public static final short DATA_INDEX_SIZE = 33;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_MEM_SIZE = 2048;
  public static final short HEAP_SIZE = 10000;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;
  public static final short OPERATION_HANDLE_SIZE = 8; /* 8 bytes */
  private static final short OPERATION_HANDLE_STATUS_OFFSET = 0;
  private static final short OPERATION_HANDLE_STATUS_SIZE = 1;
  private static final short OPERATION_HANDLE_OFFSET = 1;
  private static final short OPERATION_HANDLE_ENTRY_SIZE =
      OPERATION_HANDLE_SIZE + OPERATION_HANDLE_STATUS_SIZE;
  private static final byte POWER_RESET_STATUS_FLAG = (byte) 0xEF;

  // Data table offsets
  public static final byte ATT_ID_BRAND = 0;
  public static final byte ATT_ID_DEVICE = 1;
  public static final byte ATT_ID_PRODUCT = 2;
  public static final byte ATT_ID_SERIAL = 3;
  public static final byte ATT_ID_IMEI = 4;
  public static final byte ATT_ID_MEID = 5;
  public static final byte ATT_ID_MANUFACTURER = 6;
  public static final byte ATT_ID_MODEL = 7;
  public static final byte COMPUTED_HMAC_KEY = 8;
  public static final byte HMAC_NONCE = 9;
  public static final byte CERT_ISSUER = 10;
  public static final byte CERT_EXPIRY_TIME = 11;
  public static final byte BOOT_OS_VERSION = 12;
  public static final byte BOOT_OS_PATCH_LEVEL = 13;
  public static final byte VENDOR_PATCH_LEVEL = 14;
  public static final byte BOOT_PATCH_LEVEL = 15;
  public static final byte BOOT_VERIFIED_BOOT_KEY = 16;
  public static final byte BOOT_VERIFIED_BOOT_HASH = 17;
  public static final byte BOOT_VERIFIED_BOOT_STATE = 18;
  public static final byte BOOT_DEVICE_LOCKED_STATUS = 19;
  public static final byte DEVICE_LOCKED_TIME = 20;
  public static final byte DEVICE_LOCKED = 21;
  public static final byte DEVICE_LOCKED_PASSWORD_ONLY = 22;
  // Total 8 auth tags, so the next offset is AUTH_TAG_1 + 8
  public static final byte AUTH_TAG_1 = 23;
  public static final byte BOOT_ENDED_STATUS = 31;
  public static final byte EARLY_BOOT_ENDED_STATUS = 32;

  // Data Item sizes
  public static final short MASTER_KEY_SIZE = 16;
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final short HMAC_SEED_NONCE_SIZE = 32;
  public static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short OS_VERSION_SIZE = 4;
  public static final short OS_PATCH_SIZE = 4;
  public static final short VENDOR_PATCH_SIZE = 4;
  public static final short BOOT_PATCH_SIZE = 4;
  public static final short DEVICE_LOCK_TS_SIZE = 8;
  public static final short BOOT_DEVICE_LOCK_FLAG_SIZE = 1;
  public static final short DEVICE_LOCKED_FLAG_SIZE = 1;
  public static final short DEVICE_LOCKED_PASSWORD_ONLY_SIZE = 1;
  public static final short BOOT_STATE_SIZE = 1;
  public static final short MAX_OPS = 4;
  public static final byte  BOOT_KEY_MAX_SIZE = 32;
  public static final byte  BOOT_HASH_MAX_SIZE = 32;
  public static final short MAX_BLOB_STORAGE = 8;
  public static final short AUTH_TAG_LENGTH = 16;
  public static final short AUTH_TAG_COUNTER_SIZE = 4;
  public static final short AUTH_TAG_ENTRY_SIZE = (AUTH_TAG_LENGTH + AUTH_TAG_COUNTER_SIZE + 1);
  public static final short BOOT_ENDED_FLAG_SIZE = 1;
  public static final short EARLY_BOOT_ENDED_FLAG_SIZE = 1;
  private static final byte[] zero = {0, 0, 0, 0, 0, 0, 0, 0};
  
  // Buffer type
  public static final byte DEFAULT_BUF_TYPE = 0;
  public static final byte ATTEST_IDS_BUF_TYPE = 1;

  // Class Attributes
  private Object[] operationStateTable;
  private byte[] heap;
  private short[] heapIndex;
  private byte[] dataTable;
  private short dataIndex;
  private short[] reclaimIndex;
  private short attestIdsIndex;
  // This variable is used to monitor the power reset status as the Applet does not get
  // any power reset event. Initially the value of this variable is set to POWER_RESET_STATUS_FLAG.
  // If the power reset happens then this value becomes 0.
  private byte[] powerResetStatus;

  // Operation table.
  private static final short OPER_TABLE_DATA_OFFSET = 0;
  private static final short OPER_TABLE_OPR_OFFSET = 1;
  private static final short OPER_TABLE_HMAC_SIGNER_OPR_OFFSET = 2;
  private static final short OPER_DATA_LEN = OPERATION_HANDLE_ENTRY_SIZE + KMOperationState.MAX_DATA;
  private static final short DATA_ARRAY_LENGTH = MAX_OPS * OPER_DATA_LEN;


  // Singleton instance
  private static KMRepository repository;

  public static KMRepository instance() {
    return repository;
  }

  public KMRepository(boolean isUpgrading) {
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    powerResetStatus = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
    heapIndex[0] = (short) 0;
    reclaimIndex[0] = HEAP_SIZE;
    powerResetStatus[0] = POWER_RESET_STATUS_FLAG;
    newDataTable(isUpgrading);

    operationStateTable = new Object[3];
    operationStateTable[0] = JCSystem.makeTransientByteArray(DATA_ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
    operationStateTable[1] = JCSystem.makeTransientObjectArray(MAX_OPS, JCSystem.CLEAR_ON_RESET);
    operationStateTable[2] = JCSystem.makeTransientObjectArray(MAX_OPS, JCSystem.CLEAR_ON_RESET);

    //Initialize the device locked status
    if (!isUpgrading) {
      setDeviceLock(false);
      setDeviceLockPasswordOnly(false);
    } else {
      // In case of upgrade, the applet is deleted and installed again so all
      // volatile memory is erased. so it is necessary to force the power reset flag
      // to 0 so that the HAL can clear its operation state.
      powerResetStatus[0] = (byte) 0;
    }
    repository = this;
  }

  // This function checks if card reset event occurred and this function
  // should only be called before processing any of the APUs.
  // Transient memory is cleared in two cases:
  // 1. Card reset event
  // 2. Applet upgrade.
  public boolean isPowerResetEventOccurred() {
    if (powerResetStatus[0] == POWER_RESET_STATUS_FLAG) {
      return false;
    }
    return true;
  }

  /**
   * This function sets the power reset status flag to its
   * default value.
   */
  public void restorePowerResetStatus() {
    powerResetStatus[0] = POWER_RESET_STATUS_FLAG;
  }

  public void getOperationHandle(short oprHandle, byte[] buf, short off, short len) {
    if (KMInteger.cast(oprHandle).length() != OPERATION_HANDLE_SIZE) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    KMInteger.cast(oprHandle).getValue(buf, off, len);
  }

  public KMOperationState findOperation(byte[] buf, short off, short len) {
    short index = 0;
    byte[] oprTableData;
    short offset = 0;
    oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    Object[] hmacSignerOprs = (Object[]) operationStateTable[OPER_TABLE_HMAC_SIGNER_OPR_OFFSET];
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if (0 == Util.arrayCompare(buf, off, oprTableData, (short) (offset + OPERATION_HANDLE_OFFSET), len)) {
        return KMOperationState.read(oprTableData, (short) (offset + OPERATION_HANDLE_OFFSET), oprTableData,
            (short) (offset + OPERATION_HANDLE_ENTRY_SIZE),
            operations[index], hmacSignerOprs[index]);
      }
      index++;
    }
    return null;
  }

  /* operationHandle is a KMInteger */
  public KMOperationState findOperation(short operationHandle) {
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        operationHandle,
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    return findOperation(
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
  }

  /* opHandle is a KMInteger */
  public KMOperationState reserveOperation(short opHandle) {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    short offset = 0;
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      /* Check for unreserved operation state */
      if (oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] == 0) {
        return KMOperationState.instance(opHandle);
      }
      index++;
    }
    return null;
  }

  public void persistOperation(byte[] data, short opHandle, KMOperation op, KMOperation hmacSignerOp) {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    Object[] hmacSignerOprs = (Object[]) operationStateTable[OPER_TABLE_HMAC_SIGNER_OPR_OFFSET];
    short offset = 0;
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        opHandle,
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    //Update an existing operation state.
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if ((1 == oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)])
          && (0 == Util.arrayCompare(
          oprTableData,
          (short) (offset + OPERATION_HANDLE_OFFSET),
          KMByteBlob.cast(buf).getBuffer(),
          KMByteBlob.cast(buf).getStartOff(),
          KMByteBlob.cast(buf).length()))) {
        Util.arrayCopyNonAtomic(data, (short) 0, oprTableData, (short) (offset + OPERATION_HANDLE_ENTRY_SIZE),
            KMOperationState.MAX_DATA);
        operations[index] = op;
        hmacSignerOprs[index] = hmacSignerOp;
        return;
      }
      index++;
    }

    index = 0;
    //Persist a new operation.
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if (0 == oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)]) {
        oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] = 1;/*reserved */
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(buf).getBuffer(),
            KMByteBlob.cast(buf).getStartOff(),
            oprTableData,
            (short) (offset + OPERATION_HANDLE_OFFSET),
            OPERATION_HANDLE_SIZE);
        Util.arrayCopyNonAtomic(data, (short) 0, oprTableData, (short) (offset + OPERATION_HANDLE_ENTRY_SIZE),
            KMOperationState.MAX_DATA);
        operations[index] = op;
        hmacSignerOprs[index] = hmacSignerOp;
        break;
      }
      index++;
    }
  }

  public void releaseOperation(KMOperationState op) {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    Object[] hmacSignerOprs = (Object[]) operationStateTable[OPER_TABLE_HMAC_SIGNER_OPR_OFFSET];
    short offset = 0;
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        op.getHandle(),
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if ((oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] == 1) &&
          (0 == Util.arrayCompare(oprTableData,
              (short) (offset + OPERATION_HANDLE_OFFSET),
              KMByteBlob.cast(buf).getBuffer(),
              KMByteBlob.cast(buf).getStartOff(),
              KMByteBlob.cast(buf).length()))) {
        Util.arrayFillNonAtomic(oprTableData, offset, OPER_DATA_LEN, (byte) 0);
        op.release();
        operations[index] = null;
        hmacSignerOprs[index] = null;
        break;
      }
      index++;
    }
  }

  public void releaseAllOperations() {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    Object[] hmacSignerOprs = (Object[]) operationStateTable[OPER_TABLE_HMAC_SIGNER_OPR_OFFSET];
    
    short offset = 0;
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if (oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] == 1) {
        Util.arrayFillNonAtomic(oprTableData, offset, OPER_DATA_LEN, (byte) 0);
        if (operations[index] != null) {
          ((KMOperation) operations[index]).abort();
          operations[index] = null;
        }
        if (hmacSignerOprs[index] != null) {
            ((KMOperation) hmacSignerOprs[index]).abort();
            hmacSignerOprs[index] = null;
        }
      }
      index++;
    }
  }

  public void initHmacNonce(byte[] nonce, short offset, short len) {
    if (len != HMAC_SEED_NONCE_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(HMAC_NONCE, nonce, offset, len);
  }

  public void clearHmacNonce() {
    clearDataEntry(HMAC_NONCE);
  }

  public void onUninstall() {
    // Javacard Runtime environment cleans up the data.

  }

  public void onProcess() {
  }

  public void clean() {
    Util.arrayFillNonAtomic(heap, (short) 0, heapIndex[0], (byte) 0);
    heapIndex[0] = (short) 0;
    reclaimIndex[0] = HEAP_SIZE;
  }

  public void onDeselect() {
  }

  public void onSelect() {
    // If write through caching is implemented then this method will restore the data into cache
  }

  // This function uses memory from the back of the heap(transient memory). Call
  // reclaimMemory function immediately after the use.
  public short allocReclaimableMemory(short length) {
    if ((((short) (reclaimIndex[0] - length)) <= heapIndex[0])
        || (length >= HEAP_SIZE / 2)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    reclaimIndex[0] -= length;
    return reclaimIndex[0];
  }

  // Reclaims the memory back.
  public void reclaimMemory(short length) {
    if (reclaimIndex[0] < heapIndex[0]) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayFillNonAtomic(heap, reclaimIndex[0], length, (byte) 0);
    reclaimIndex[0] += length;
  }

  public short allocAvailableMemory() {
    if (heapIndex[0] >= heap.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short index = heapIndex[0];
    heapIndex[0] = (short) heap.length;
    return index;
  }

  public short alloc(short length) {
    if (length < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if ((((short) (heapIndex[0] + length)) > heap.length) ||
        (((short) (heapIndex[0] + length)) > reclaimIndex[0])) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex[0] += length;
    return (short) (heapIndex[0] - length);
  }

  private short dataAlloc(byte bufType, short length) {
    short maxSize = getMaxLimitSize(bufType);
    short dataIndex = getDataTableIndex(bufType);
    if (length < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (((short) (dataIndex + length)) > maxSize) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    dataIndex += length;
    setDataTableIndex(bufType, dataIndex);
    return (short) (dataIndex - length);
  }

  private short getDataTableIndex(byte bufType) {
    if (bufType == ATTEST_IDS_BUF_TYPE) {
      return this.attestIdsIndex;
    } else {
      return this.dataIndex;
    }
  }
  
  private void setDataTableIndex(byte bufType, short index) {
    if (bufType == ATTEST_IDS_BUF_TYPE) {
      JCSystem.beginTransaction();
      this.attestIdsIndex = index;
      JCSystem.commitTransaction();
    } else {
      JCSystem.beginTransaction();
      this.dataIndex = index;
      JCSystem.commitTransaction();
    }
  }
  
  private short getMaxLimitSize(byte bufType) {
    if (bufType == ATTEST_IDS_BUF_TYPE) {
      return (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE + KMConfigurations.TOTAL_ATTEST_IDS_SIZE);
    } else { // Default buf type.
      return (short) dataTable.length;
    }
  }

  private void newDataTable(boolean isUpgrading) {
    if (!isUpgrading) {
      if (dataTable == null) {
        dataTable = new byte[DATA_MEM_SIZE];
        attestIdsIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
        dataIndex = (short) (attestIdsIndex + KMConfigurations.TOTAL_ATTEST_IDS_SIZE);
      }
    }
  }

  public byte[] getDataTable() {
    return dataTable;
  }

  private void clearDataEntry(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen != 0) {
      short dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      JCSystem.beginTransaction();
      Util.arrayFillNonAtomic(dataTable, dataPtr, dataLen, (byte) 0);
      JCSystem.commitTransaction();
    }
  }

  private void writeDataEntry(short id, byte[] buf, short offset, short len) {
    writeDataEntry(DEFAULT_BUF_TYPE, id, buf, offset, len);
  }

  private short readDataEntry(short id, byte[] buf, short offset) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
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

  private void writeDataEntry(byte bufType, short id, byte[] buf, short offset, short len) {
    short dataPtr;
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen == 0) {
      dataPtr = dataAlloc(bufType, len);
      // Begin Transaction
      JCSystem.beginTransaction();
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET), dataPtr);
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH), len);
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
      JCSystem.commitTransaction();
      // End Transaction
    } else {
      if (len != dataLen) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      // Begin Transaction
      JCSystem.beginTransaction();
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
      JCSystem.commitTransaction();
      // End Transaction
    }
  }

  private short dataLength(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
  }

  public byte[] getHeap() {
    return heap;
  }

  public short getHmacNonce() {
    return readData(HMAC_NONCE);
  }

  public short getComputedHmacKey() {
    return readData(COMPUTED_HMAC_KEY);
  }

  public void persistAttId(byte id, byte[] buf, short start, short len) {
    writeDataEntry(ATTEST_IDS_BUF_TYPE, id, buf, start, len);
  }

  public short getAttId(byte id) {
    return readData(id);
  }

  public void deleteAttIds() {
    JCSystem.beginTransaction();
    attestIdsIndex = (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
    Util.arrayFillNonAtomic(dataTable, attestIdsIndex, KMConfigurations.TOTAL_ATTEST_IDS_SIZE, (byte) 0);
    JCSystem.commitTransaction();
  }

  public short getIssuer() {
    return readData(CERT_ISSUER);
  }

  public short readData(short id) {
    short len = dataLength(id);
    if (len != 0) {
      short blob = KMByteBlob.instance(len);
      readDataEntry(id, KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
      return blob;
    }
    return KMType.INVALID_VALUE;
  }

  public short readData(byte[] dataTable, short id, byte[] buf, short startOff, short bufLen) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (len > bufLen) {
      return KMType.INVALID_VALUE;
    }
    if (len != 0) {
      Util.arrayCopyNonAtomic(
          dataTable,
          Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)),
          buf,
          startOff,
          len);
    }
    return len;
  }

  public short getCertExpiryTime() {
    return readData(CERT_EXPIRY_TIME);
  }

  public short getOsVersion() {
    short blob = readData(BOOT_OS_VERSION);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getVendorPatchLevel() {
    short blob = readData(VENDOR_PATCH_LEVEL);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getBootPatchLevel() {
    short blob = readData(BOOT_PATCH_LEVEL);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getOsPatch() {
    short blob = readData(BOOT_OS_PATCH_LEVEL);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short readROT(short version) {
    short totalLength = 0;
    short length = dataLength(BOOT_VERIFIED_BOOT_KEY);
    if (length == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;
    // As per specification The root of trust
    // consists of verifyBootKey, boot state and device locked.
    if (version <= KMKeymasterApplet.KEYBLOB_VERSION_0) {
      // To parse old keyblobs verified boot hash is included in
      // the root of trust.

      if ((length = dataLength(BOOT_VERIFIED_BOOT_HASH)) == 0) {
        return KMType.INVALID_VALUE;
      }
      totalLength += length;
    }    
    if ((length = dataLength(BOOT_VERIFIED_BOOT_STATE)) == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;
    if ((length = dataLength(BOOT_DEVICE_LOCKED_STATUS)) == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;

    short blob = KMByteBlob.instance(totalLength);
    length = readDataEntry(BOOT_VERIFIED_BOOT_KEY, KMByteBlob.cast(blob)
        .getBuffer(), KMByteBlob.cast(blob).getStartOff());

    if (version <= KMKeymasterApplet.KEYBLOB_VERSION_0) {
      length += readDataEntry(BOOT_VERIFIED_BOOT_HASH, KMByteBlob.cast(blob)
              .getBuffer(),
          (short) (KMByteBlob.cast(blob).getStartOff() + length));
    }
    length += readDataEntry(BOOT_VERIFIED_BOOT_STATE, KMByteBlob.cast(blob)
            .getBuffer(),
        (short) (KMByteBlob.cast(blob).getStartOff() + length));

    readDataEntry(BOOT_DEVICE_LOCKED_STATUS, KMByteBlob.cast(blob)
            .getBuffer(),
        (short) (KMByteBlob.cast(blob).getStartOff() + length));
    return blob;
  }

  public short getVerifiedBootKey() {
    return readData(BOOT_VERIFIED_BOOT_KEY);
  }

  public short getVerifiedBootHash() {
    return readData(BOOT_VERIFIED_BOOT_HASH);
  }

  public boolean getBootLoaderLock() {
    short blob = readData(BOOT_DEVICE_LOCKED_STATUS);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }

  public byte getBootState() {
    short blob = readData(BOOT_VERIFIED_BOOT_STATE);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (getHeap())[KMByteBlob.cast(blob).getStartOff()];
  }

  public boolean getDeviceLock() {
    short blob = readData(DEVICE_LOCKED);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }

  public boolean getDeviceLockPasswordOnly() {
    short blob = readData(DEVICE_LOCKED_PASSWORD_ONLY);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }

  public short getDeviceTimeStamp() {
    short blob = readData(DEVICE_LOCKED_TIME);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_64(KMByteBlob.cast(blob).getBuffer(),
          KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_64(zero, (short) 0);
    }
  }

  public void setOsVersion(byte[] buf, short start, short len) {
    if (len != OS_VERSION_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_OS_VERSION, buf, start, len);
  }

  public void setVendorPatchLevel(byte[] buf, short start, short len) {
    if (len != VENDOR_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(VENDOR_PATCH_LEVEL, buf, start, len);
  }

  public void setBootPatchLevel(byte[] buf, short start, short len) {
    if (len != BOOT_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_PATCH_LEVEL, buf, start, len);
  }

  public void clearAndroidSystemProperties() {
    clearDataEntry(BOOT_OS_VERSION);
    clearDataEntry(BOOT_OS_PATCH_LEVEL);
    clearDataEntry(VENDOR_PATCH_LEVEL);
    // Don't clear BOOT_PATCH_LEVEL as it is part of
    // boot parameters.
  }

  public void setBootloaderLocked(boolean flag) {
    short start = alloc(BOOT_DEVICE_LOCK_FLAG_SIZE);
    if (flag) {
      (getHeap())[start] = (byte) 0x01;
    } else {
      (getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(BOOT_DEVICE_LOCKED_STATUS, getHeap(), start, BOOT_DEVICE_LOCK_FLAG_SIZE);
  }

  public void setDeviceLock(boolean flag) {
    short start = alloc(DEVICE_LOCKED_FLAG_SIZE);
    if (flag) {
      (getHeap())[start] = (byte) 0x01;
    } else {
      (getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(DEVICE_LOCKED, getHeap(), start, DEVICE_LOCKED_FLAG_SIZE);
  }

  public void setDeviceLockPasswordOnly(boolean flag) {
    short start = alloc(DEVICE_LOCKED_PASSWORD_ONLY_SIZE);
    if (flag) {
      (getHeap())[start] = (byte) 0x01;
    } else {
      (getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(DEVICE_LOCKED_PASSWORD_ONLY, getHeap(), start, DEVICE_LOCKED_PASSWORD_ONLY_SIZE);
  }

  public void setDeviceLockTimestamp(byte[] buf, short start, short len) {
    if (len != DEVICE_LOCK_TS_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(DEVICE_LOCKED_TIME, buf, start, len);
  }

  public void clearDeviceLockTimeStamp() {
    clearDataEntry(DEVICE_LOCKED_TIME);
  }

  public void setOsPatch(byte[] buf, short start, short len) {
    if (len != OS_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_OS_PATCH_LEVEL, buf, start, len);
  }

  public void setVerifiedBootKey(byte[] buf, short start, short len) {
    if (len > BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_VERIFIED_BOOT_KEY, buf, start, len);
  }


  public void setVerifiedBootHash(byte[] buf, short start, short len) {
    if (len > BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_VERIFIED_BOOT_HASH, buf, start, len);
  }

  public void setBootState(byte state) {
    short start = alloc(BOOT_STATE_SIZE);
    (getHeap())[start] = state;
    writeDataEntry(BOOT_VERIFIED_BOOT_STATE, getHeap(), start, BOOT_STATE_SIZE);
  }

  private boolean isAuthTagSlotAvailable(short tagId, byte[] buf, short offset) {
    readDataEntry(tagId, buf, offset);
    return (0 == buf[offset]);
  }

  private void writeAuthTagState(byte[] buf, short offset, byte state) {
    buf[offset] = state;
  }

  public boolean persistAuthTag(short authTag) {

    if (KMByteBlob.cast(authTag).length() != AUTH_TAG_LENGTH) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    short authTagEntry = alloc(AUTH_TAG_ENTRY_SIZE);
    short scratchPadOff = alloc(AUTH_TAG_ENTRY_SIZE);
    byte[] scratchPad = getHeap();
    writeAuthTagState(getHeap(), authTagEntry, (byte) 1);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(authTag).getBuffer(),
        KMByteBlob.cast(authTag).getStartOff(),
        getHeap(), (short) (authTagEntry + 1), AUTH_TAG_LENGTH);
    Util.setShort(getHeap(), (short) (authTagEntry + AUTH_TAG_LENGTH + 1 + 2),
        (short) 1);
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      if ((dataLength((short) (index + AUTH_TAG_1)) == 0) ||
          isAuthTagSlotAvailable((short) (index + AUTH_TAG_1), scratchPad, scratchPadOff)) {

        writeDataEntry((short) (index + AUTH_TAG_1), getHeap(), authTagEntry, AUTH_TAG_ENTRY_SIZE);
        return true;
      }
      index++;
    }
    return false;
  }

  public void removeAllAuthTags() {
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      clearDataEntry((short) (index + AUTH_TAG_1));
      index++;
    }
  }

  public boolean isAuthTagPersisted(short authTag) {
    return (KMType.INVALID_VALUE != findTag(authTag));
  }

  private short findTag(short authTag) {
    if (KMByteBlob.cast(authTag).length() != AUTH_TAG_LENGTH) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    short index = 0;
    short found;
    short offset = alloc(AUTH_TAG_ENTRY_SIZE);
    while (index < MAX_BLOB_STORAGE) {
      if (dataLength((short) (index + AUTH_TAG_1)) != 0) {
        readDataEntry((short) (index + AUTH_TAG_1),
            getHeap(), offset);
        found =
            Util.arrayCompare(
                getHeap(),
                (short) (offset + 1),
                KMByteBlob.cast(authTag).getBuffer(),
                KMByteBlob.cast(authTag).getStartOff(),
                AUTH_TAG_LENGTH);
        if (found == 0) {
          return (short) (index + AUTH_TAG_1);
        }
      }
      index++;
    }
    return KMType.INVALID_VALUE;
  }

  public short getRateLimitedKeyCount(short authTag, byte[] out, short outOff) {
    short tag = findTag(authTag);
    short blob;
    if (tag != KMType.INVALID_VALUE) {
      blob = readData(tag);
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(blob).getBuffer(),
          (short) (KMByteBlob.cast(blob).getStartOff() + AUTH_TAG_LENGTH + 1),
          out,
          outOff,
          AUTH_TAG_COUNTER_SIZE);
      return AUTH_TAG_COUNTER_SIZE;
    }
    return (short) 0;
  }

  public void setRateLimitedKeyCount(short authTag, byte[] buf, short off, short len) {
    short tag = findTag(authTag);
    if (tag != KMType.INVALID_VALUE) {
      short dataPtr = readData(tag);
      Util.arrayCopyNonAtomic(
          buf,
          off,
          KMByteBlob.cast(dataPtr).getBuffer(),
          (short) (KMByteBlob.cast(dataPtr).getStartOff() + AUTH_TAG_LENGTH + 1),
          len);
      writeDataEntry(tag,
          KMByteBlob.cast(dataPtr).getBuffer(),
          KMByteBlob.cast(dataPtr).getStartOff(),
          KMByteBlob.cast(dataPtr).length());
    }
  }

  @Override
  public void onSave(Element ele) {
    ele.write(dataIndex);
    ele.write(dataTable);
    ele.write(attestIdsIndex);
  }

  @Override
  public void onRestore(Element ele, short oldVersion, short currentVersion) {
    dataIndex = ele.readShort();
    dataTable = (byte[]) ele.readObject();
    if (oldVersion == 0) {
      // Previous versions does not contain version information.
      handleDataUpgradeToVersion2_0();
    } else {
      attestIdsIndex = ele.readShort();
    }
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    // dataIndex
    return (short) 4;
  }

  @Override
  public short getBackupObjectCount() {
    // dataTable
    return (short) 1;
  }

  public boolean getBootEndedStatus() {
    short blob = readData(BOOT_ENDED_STATUS);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }
  
  public void setBootEndedStatus(boolean flag) {
    short start = alloc(BOOT_ENDED_STATUS);
    if (flag) {
      (getHeap())[start] = (byte) 0x01;
    } else {
      (getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(BOOT_ENDED_STATUS, getHeap(), start, BOOT_ENDED_FLAG_SIZE);
  }
  
  public boolean getEarlyBootEndedStatus() {
    short blob = readData(EARLY_BOOT_ENDED_STATUS);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }
	  
  public void setEarlyBootEndedStatus(boolean flag) {
    short start = alloc(EARLY_BOOT_ENDED_STATUS);
    if (flag) {
      (getHeap())[start] = (byte) 0x01;
    } else {
      (getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(EARLY_BOOT_ENDED_STATUS, getHeap(), start, EARLY_BOOT_ENDED_FLAG_SIZE);
  }
  
  public void handleDataUpgradeToVersion2_0() {
    byte[] oldDataTable = dataTable;
    dataTable = new byte[2048];
    attestIdsIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
    dataIndex = (short) (attestIdsIndex + KMConfigurations.TOTAL_ATTEST_IDS_SIZE);
    // temp buffer.
    short startOffset = alloc((short) 256);

    short index = ATT_ID_BRAND;
    short len = 0;
    while (index <= DEVICE_LOCKED) {
      len = readData(oldDataTable, index, heap, startOffset, (short) 256);
      writeDataEntry(index, heap, startOffset, len);
      index++;
    }
    // set default values for the new IDS.
    setDeviceLockPasswordOnly(false);
    setBootEndedStatus(false);
    setEarlyBootEndedStatus(false);

    // Request object deletion
    oldDataTable = null;
    JCSystem.requestObjectDeletion();
  }
}
