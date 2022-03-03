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

import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMUpgradable;
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

  public static final short HEAP_SIZE = 15000;

  // Data table configuration
  public static final short DATA_INDEX_SIZE = 17;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;

  //TODO reduced data table size from 2048 to 300.
  public static final short DATA_MEM_SIZE = 300;

  // Data table offsets
  public static final byte COMPUTED_HMAC_KEY = 0;
  public static final byte HMAC_NONCE = 1;
  public static final byte BOOT_OS_VERSION = 2;
  public static final byte BOOT_OS_PATCH_LEVEL = 3;
  public static final byte VENDOR_PATCH_LEVEL = 4;
  public static final byte DEVICE_LOCKED_TIME = 5;
  public static final byte DEVICE_LOCKED = 6;
  public static final byte DEVICE_LOCKED_PASSWORD_ONLY = 7;
  // Total 8 auth tags, so the next offset is AUTH_TAG_1 + 8
  public static final byte AUTH_TAG_1 = 8;
  public static final byte BOOT_ENDED_FLAG = 15;
  public static final byte EARLY_BOOT_ENDED_FLAG = 16;
  
  // Data Item sizes
  public static final short HMAC_SEED_NONCE_SIZE = 32;
  public static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short OS_VERSION_SIZE = 4;
  public static final short OS_PATCH_SIZE = 4;
  public static final short VENDOR_PATCH_SIZE = 4;
  public static final short DEVICE_LOCK_TS_SIZE = 8;
  public static final short MAX_BLOB_STORAGE = 8;
  public static final short AUTH_TAG_LENGTH = 16;
  public static final short AUTH_TAG_COUNTER_SIZE = 4;
  public static final short AUTH_TAG_ENTRY_SIZE = (AUTH_TAG_LENGTH + AUTH_TAG_COUNTER_SIZE + 1);

  // Class Attributes
  private byte[] heap;
  private short[] heapIndex;
  private byte[] dataTable;
  private short dataIndex;
  private short reclaimIndex;

  // Singleton instance
  private static KMRepository repository;

  public static KMRepository instance() {
    return repository;
  }

  public KMRepository(boolean isUpgrading) {
    newDataTable(isUpgrading);
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex = HEAP_SIZE;

    //Initialize the device locked status
    if (!isUpgrading) {
      setDeviceLock(false);
      setDeviceLockPasswordOnly(false);
    }
    repository = this;
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
    heapIndex[0] = 0;
    reclaimIndex = HEAP_SIZE;
  }

  public void onDeselect() {
  }

  public void onSelect() {
    // If write through caching is implemented then this method will restore the data into cache
  }

  // This function uses memory from the back of the heap(transient memory). Call
  // reclaimMemory function immediately after the use.
  public short allocReclaimableMemory(short length) {
    if ((((short) (reclaimIndex - length)) <= heapIndex[0])
        || (length >= HEAP_SIZE / 2)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    reclaimIndex -= length;
    return reclaimIndex;
  }

  // Reclaims the memory back.
  public void reclaimMemory(short length) {
    if (reclaimIndex < heapIndex[0]) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    reclaimIndex += length;
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
    if ((((short) (heapIndex[0] + length)) > heap.length) ||
        (((short) (heapIndex[0] + length)) > reclaimIndex)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex[0] += length;
    return (short) (heapIndex[0] - length);
  }

  private short dataAlloc(short length) {
    if (((short) (dataIndex + length)) > dataTable.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    dataIndex += length;
    return (short) (dataIndex - length);
  }

  private void newDataTable(boolean isUpgrading) {
    if (!isUpgrading) {
      if (dataTable == null) {
        dataTable = new byte[DATA_MEM_SIZE];
        dataIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
      }
    }
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
    short dataPtr;
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen == 0) {
      dataPtr = dataAlloc(len);
      JCSystem.beginTransaction();
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET), dataPtr);
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH), len);
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
      JCSystem.commitTransaction();
    } else {
      if (len != dataLen) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      JCSystem.beginTransaction();
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
      JCSystem.commitTransaction();
    }
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

  public short readData(short id) {
    short len = dataLength(id);
    if (len != 0) {
      short blob = KMByteBlob.instance(dataLength(id));
      readDataEntry(id, KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
      return blob;
    }
    return KMType.INVALID_VALUE;
  }

  private static final byte[] zero = {0, 0, 0, 0, 0, 0, 0, 0};

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

  public short getOsPatch() {
    short blob = readData(BOOT_OS_PATCH_LEVEL);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  private boolean readBoolean(short id) {
    short blob = readData(id);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }

  public boolean getDeviceLock() {
    return readBoolean(DEVICE_LOCKED);
  }

  public boolean getDeviceLockPasswordOnly() {
    return readBoolean(DEVICE_LOCKED_PASSWORD_ONLY);
  }

  public boolean getEarlyBootEndedStatus() {
    return readBoolean(EARLY_BOOT_ENDED_FLAG);
  }

  public boolean getBootEndedStatus() {
    return readBoolean(BOOT_ENDED_FLAG);
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

  private void writeBoolean(short id, boolean flag) {
    short start = alloc((short) 1);
    if (flag) {
      (getHeap())[start] = (byte) 0x01;
    } else {
      (getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(id, getHeap(), start, (short) 1);
  }

  public void setDeviceLock(boolean flag) {
    writeBoolean(DEVICE_LOCKED, flag);
  }

  public void setDeviceLockPasswordOnly(boolean flag) {
    writeBoolean(DEVICE_LOCKED_PASSWORD_ONLY, flag);
  }

  public void setDeviceLockTimestamp(byte[] buf, short start, short len) {
    if (len != DEVICE_LOCK_TS_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(DEVICE_LOCKED_TIME, buf, start, len);
  }

  public void setEarlyBootEndedStatus(boolean flag) {
    writeBoolean(EARLY_BOOT_ENDED_FLAG, flag);
  }
 
  public void setBootEndedStatus(boolean flag) {
    writeBoolean(BOOT_ENDED_FLAG, flag);
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
  }

  @Override
  public void onRestore(Element ele) {
    dataIndex = ele.readShort();
    dataTable = (byte[]) ele.readObject();
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    // dataIndex
    return (short) 2;
  }

  @Override
  public short getBackupObjectCount() {
    // dataTable
    return (short) 1;
  }
}
