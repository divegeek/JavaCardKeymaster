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
  public static final short HEAP_SIZE = 0x1000;
  public static final short MAX_BLOB_STORAGE = 32;
  public static final short AES_GCM_AUTH_TAG_LENGTH = 12;
  // Boot params constants
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;
  // Repository attributes
  private static KMRepository repository;
  private byte[] masterKey;
  private byte[] heap;
  private short heapIndex;
  // boot parameters
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
  public boolean deviceLockedFlag ;

  public static KMRepository instance() {
    return repository;
  }

  public KMRepository(byte[] masterKey) {
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    this.masterKey = new byte[(short)masterKey.length];
    // Initialize masterkey
    Util.arrayCopy(masterKey, (short)0, this.masterKey, (short)0, (short)masterKey.length);
    authTagRepo = new Object[MAX_BLOB_STORAGE];
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      authTagRepo[index] = new byte[AES_GCM_AUTH_TAG_LENGTH];
      index++;
    }
    osVersion = new byte[4];
    osPatch = new byte[4];
    verifiedBootKey = new byte[BOOT_KEY_MAX_SIZE];
    verifiedBootHash = new byte[BOOT_HASH_MAX_SIZE];
    repository = this;
  }

  public void onUninstall() {
    //TODO change this
    Util.arrayFillNonAtomic(masterKey,(short)0,(short)masterKey.length,(byte) 0);
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

  public static void persistAuthTag(short authTag) {
    final byte[] compare = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    }; // length equal to AES_GCM_AUTH_TAG_LENGTH.
    short index = 0;
    byte ret = 0;
    while (index < MAX_BLOB_STORAGE) {
      ret =
        Util.arrayCompare(
          (byte[]) (repository.authTagRepo[index]),
          (short) 0,
          compare,
          (short) 0,
          AES_GCM_AUTH_TAG_LENGTH);
      if (ret == 0) {
        break;
      }
      index++;
    }
    // This should never happen
    if (index >= repository.MAX_BLOB_STORAGE){
      ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
    }
    JCSystem.beginTransaction();
    Util.arrayCopy(
      KMByteBlob.cast(authTag).getBuffer(),
      KMByteBlob.cast(authTag).getStartOff(),
      (byte[]) (repository.authTagRepo[index]),
      (short) 0,
      AES_GCM_AUTH_TAG_LENGTH);
    repository.keyBlobCount++;
    JCSystem.commitTransaction();
  }

  public static void removeAuthTag(short authTag) {
    final byte[] zeroTag = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    }; // length equal to AES_GCM_AUTH_TAG_LENGTH.
    short index = 0;
    byte ret = 0;
    while (index < repository.MAX_BLOB_STORAGE) {
      ret =
        Util.arrayCompare(
          (byte[]) (repository.authTagRepo[index]),
          (short) 0,
          KMByteBlob.cast(authTag).getBuffer(),
          KMByteBlob.cast(authTag).getStartOff(),
          AES_GCM_AUTH_TAG_LENGTH);
      if (ret == 0) {
        break;
      }
      index++;
    }
    if (index >= MAX_BLOB_STORAGE) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }
    JCSystem.beginTransaction();
    Util.arrayCopy(
      zeroTag, (short) 0, (byte[]) (repository.authTagRepo[index]), (short) 0, AES_GCM_AUTH_TAG_LENGTH);
    repository.keyBlobCount--;
    JCSystem.commitTransaction();
  }

  public static boolean validateAuthTag(short authTag) {
    short index = 0;
    byte ret = 0;
    while (index < MAX_BLOB_STORAGE) {
      ret =
        Util.arrayCompare(
          (byte[]) (repository.authTagRepo[index]),
          (short) 0,
          KMByteBlob.cast(authTag).getBuffer(),
          KMByteBlob.cast(authTag).getStartOff(),
          AES_GCM_AUTH_TAG_LENGTH);
      if (ret == 0) {
        break;
      }
      index++;
    }
    if (index >= MAX_BLOB_STORAGE) {
      return false;
    }
    return true;
  }

}
