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

import java.util.Base64.Decoder;
import org.globalplatform.upgrade.Element;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMUpgradable;
import org.globalplatform.upgrade.Element;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * KMRepository class manages volatile memory usage by the applet. Note the
 * repository is only used by applet and it is not intended to be used by seProvider.
 */
public class KMRepository {

  public static final short HEAP_SIZE = 10000;

  // Class Attributes
  private byte[] heap;
  private short[] heapIndex;
  private  static short[] reclaimIndex;

  // Singleton instance
  private static KMRepository repository;

  public static KMRepository instance() {
    return repository;
  }

  public KMRepository(boolean isUpgrading) {
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex[0] = HEAP_SIZE;
    repository = this;
  }

  public void onUninstall() {
    // Javacard Runtime environment cleans up the data.

  }

  public void onProcess() {
  }

  public void clean() {
    Util.arrayFillNonAtomic(heap, (short) 0, HEAP_SIZE, (byte) 0);
    heapIndex[0] = 0;
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

  // Use this function to reset the heapIndex to its previous state.
  // Some of the data might be lost so use it carefully.
  public void setHeapIndex(short offset) {
    if (offset > heapIndex[0] || offset < 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayFillNonAtomic(heap, offset, (short) (heapIndex[0] - offset), (byte) 0);
    heapIndex[0] = offset;
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
    heapIndex[0] = reclaimIndex[0];
    return index;
  }

  public short alloc(short length) {
    if ((((short) (heapIndex[0] + length)) > heap.length) ||
        (((short) (heapIndex[0] + length)) > reclaimIndex[0])) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex[0] += length;
    return (short) (heapIndex[0] - length);
  }

  public byte[] getHeap() {
    return heap;
  }
  
  public short getHeapIndex() {
    return heapIndex[0];
  }
  
  public short getHeapReclaimIndex() {
    return reclaimIndex[0];
  }
}
