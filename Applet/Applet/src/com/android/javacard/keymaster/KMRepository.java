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
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

// TODO cleanup, move most of the buffers to transient memory with "clear on deselect". Only
//  exception may be OperationState - TBD. The initialize and reset functions will be refactored
//  to handle onInstall and onSelect.

public class KMRepository {
  public static final short HEAP_SIZE = 0x1000;
  private static KMRepository repository;
  private AESKey masterKey;
  private byte[] heap;
  private short heapIndex;

  public static KMRepository instance() {
    if (repository == null) {
      repository = new KMRepository();
    }
    return repository;
  }

  public KMRepository(){
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    // Initialize masterkey - AES 256 bit key.
    if (masterKey == null) {
      masterKey =
        (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }
  }

  public void onUninstall() {
    masterKey = null;
  }

  public void onProcess() {}

  public void clean(){
    Util.arrayFillNonAtomic(heap, (short) 0, heapIndex, (byte) 0);
    heapIndex = 0;
  }

  public void onDeselect() {}

  public void onSelect() {}

  public AESKey getMasterKey() {
    return masterKey;
  }

  public short alloc(short length) {
    if (((short) (heapIndex + length)) > heap.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex += length;
    return (short) (heapIndex - length);
  }

  public byte[] getHeap(){
    return heap;
  }
}
