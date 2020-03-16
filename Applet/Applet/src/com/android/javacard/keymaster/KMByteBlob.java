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
import javacard.framework.Util;

// Byte val represents contiguous memory buffer.
public class KMByteBlob extends KMType {
  private byte[] val;
  private short startOff;
  private short length;

  private KMByteBlob() {
    init();
  }

  @Override
  public void init() {
    length = 0;
    startOff = 0;
    val = null;
  }

  @Override
  public short length() {
    return length;
  }

  public static KMByteBlob instance() {
    return repository.newByteBlob();
  }

  // copy the blob
  public static KMByteBlob instance(byte[] blob, short startOff, short length) {
    if ((length <= 0) || (startOff >= length) || ((short)(startOff+length) > blob.length)) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    KMByteBlob inst = instance(length);
    Util.arrayCopyNonAtomic(blob, startOff, inst.val, inst.startOff, inst.length);
    return inst;
  }

  // returns empty blob with given length
  public static KMByteBlob instance(short length) {
    if (length <= 0) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    KMByteBlob inst = instance();
    inst.startOff = repository.newByteArray(length);
    inst.val = repository.getByteHeapRef();
    inst.length = length;
    return inst;
  }

  public static void create(KMByteBlob[] byteBlobRefTable) {
    byte index = 0;
    while (index < byteBlobRefTable.length) {
      byteBlobRefTable[index] = new KMByteBlob();
      index++;
    }
  }

  // sets the expected length for prototype byte val.
  public KMByteBlob withLength(short len) {
    this.length = len;
    return this;
  }

  public void add(short index, byte val) {
    if (index >= this.length) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    if (this.val == null) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    this.val[(short) (startOff + index)] = val;
  }

  public byte get(short index) {
    if (index >= this.length) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    if (this.val == null) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    return this.val[(short) (startOff + index)];
  }

  public byte[] getVal() {
    return val;
  }

  public short getStartOff() {
    return startOff;
  }
}
