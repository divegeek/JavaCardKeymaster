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
import javacard.framework.Util;

/**
 * KMByteBlob represents contiguous block of bytes. It corresponds to CBOR type of Byte String. It
 * extends KMType by specifying value field as zero or more sequence of bytes. struct{byte
 * BYTE_BLOB_TYPE; short length; sequence of bytes}
 */
public class KMByteBlob extends KMType {
  private static short OFFSET_SIZE = 2;
  private static KMByteBlob prototype;

  protected KMByteBlob() {
  }

  private static KMByteBlob proto(short ptr) {
    if (prototype == null) {
      prototype = new KMByteBlob();
    }
    KMType.instanceTable[KM_BYTE_BLOB_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    return KMType.exp(BYTE_BLOB_TYPE);
  }

  // return an empty byte blob instance
  public static short instance(short length) {
    short ptr = KMType.instance(BYTE_BLOB_TYPE, (short)(length+2));
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), (short)(ptr+TLV_HEADER_SIZE+OFFSET_SIZE));
    Util.setShort(heap, (short)(ptr + 1), length);
    return ptr;
  }

  // byte blob from existing buf
  public static short instance(byte[] buf, short startOff, short length) {
    short ptr = instance(length);
    Util.arrayCopyNonAtomic(buf, startOff, heap, (short)(ptr+TLV_HEADER_SIZE+OFFSET_SIZE), length);
    return ptr;
  }

  // cast the ptr to KMByteBlob
  public static KMByteBlob cast(short ptr) {
    if (heap[ptr] != BYTE_BLOB_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  // Add the byte
  public void add(short index, byte val) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    heap[(short) (getStartOff() + index)] = val;
  }

  // Get the byte
  public byte get(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return heap[(short) (getStartOff() + index)];
  }

  // Get the start of blob
  public short getStartOff() {
    return Util.getShort(heap, (short)(getBaseOffset() + TLV_HEADER_SIZE));
  }

  // Get the length of the blob
  public short length() {
    return Util.getShort(heap, (short) (getBaseOffset() + 1));
  }

  // Get the buffer pointer in which blob is contained.
  public byte[] getBuffer() {
    return heap;
  }

  public void getValue(byte[] destBuf, short destStart, short destLength) {
    Util.arrayCopyNonAtomic(heap, getStartOff(), destBuf, destStart, destLength);
  }

  public short getValues(byte[] destBuf, short destStart) {
    short destLength = length();
    Util.arrayCopyNonAtomic(heap, getStartOff(), destBuf, destStart, destLength);
    return destLength;
  }

  public void setValue(byte[] srcBuf, short srcStart, short srcLength) {
    if (length() < srcLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.arrayCopyNonAtomic(srcBuf, srcStart, heap, getStartOff(), srcLength);
    setLength(srcLength);
  }

  public boolean isValid() {
    return (length() != 0);
  }

  public void setStartOff(short offset){
    Util.setShort(heap, (short)(getBaseOffset() + TLV_HEADER_SIZE), offset);
  }

  protected short getBaseOffset() {
    return instanceTable[KM_BYTE_BLOB_OFFSET];
  }

  public void setLength(short len){
    Util.setShort(heap, (short)(getBaseOffset() + 1), len);
  }
}
