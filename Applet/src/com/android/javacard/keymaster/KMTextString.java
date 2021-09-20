/*
 * Copyright(C) 2021 The Android Open Source Project
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
 * KMTextString represents contiguous block of bytes. It corresponds to CBOR type of Text String. It
 * extends KMByteBlob by specifying value field as zero or more sequence of bytes. struct{ byte
 * TEXT_STR_TYPE; short length; sequence of bytes}
 */
public class KMTextString extends KMByteBlob {
  private static short OFFSET_SIZE = 2;

  private static KMTextString prototype;

  private KMTextString() {
  }

  private static KMTextString proto(short ptr) {
    if (prototype == null) {
      prototype = new KMTextString();
    }
    instanceTable[KM_TEXT_STRING_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    return KMType.exp(TEXT_STRING_TYPE);
  }

  // return an empty byte blob instance
  public static short instance(short length) {
    short ptr = KMType.instance(TEXT_STRING_TYPE, (short) (length + OFFSET_SIZE));
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE),
        (short) (ptr + TLV_HEADER_SIZE + OFFSET_SIZE));
    Util.setShort(heap, (short)(ptr + 1), length);
    return ptr;
  }

  // byte blob from existing buf
  public static short instance(byte[] buf, short startOff, short length) {
    short ptr = instance(length);
    Util.arrayCopyNonAtomic(buf, startOff, heap,
        (short) (ptr + TLV_HEADER_SIZE + OFFSET_SIZE), length);
    return ptr;
  }

  // cast the ptr to KMTextString
  public static KMTextString cast(short ptr) {
    if (heap[ptr] != TEXT_STRING_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  protected short getBaseOffset() {
    return instanceTable[KM_TEXT_STRING_OFFSET];
  }
}
