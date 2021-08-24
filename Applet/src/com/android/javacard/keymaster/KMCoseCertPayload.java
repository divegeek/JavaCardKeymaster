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
 * KMCoseCertPayload represents the COSE_Sign1 payload for each certificate in BCC. The supported key types are
 * KMInteger, KMNInteger and the supported value types are KMByteBlob and KMTextString.
 * It corresponds to a CBOR Map type. struct{byte TAG_TYPE; short length; short arrayPtr }  where
 * arrayPtr is a pointer to array with any KMCosePairTagType subtype instances.
 */
public class KMCoseCertPayload extends KMCoseMap {

  private static KMCoseCertPayload prototype;

  private KMCoseCertPayload() {
  }

  private static KMCoseCertPayload proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseCertPayload();
    }
    instanceTable[KM_COSE_CERT_PAYLOAD_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 2);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMCosePairTextStringTag.exp());
    arr.add((short) 1, KMCosePairByteBlobTag.exp());
    return KMCoseCertPayload.instance(arrPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(COSE_CERT_PAYLOAD_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMCoseCertPayload cast(short ptr) {
    if (heap[ptr] != COSE_CERT_PAYLOAD_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  @Override
  public short getVals() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_CERT_PAYLOAD_OFFSET] + TLV_HEADER_SIZE));
  }

  @Override
  public short length() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).length();
  }

  @Override
  public void canonicalize() {
    KMCoseMap.canonicalize(getVals());
  }

  private short getValueType(short key, short significantKey) {
    short arr = getVals();
    short length = length();
    short keyPtr;
    short valPtr = 0;
    short index = 0;
    short tagType;
    boolean found = false;
    while (index < length) {
      tagType = KMCosePairTagType.getTagValueType(KMArray.cast(arr).get(index));
      switch (tagType) {
        case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
          keyPtr = KMCosePairByteBlobTag.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == KMCosePairTagType.getKeyValueShort(keyPtr) &&
            significantKey == KMCosePairTagType.getKeyValueSignificantShort(keyPtr)) {
            valPtr = KMCosePairByteBlobTag.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_TEXT_STR_TAG_TYPE:
          keyPtr = KMCosePairTextStringTag.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairTextStringTag.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        default:
          break;

      }
      if (found)
        break;
      index++;
    }
    return valPtr;
  }

  public short getSubjectPublicKey() {
    return getValueType(Util.getShort(KMCose.SUBJECT_PUBLIC_KEY, (short) 2), // LSB
      Util.getShort(KMCose.SUBJECT_PUBLIC_KEY, (short) 0) // MSB (Significant)
    );
  }

  public short getSubject() {
    return getValueType(KMCose.SUBJECT, KMType.INVALID_VALUE);
  }

  public short getIssuer() {
    return getValueType(KMCose.ISSUER, KMType.INVALID_VALUE);
  }

}
