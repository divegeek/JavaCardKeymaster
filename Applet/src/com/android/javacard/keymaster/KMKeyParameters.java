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
 * KMKeyParameters represents KeyParameters structure from android keymaster hal specifications. It
 * corresponds to CBOR map type. struct{byte KEY_PARAM_TYPE; short length=2; short arrayPtr} where
 * arrayPtr is a pointer to array with any KMTag subtype instances.
 */
public class KMKeyParameters extends KMType {

  private static KMKeyParameters prototype;

  private KMKeyParameters() {
  }

  private static KMKeyParameters proto(short ptr) {
    if (prototype == null) {
      prototype = new KMKeyParameters();
    }
    instanceTable[KM_KEY_PARAMETERS_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 9);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMIntegerTag.exp(UINT_TAG));
    arr.add((short) 1, KMIntegerArrayTag.exp(UINT_ARRAY_TAG));
    arr.add((short) 2, KMIntegerTag.exp(ULONG_TAG));
    arr.add((short) 3, KMIntegerTag.exp(DATE_TAG));
    arr.add((short) 4, KMIntegerArrayTag.exp(ULONG_ARRAY_TAG));
    arr.add((short) 5, KMEnumTag.exp());
    arr.add((short) 6, KMEnumArrayTag.exp());
    arr.add((short) 7, KMByteTag.exp());
    arr.add((short) 8, KMBoolTag.exp());
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(KEY_PARAM_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMKeyParameters cast(short ptr) {
    if (heap[ptr] != KEY_PARAM_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getVals() {
    return Util.getShort(heap, (short) (instanceTable[KM_KEY_PARAMETERS_OFFSET] + TLV_HEADER_SIZE));
  }

  public short length() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).length();
  }

  public static short findTag(short tagType, short tagKey, short keyParam) {
    KMKeyParameters instParam = KMKeyParameters.cast(keyParam);
    return instParam.findTag(tagType, tagKey);
  }

  public short findTag(short tagType, short tagKey) {
    KMArray vals = KMArray.cast(getVals());
    short index = 0;
    short length = vals.length();
    short key;
    short type;
    short ret = KMType.INVALID_VALUE;
    short obj;
    while (index < length) {
      obj = vals.get(index);
      key = KMTag.getKey(obj);
      type = KMTag.getTagType(obj);
      if ((tagKey == key) && (tagType == type)) {
        ret = obj;
        break;
      }
      index++;
    }
    return ret;
  }

  public static boolean hasUnsupportedTags(short keyParamsPtr) {
    final short[] tagArr = {
        // Unsupported tags.
        KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED,
        KMType.BOOL_TAG, KMType.TRUSTED_USER_PRESENCE_REQUIRED,
        KMType.BOOL_TAG, KMType.ALLOW_WHILE_ON_BODY,
        KMType.UINT_TAG, KMType.MIN_SEC_BETWEEN_OPS,
        KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT
    };
    byte index = 0;
    short tagInd;
    short tagPtr;
    short tagKey;
    short tagType;
    short arrPtr = KMKeyParameters.cast(keyParamsPtr).getVals();
    short len = KMArray.cast(arrPtr).length();
    while (index < len) {
      tagInd = 0;
      tagPtr = KMArray.cast(arrPtr).get(index);
      tagKey = KMTag.getKey(tagPtr);
      tagType = KMTag.getTagType(tagPtr);
      while (tagInd < (short) tagArr.length) {
        if ((tagArr[tagInd] == tagType)
            && (tagArr[(short) (tagInd + 1)] == tagKey)) {
          return true;
        }
        tagInd += 2;
      }
      index++;
    }
    return false;
  }

  // KDF, ECIES_SINGLE_HASH_MODE missing from types.hal
  public static short makeHwEnforced(short keyParamsPtr, byte origin,
      short osVersionObjPtr, short osPatchObjPtr, short vendorPatchObjPtr,
      short bootPatchObjPtr, byte[] scratchPad) {
    final short[] hwEnforcedTagArr = {
        // HW Enforced
        KMType.ENUM_TAG, KMType.ORIGIN,
        KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,
        KMType.ENUM_TAG, KMType.ALGORITHM,
        KMType.UINT_TAG, KMType.KEYSIZE,
        KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
        KMType.ENUM_TAG, KMType.BLOB_USAGE_REQ,
        KMType.ENUM_ARRAY_TAG, KMType.DIGEST,
        KMType.ENUM_ARRAY_TAG, KMType.PADDING,
        KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE,
        KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID,
        KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED,
        KMType.UINT_TAG, KMType.AUTH_TIMEOUT,
        KMType.BOOL_TAG, KMType.CALLER_NONCE,
        KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
        KMType.ENUM_TAG, KMType.ECCURVE,
        KMType.BOOL_TAG, KMType.INCLUDE_UNIQUE_ID,
        KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE,
        KMType.ENUM_TAG, KMType.USER_AUTH_TYPE,
        KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED,
        KMType.BOOL_TAG, KMType.RESET_SINCE_ID_ROTATION
    };
    byte index = 0;
    short tagInd;
    short arrInd = 0;
    short tagPtr;
    short tagKey;
    short tagType;
    short arrPtr = KMKeyParameters.cast(keyParamsPtr).getVals();
    short len = KMArray.cast(arrPtr).length();
    while (index < len) {
      tagInd = 0;
      tagPtr = KMArray.cast(arrPtr).get(index);
      tagKey = KMTag.getKey(tagPtr);
      tagType = KMTag.getTagType(tagPtr);
      if (!isValidTag(tagType, tagKey)) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      while (tagInd < (short) hwEnforcedTagArr.length) {
        if ((hwEnforcedTagArr[tagInd] == tagType)
            && (hwEnforcedTagArr[(short) (tagInd + 1)] == tagKey)) {
          Util.setShort(scratchPad, arrInd, tagPtr);
          arrInd += 2;
          break;
        }
        tagInd += 2;
      }
      index++;
    }
    short originTag = KMEnumTag.instance(KMType.ORIGIN, origin);
    Util.setShort(scratchPad, arrInd, originTag);
    arrInd += 2;
    short osVersionTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.OS_VERSION, osVersionObjPtr);
    Util.setShort(scratchPad, arrInd, osVersionTag);
    arrInd += 2;
    short osPatchTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, osPatchObjPtr);
    Util.setShort(scratchPad, arrInd, osPatchTag);
    arrInd += 2;
    short vendorPatchTag = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.VENDOR_PATCH_LEVEL, vendorPatchObjPtr);
    Util.setShort(scratchPad, arrInd, vendorPatchTag);
    arrInd += 2;
    short bootPatchTag = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.BOOT_PATCH_LEVEL, bootPatchObjPtr);
    Util.setShort(scratchPad, arrInd, bootPatchTag);
    arrInd += 2;
    return createKeyParameters(scratchPad, (short) (arrInd / 2));
  }

  // ALL_USERS, EXPORTABLE missing from types.hal
  public static short makeSwEnforced(short keyParamsPtr, byte[] scratchPad) {
    final short[] swEnforcedTagsArr = {
        KMType.DATE_TAG, KMType.ACTIVE_DATETIME,
        KMType.DATE_TAG, KMType.ORIGINATION_EXPIRE_DATETIME,
        KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME,
        KMType.UINT_TAG, KMType.USERID,
        KMType.DATE_TAG, KMType.CREATION_DATETIME
    };
    byte index = 0;
    short tagInd;
    short arrInd = 0;
    short tagPtr;
    short tagKey;
    short tagType;
    short arrPtr = KMKeyParameters.cast(keyParamsPtr).getVals();
    short len = KMArray.cast(arrPtr).length();
    while (index < len) {
      tagInd = 0;
      tagPtr = KMArray.cast(arrPtr).get(index);
      tagKey = KMTag.getKey(tagPtr);
      tagType = KMTag.getTagType(tagPtr);
      if (!isValidTag(tagType, tagKey)) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      while (tagInd < (short) swEnforcedTagsArr.length) {
        if ((swEnforcedTagsArr[tagInd] == tagType)
            && (swEnforcedTagsArr[(short) (tagInd + 1)] == tagKey)) {
          Util.setShort(scratchPad, arrInd, tagPtr);
          arrInd += 2;
          break;
        }
        tagInd += 2;
      }
      index++;
    }
    return createKeyParameters(scratchPad, (short) (arrInd / 2));
  }

  public static short makeHidden(short keyParamsPtr, short rootOfTrustBlob, byte[] scratchPad) {
    short appId = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, keyParamsPtr);
    if (appId != KMTag.INVALID_VALUE) {
      appId = KMByteTag.cast(appId).getValue();
    }
    short appData =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, keyParamsPtr);
    if (appData != KMTag.INVALID_VALUE) {
      appData = KMByteTag.cast(appData).getValue();
    }
    return makeHidden(appId, appData, rootOfTrustBlob, scratchPad);
  }

  public static short makeHidden(short appIdBlob, short appDataBlob, short rootOfTrustBlob,
      byte[] scratchPad) {
    // Order in which the hidden array is created should not change.
    short index = 0;
    KMByteBlob.cast(rootOfTrustBlob);
    Util.setShort(scratchPad, index, rootOfTrustBlob);
    index += 2;
    if (appIdBlob != KMTag.INVALID_VALUE) {
      KMByteBlob.cast(appIdBlob);
      Util.setShort(scratchPad, index, appIdBlob);
      index += 2;
    }
    if (appDataBlob != KMTag.INVALID_VALUE) {
      Util.setShort(scratchPad, index, appDataBlob);
      index += 2;
    }
    return createKeyParameters(scratchPad, (short) (index / 2));

  }

  public static boolean isValidTag(short tagType, short tagKey) {
    short[] invalidTagsArr = {
        KMType.BYTES_TAG, KMType.NONCE,
        KMType.BYTES_TAG, KMType.ASSOCIATED_DATA,
        KMType.BYTES_TAG, KMType.UNIQUE_ID,
        KMType.UINT_TAG, KMType.MAC_LENGTH,
        KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY
    };
    short index = 0;
    if (tagKey == KMType.INVALID_TAG) {
      return false;
    }
    while (index < invalidTagsArr.length) {
      if ((tagType == invalidTagsArr[index]) && (tagKey == invalidTagsArr[(short) (index + 1)])) {
        return false;
      }
      index += 2;
    }
    return true;
  }

  public static short createKeyParameters(byte[] ptrArr, short len) {
    short arrPtr = KMArray.instance(len);
    short index = 0;
    short ptr = 0;
    while (index < len) {
      KMArray.cast(arrPtr).add(index, Util.getShort(ptrArr, ptr));
      index++;
      ptr += 2;
    }
    return KMKeyParameters.instance(arrPtr);
  }
}
