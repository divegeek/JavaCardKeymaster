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

  private static final short[] customTags  = {
      KMType.ULONG_TAG, KMType.AUTH_TIMEOUT_MILLIS,
  };

  private static final short[] tagArr = {
	        // Unsupported tags.
	        KMType.BOOL_TAG, KMType.TRUSTED_USER_PRESENCE_REQUIRED,
	        KMType.UINT_TAG, KMType.MIN_SEC_BETWEEN_OPS 
	        };

  private static final short[] hwEnforcedTagArr = {
	        // HW Enforced
	        KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,
	        KMType.ENUM_TAG, KMType.ALGORITHM,
	        KMType.UINT_TAG, KMType.KEYSIZE,
	        KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
	        KMType.ENUM_TAG, KMType.BLOB_USAGE_REQ,
	        KMType.ENUM_ARRAY_TAG, KMType.DIGEST,
	        KMType.ENUM_ARRAY_TAG, KMType.PADDING,
	        KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE,
	        KMType.ENUM_ARRAY_TAG, KMType.RSA_OAEP_MGF_DIGEST,
	        KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED,
	        KMType.BOOL_TAG, KMType.CALLER_NONCE,
	        KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
	        KMType.ENUM_TAG, KMType.ECCURVE,
	        KMType.BOOL_TAG, KMType.INCLUDE_UNIQUE_ID,
	        KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE,
	        KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY,
	        KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY,
	        KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT,
	    };

  private static final short[] swEnforcedTagsArr = {
	        KMType.DATE_TAG, KMType.ACTIVE_DATETIME,
	        KMType.DATE_TAG, KMType.ORIGINATION_EXPIRE_DATETIME,
	        KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME,
	        KMType.UINT_TAG, KMType.USERID,
	        KMType.DATE_TAG, KMType.CREATION_DATETIME,
	        KMType.UINT_TAG, KMType.USAGE_COUNT_LIMIT,
	        KMType.BOOL_TAG, KMType.ALLOW_WHILE_ON_BODY,
	        KMType.UINT_TAG, KMType.MAX_BOOT_LEVEL,
	    };

  private static final short[] teeEnforcedTagsArr = {
	        KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID,
	        KMType.UINT_TAG, KMType.AUTH_TIMEOUT,
	        KMType.ENUM_TAG, KMType.USER_AUTH_TYPE,
                KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED,
                KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED,
	    };

  private static final short[] invalidTagsArr = {
	        KMType.BYTES_TAG, KMType.NONCE,
	        KMType.BYTES_TAG, KMType.ASSOCIATED_DATA,
	        KMType.BYTES_TAG, KMType.UNIQUE_ID,
	        KMType.UINT_TAG, KMType.MAC_LENGTH,
	    };

  private KMKeyParameters() {
  }

  private static KMKeyParameters proto(short ptr) {
    if (prototype == null) {
      prototype = new KMKeyParameters();
    }
    KMType.instanceTable[KM_KEY_PARAMETERS_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 11);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMEnum.instance(KMType.RULE, KMType.FAIL_ON_INVALID_TAGS));
    arr.add((short) 1, KMIntegerTag.exp(UINT_TAG));
    arr.add((short) 2, KMIntegerArrayTag.exp(UINT_ARRAY_TAG));
    arr.add((short) 3, KMIntegerTag.exp(ULONG_TAG));
    arr.add((short) 4, KMIntegerTag.exp(DATE_TAG));
    arr.add((short) 5, KMIntegerArrayTag.exp(ULONG_ARRAY_TAG));
    arr.add((short) 6, KMEnumTag.exp());
    arr.add((short) 7, KMEnumArrayTag.exp());
    arr.add((short) 8, KMByteTag.exp());
    arr.add((short) 9, KMBoolTag.exp());
    arr.add((short) 10, KMBignumTag.exp());
    return instance(arrPtr);
  }

  public static short expAny() {
    short arrPtr = KMArray.instance((short) 11);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMEnum.instance(KMType.RULE, KMType.IGNORE_INVALID_TAGS));
    arr.add((short) 1, KMIntegerTag.exp(UINT_TAG));
    arr.add((short) 2, KMIntegerArrayTag.exp(UINT_ARRAY_TAG));
    arr.add((short) 3, KMIntegerTag.exp(ULONG_TAG));
    arr.add((short) 4, KMIntegerTag.exp(DATE_TAG));
    arr.add((short) 5, KMIntegerArrayTag.exp(ULONG_ARRAY_TAG));
    arr.add((short) 6, KMEnumTag.exp());
    arr.add((short) 7, KMEnumArrayTag.exp());
    arr.add((short) 8, KMByteTag.exp());
    arr.add((short) 9, KMBoolTag.exp());
    arr.add((short) 10, KMBignumTag.exp());
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
    return Util.getShort(heap, (short) (KMType.instanceTable[KM_KEY_PARAMETERS_OFFSET] + TLV_HEADER_SIZE));
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
  public static short makeSbEnforced(short keyParamsPtr, byte origin,
      short osVersionObjPtr, short osPatchObjPtr, short vendorPatchObjPtr,
      short bootPatchObjPtr, byte[] scratchPad) {
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

  public static short makeHwEnforced(short sb, short tee){
    short len = KMKeyParameters.cast(sb).length();
    len += KMKeyParameters.cast(tee).length();
    short hwEnf = KMArray.instance(len);
    sb = KMKeyParameters.cast(sb).getVals();
    tee = KMKeyParameters.cast(tee).getVals();
    len = KMArray.cast(sb).length();
    short src = 0;
    short dest =0;
    short val = 0;
    while(src < len){
      val = KMArray.cast(sb).get(src);
      KMArray.cast(hwEnf).add(dest, val);
      src++;
      dest++;
    }
    src = 0;
    len = KMArray.cast(tee).length();
    while(src < len){
      val = KMArray.cast(tee).get(src);
      KMArray.cast(hwEnf).add(dest, val);
      src++;
      dest++;
    }
    return KMKeyParameters.instance(hwEnf);
  }
  // ALL_USERS, EXPORTABLE missing from types.hal
  public static short makeKeystoreEnforced(short keyParamsPtr, byte[] scratchPad) {
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

  public static short makeTeeEnforced(short keyParamsPtr, byte[] scratchPad) {
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
      while (tagInd < (short) teeEnforcedTagsArr.length) {
        if ((teeEnforcedTagsArr[tagInd] == tagType)
            && (teeEnforcedTagsArr[(short) (tagInd + 1)] == tagKey)) {
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
      if (KMByteBlob.cast(appId).length() == 0) {
        appId = KMTag.INVALID_VALUE;
      }
    }
    short appData =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, keyParamsPtr);
    if (appData != KMTag.INVALID_VALUE) {
      appData = KMByteTag.cast(appData).getValue();
      if (KMByteBlob.cast(appData).length() == 0) {
        appData = KMTag.INVALID_VALUE;
      }
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
      KMByteBlob.cast(appDataBlob);
      Util.setShort(scratchPad, index, appDataBlob);
      index += 2;
    }
    return createKeyParameters(scratchPad, (short) (index / 2));

  }

  public static boolean isValidTag(short tagType, short tagKey) {
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

  public static short makeCustomTags(short keyParams, byte[] scratchPad) {
    short index = 0;
    short tagPtr;
    short offset = 0;
    short len = (short) customTags.length;
    short tagType;
    while (index < len) {
      tagType = customTags[(short) (index + 1)];
      switch(tagType) {
        case KMType.AUTH_TIMEOUT_MILLIS:
          short authTimeOutTag =
              KMKeyParameters.cast(keyParams).findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT);
          if (authTimeOutTag != KMType.INVALID_VALUE) {
            tagPtr = createAuthTimeOutMillisTag(authTimeOutTag, scratchPad, offset);
            Util.setShort(scratchPad, offset, tagPtr);
            offset += 2;
          }
          break;
        default:
          break;
      }
      index += 2;
    }
    return createKeyParameters(scratchPad, (short) (offset / 2));
  }

  public void deleteCustomTags() {
    short arrPtr = getVals();
    short index = (short) (customTags.length - 1);
    short obj;
    while (index >= 0) {
      obj = findTag(customTags[(short) (index - 1)], customTags[index]);
      if (obj != KMType.INVALID_VALUE) {
        KMArray.cast(arrPtr).deleteLastEntry();
      }
      index -= 2;
    }
  }

  public static short createAuthTimeOutMillisTag(short authTimeOutTag, byte[] scratchPad, short offset) {
    short authTime = KMIntegerTag.cast(authTimeOutTag).getValue();
    Util.arrayFillNonAtomic(scratchPad, offset, (short) 40, (byte) 0);
    Util.arrayCopyNonAtomic(
        KMInteger.cast(authTime).getBuffer(),
        KMInteger.cast(authTime).getStartOff(),
        scratchPad,
        (short) (offset + 8 - KMInteger.cast(authTime).length()),
        KMInteger.cast(authTime).length());
    KMUtils.convertToMilliseconds(scratchPad, offset, (short) (offset + 8), (short) (offset + 16));
    return KMIntegerTag.instance(KMType.ULONG_TAG, KMType.AUTH_TIMEOUT_MILLIS,
        KMInteger.uint_64(scratchPad, (short) (offset + 8)));
  }
}
