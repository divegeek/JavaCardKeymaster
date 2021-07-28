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

import javacard.framework.Util;

/**
 * This class represents a tag as defined by keymaster hal specifications. It is composed of key
 * value pair. The key consists of short tag type e.g. KMType.ENUM and short tag key e.g.
 * KMType.ALGORITHM. The key is encoded as uint CBOR type with 4 bytes. This is followed by value
 * which can be any CBOR type based on key. struct{byte tag=KMType.TAG_TYPE, short length, value)
 * where value is subtype of KMTag i.e. struct{short tagType=one of tag types declared in KMType ,
 * short tagKey=one of the tag keys declared in KMType, value} where value is one of the sub-types
 * of KMType.
 */
public class KMTag extends KMType {
  public static short getTagType(short ptr) {
    return Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
  }

  public static short getKey(short ptr) {
    return Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2));
  }

  public static void assertPresence(short params, short tagType, short tagKey, short error){
    if(!isPresent(params, tagType, tagKey)){
      KMException.throwIt(error);
    }
  }
  public static void assertAbsence(short params, short tagType, short tagKey, short error){
    if(isPresent(params, tagType, tagKey)){
      KMException.throwIt(error);
    }
  }

  public static boolean isPresent(short params, short tagType, short tagKey){
    short tag = KMKeyParameters.findTag(tagType, tagKey, params);
    return tag != KMType.INVALID_VALUE;
  }

  public static boolean isEqual(short params, short tagType, short tagKey, short value){
    switch(tagType){
      case KMType.ENUM_TAG:
        return KMEnumTag.getValue(tagKey, params) == value;
      case KMType.UINT_TAG:
      case KMType.DATE_TAG:
      case KMType.ULONG_TAG:
        return KMIntegerTag.isEqual(params, tagType, tagKey, value);
      case KMType.ENUM_ARRAY_TAG:
        return KMEnumArrayTag.contains(tagKey,value,params);
      case KMType.UINT_ARRAY_TAG:
      case KMType.ULONG_ARRAY_TAG:
        return KMIntegerArrayTag.contains(tagKey, value, params);
    }
    return false;
  }
  public static void assertTrue(boolean condition, short error){
    if(!condition){
      KMException.throwIt(error);
    }
  }

  public static boolean isValidPublicExponent(short params) {
    short pubExp = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, params);
    if(pubExp == KMType.INVALID_VALUE){
      return false;
    }
    pubExp = KMIntegerTag.cast(pubExp).getValue();
    if(!(KMInteger.cast(pubExp).getShort() == 0x01 &&
        KMInteger.cast(pubExp).getSignificantShort() == 0x01)){
      return false;
    }
    return true;
  }

  public static boolean isValidKeySize(short params){
    short keysize = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, params);
    if(keysize == KMType.INVALID_VALUE){
      return false;
    }
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, params);
    return KMIntegerTag.cast(keysize).isValidKeySize((byte)alg);
  }
}
