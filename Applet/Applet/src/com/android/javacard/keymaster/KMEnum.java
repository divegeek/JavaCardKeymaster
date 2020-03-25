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

public class KMEnum extends KMType {
  private static short[] types = {HARDWARE_TYPE, KEY_FORMAT, KEY_DERIVATION_FUNCTION};

  private static Object[] enums = null;

  private short type;
  private byte val;

  private KMEnum() {
    init();
  }

  @Override
  public void init() {
    type = 0;
    val = 0;
  }

  @Override
  public short length() {
    return 1;
  }

  public static KMEnum instance() {
    return repository.newEnum();
  }

  public static KMEnum instance(short enumType, byte val) {
    KMEnum inst = repository.newEnum();
    if (!validateEnum(enumType, val)) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    inst.type = enumType;
    inst.val = val;
    return inst;
  }

  public static void create(KMEnum[] enumRefTable) {
    if (enums == null) {
      enums =
          new Object[] {
            new byte[] {SOFTWARE, TRUSTED_ENVIRONMENT,STRONGBOX},
            new byte[] {X509, PKCS8, RAW},
            new byte[] {
              DERIVATION_NONE,
              RFC5869_SHA256,
              ISO18033_2_KDF1_SHA1,
              ISO18033_2_KDF1_SHA256,
              ISO18033_2_KDF2_SHA1,
              ISO18033_2_KDF2_SHA256
            }
          };
    }
    byte index = 0;
    while (index < enumRefTable.length) {
      enumRefTable[index] = new KMEnum();
      index++;
    }
  }

  public KMEnum setVal(byte val) {
    this.val = val;
    return this;
  }

  public byte getVal() {
    return val;
  }

  public KMEnum setType(short type) {
    this.type = type;
    return this;
  }

  public short getType() {
    return type;
  }
  // validate enumeration keys and values.
  private static boolean validateEnum(short key, byte value) {
    // check if key exists
    short index = (short) types.length;
    while (--index >= 0) {
      if (types[index] == key) {
        // check if value given
        if (value != NO_VALUE) {
          // check if the value exist
          byte[] vals = (byte[]) enums[index];
          short enumInd = (short) vals.length;
          while (--enumInd >= 0) {
            if (vals[enumInd] == value) {
              // return true if value exist
              return true;
            }
          }
          // return false if value does not exist
          return false;
        }
        // return true if key exist and value not given
        return true;
      }
    }
    // return false if key does not exist
    return false;
  }
}
