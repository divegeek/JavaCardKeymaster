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
package com.android.javacard.kmdevice;

public class KMDataStoreConstants {

  public static final byte ATT_ID_BRAND = 0;
  public static final byte ATT_ID_DEVICE = 1;
  public static final byte ATT_ID_PRODUCT = 2;
  public static final byte ATT_ID_SERIAL = 3;
  public static final byte ATT_ID_IMEI = 4;
  public static final byte ATT_ID_MEID = 5;
  public static final byte ATT_ID_MANUFACTURER = 6;
  public static final byte ATT_ID_MODEL = 7;
  public static final byte COMPUTED_HMAC_KEY = 8;
  public static final byte HMAC_NONCE = 9;
  public static final byte CERT_ISSUER = 10;
  public static final byte CERT_EXPIRY_TIME = 11;
  public static final byte OS_VERSION = 12;
  public static final byte OS_PATCH_LEVEL = 13;
  public static final byte VENDOR_PATCH_LEVEL = 14;
  public static final byte DEVICE_LOCKED_TIME = 15;
  public static final byte DEVICE_LOCKED = 16;
  public static final byte DEVICE_LOCKED_PASSWORD_ONLY = 17;
  public static final byte BOOT_ENDED_STATUS = 18;
  public static final byte EARLY_BOOT_ENDED_STATUS = 19;
  public static final byte PROVISIONED_LOCKED = 20;
  public static final byte PROVISIONED_STATUS = 21;
  public static final byte MASTER_KEY = 22;
  public static final byte PRE_SHARED_KEY = 23;
  public static final byte ATTESTATION_KEY = 24;
  public static final byte AUTH_TAG_1 = 25;
  public static final byte AUTH_TAG_2 = 26;
  public static final byte AUTH_TAG_3 = 27;
  public static final byte AUTH_TAG_4 = 28;
  public static final byte AUTH_TAG_5 = 29;
  public static final byte AUTH_TAG_6 = 30;
  public static final byte AUTH_TAG_7 = 31;
  public static final byte AUTH_TAG_8 = 32;
  public static final byte ADDITIONAL_CERT_CHAIN = 33;
  public static final byte BOOT_CERT_CHAIN = 34;

  //certificate data constants.
  public static final byte CERTIFICATE_CHAIN = 0;
  public static final byte CERTIFICATE_EXPIRY = 1;
  public static final byte CERTIFICATE_ISSUER = 2;

  // INTERFACE Types
  public static final byte INTERFACE_TYPE_COMPUTED_HMAC_KEY = 0x01;
  public static final byte INTERFACE_TYPE_ATTESTATION_KEY = 0x02;
  public static final byte INTERFACE_TYPE_DEVICE_UNIQUE_KEY = 0x03;
  public static final byte INTERFACE_TYPE_MASTER_KEY = 0x04;
  public static final byte INTERFACE_TYPE_PRE_SHARED_KEY = 0x05;


}
