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

/**
 * This class declares all types, tag types, and tag keys. It also establishes basic structure of
 * any KMType i.e. struct{byte type, short length, value} where value can any of the KMType. Also,
 * KMType refers to transient memory heap in the repository. Finally KMType's subtypes are singleton
 * prototype objects which just cast the structure over contiguous memory buffer.
 */
public abstract class KMType {

  public static final short INVALID_VALUE = (short) 0x8000;
  protected static final byte TLV_HEADER_SIZE = 3;

  // Types
  public static final byte BYTE_BLOB_TYPE = 0x01;
  public static final byte INTEGER_TYPE = 0x02;
  public static final byte ENUM_TYPE = 0x03;
  public static final byte TAG_TYPE = 0x04;
  public static final byte ARRAY_TYPE = 0x05;
  public static final byte KEY_PARAM_TYPE = 0x06;
  public static final byte KEY_CHAR_TYPE = 0x07;
  public static final byte HW_AUTH_TOKEN_TYPE = 0x08;
  public static final byte VERIFICATION_TOKEN_TYPE = 0x09;
  public static final byte HMAC_SHARING_PARAM_TYPE = 0x0A;
  public static final byte X509_CERT = 0x0B;
  public static final byte NEG_INTEGER_TYPE = 0x0C;
  public static final byte TEXT_STRING_TYPE = 0x0D;
  public static final byte MAP_TYPE = 0x0E;
  public static final byte COSE_KEY_TYPE = 0x0F;
  public static final byte COSE_PAIR_TAG_TYPE = 0x10;
  public static final byte COSE_PAIR_INT_TAG_TYPE = 0x20;
  public static final byte COSE_PAIR_NEG_INT_TAG_TYPE = 0x30;
  public static final byte COSE_PAIR_BYTE_BLOB_TAG_TYPE = 0x40;
  public static final byte COSE_PAIR_COSE_KEY_TAG_TYPE = 0x60;
  public static final byte COSE_PAIR_SIMPLE_VALUE_TAG_TYPE = 0x70;
  public static final byte COSE_PAIR_TEXT_STR_TAG_TYPE = (byte) 0x80;
  public static final byte SIMPLE_VALUE_TYPE = (byte) 0x90;
  public static final byte COSE_HEADERS_TYPE = (byte) 0xA0;
  public static final byte COSE_CERT_PAYLOAD_TYPE = (byte) 0xB0;
  public static final byte SEMANTIC_TAG_TYPE = (byte) 0xC0;
  // Tag Types
  public static final short INVALID_TAG = 0x0000;
  public static final short ENUM_TAG = 0x1000;
  public static final short ENUM_ARRAY_TAG = 0x2000;
  public static final short UINT_TAG = 0x3000;
  public static final short UINT_ARRAY_TAG = 0x4000;
  public static final short ULONG_TAG = 0x5000;
  public static final short DATE_TAG = 0x6000;
  public static final short BOOL_TAG = 0x7000;
  public static final short BIGNUM_TAG = (short) 0x8000;
  public static final short BYTES_TAG = (short) 0x9000;
  public static final short ULONG_ARRAY_TAG = (short) 0xA000;
  public static final short TAG_TYPE_MASK = (short) 0xF000;

  // Enum Tag
  // Internal tags
  public static final short RULE = 0x7FFF;
  public static final byte IGNORE_INVALID_TAGS = 0x00;
  public static final byte FAIL_ON_INVALID_TAGS = 0x01;

  // Algorithm Enum Tag key and values
  public static final short ALGORITHM = 0x0002;
  public static final byte RSA = 0x01;
  public static final byte DES = 0x21;
  public static final byte EC = 0x03;
  public static final byte AES = 0x20;
  public static final byte HMAC = (byte) 0x80;

  // EcCurve Enum Tag key and values.
  public static final short ECCURVE = 0x000A;
  public static final byte P_224 = 0x00;
  public static final byte P_256 = 0x01;
  public static final byte P_384 = 0x02;
  public static final byte P_521 = 0x03;
  public static final byte CURVE_25519 = 0x04;

  // KeyBlobUsageRequirements Enum Tag key and values.
  public static final short BLOB_USAGE_REQ = 0x012D;
  public static final byte STANDALONE = 0x00;
  public static final byte REQUIRES_FILE_SYSTEM = 0x01;

  // HardwareAuthenticatorType Enum Tag key and values.
  public static final short USER_AUTH_TYPE = 0x01F8;
  public static final byte USER_AUTH_NONE = 0x00;
  public static final byte PASSWORD = 0x01;
  public static final byte FINGERPRINT = 0x02;
  public static final byte BOTH = 0x03;
  // have to be power of 2
  public static final byte ANY = (byte) 0xFF;

  // Origin Enum Tag key and values.
  public static final short ORIGIN = 0x02BE;
  public static final byte GENERATED = 0x00;
  public static final byte DERIVED = 0x01;
  public static final byte IMPORTED = 0x02;
  public static final byte UNKNOWN = 0x03;
  public static final byte SECURELY_IMPORTED = 0x04;

  // Hardware Type tag key and values
  public static final short HARDWARE_TYPE = 0x0130;
  public static final byte SOFTWARE = 0x00;
  public static final byte TRUSTED_ENVIRONMENT = 0x01;
  public static final byte STRONGBOX = 0x02;

  // No Tag
  // Derivation Function - No Tag defined
  public static final short KEY_DERIVATION_FUNCTION = (short) 0xF001;
  public static final byte DERIVATION_NONE = 0x00;
  public static final byte RFC5869_SHA256 = 0x01;
  public static final byte ISO18033_2_KDF1_SHA1 = 0x02;
  public static final byte ISO18033_2_KDF1_SHA256 = 0x03;
  public static final byte ISO18033_2_KDF2_SHA1 = 0x04;
  public static final byte ISO18033_2_KDF2_SHA256 = 0x05;

  // KeyFormat - No Tag defined.
  public static final short KEY_FORMAT = (short) 0xF002;
  public static final byte X509 = 0x00;
  public static final byte PKCS8 = 0x01;
  public static final byte RAW = 0x03;

  // Verified Boot State
  public static final short VERIFIED_BOOT_STATE = (short) 0xF003;
  public static final byte VERIFIED_BOOT = 0x00;
  public static final byte SELF_SIGNED_BOOT = 0x01;
  public static final byte UNVERIFIED_BOOT = 0x02;
  public static final byte FAILED_BOOT = 0x03;

  // Device Locked
  public static final short DEVICE_LOCKED = (short) 0xF006;
  public static final byte DEVICE_LOCKED_TRUE = 0x01;
  public static final byte DEVICE_LOCKED_FALSE = 0x00;

  // Enum Array Tag
  // Purpose
  public static final short PURPOSE = 0x0001;
  public static final byte ENCRYPT = 0x00;
  public static final byte DECRYPT = 0x01;
  public static final byte SIGN = 0x02;
  public static final byte VERIFY = 0x03;
  public static final byte DERIVE_KEY = 0x04;
  public static final byte WRAP_KEY = 0x05;
  public static final byte AGREE_KEY = 0x06;
  public static final byte ATTEST_KEY = (byte) 0x07;
  // Block mode
  public static final short BLOCK_MODE = 0x0004;
  public static final byte ECB = 0x01;
  public static final byte CBC = 0x02;
  public static final byte CTR = 0x03;
  public static final byte GCM = 0x20;

  // Digest
  public static final short DIGEST = 0x0005;
  public static final byte DIGEST_NONE = 0x00;
  public static final byte MD5 = 0x01;
  public static final byte SHA1 = 0x02;
  public static final byte SHA2_224 = 0x03;
  public static final byte SHA2_256 = 0x04;
  public static final byte SHA2_384 = 0x05;
  public static final byte SHA2_512 = 0x06;

  // Padding mode
  public static final short PADDING = 0x0006;
  public static final byte PADDING_NONE = 0x01;
  public static final byte RSA_OAEP = 0x02;
  public static final byte RSA_PSS = 0x03;
  public static final byte RSA_PKCS1_1_5_ENCRYPT = 0x04;
  public static final byte RSA_PKCS1_1_5_SIGN = 0x05;
  public static final byte PKCS7 = 0x40;

  // OAEP MGF Digests - only SHA-1 is supported in Javacard
  public static final short RSA_OAEP_MGF_DIGEST = 0xCB;

  // Integer Tag - UINT, ULONG and DATE
  // UINT tags
  // Keysize
  public static final short KEYSIZE = 0x0003;
  // Min Mac Length
  public static final short MIN_MAC_LENGTH = 0x0008;
  // Min Seconds between OPS
  public static final short MIN_SEC_BETWEEN_OPS = 0x0193;
  // Max Uses per Boot
  public static final short MAX_USES_PER_BOOT = 0x0194;
  // UserId
  public static final short USERID = 0x01F5;
  // Auth Timeout
  public static final short AUTH_TIMEOUT = 0x01F9;
  // Auth Timeout in Milliseconds
  public static final short AUTH_TIMEOUT_MILLIS = 0x7FFF;
  // OS Version
  public static final short OS_VERSION = 0x02C1;
  // OS Patch Level
  public static final short OS_PATCH_LEVEL = 0x02C2;
  // Vendor Patch Level
  public static final short VENDOR_PATCH_LEVEL = 0x02CE;
  // Boot Patch Level
  public static final short BOOT_PATCH_LEVEL = 0x02CF;
  // Mac Length
  public static final short MAC_LENGTH = 0x03EB;
  // Usage Count Limit
  public static final short USAGE_COUNT_LIMIT = 0x195;

  // ULONG tags
  // RSA Public Exponent
  public static final short RSA_PUBLIC_EXPONENT = 0x00C8;

  // DATE tags
  public static final short ACTIVE_DATETIME = 0x0190;
  public static final short ORIGINATION_EXPIRE_DATETIME = 0x0191;
  public static final short USAGE_EXPIRE_DATETIME = 0x0192;
  public static final short CREATION_DATETIME = 0x02BD;;
  public static final short CERTIFICATE_NOT_BEFORE = 0x03F0;
  public static final short CERTIFICATE_NOT_AFTER = 0x03F1;
  // Integer Array Tags - ULONG_REP and UINT_REP.
  // User Secure Id
  public static final short USER_SECURE_ID = (short) 0x01F6;

  // Boolean Tag
  // Caller Nonce
  public static final short CALLER_NONCE = (short) 0x0007;
  // Include Unique Id
  public static final short INCLUDE_UNIQUE_ID = (short) 0x00CA;
  // Bootloader Only
  public static final short BOOTLOADER_ONLY = (short) 0x012E;
  // Rollback Resistance
  public static final short ROLLBACK_RESISTANCE = (short) 0x012F;
  // No Auth Required
  public static final short NO_AUTH_REQUIRED = (short) 0x01F7;
  // Allow While On Body
  public static final short ALLOW_WHILE_ON_BODY = (short) 0x01FA;
  // Max Boot Level
  public static final short MAX_BOOT_LEVEL = (short) 0x03F2;
  // Trusted User Presence Required
  public static final short TRUSTED_USER_PRESENCE_REQUIRED = (short) 0x01FB;
  // Trusted Confirmation Required
  public static final short TRUSTED_CONFIRMATION_REQUIRED = (short) 0x01FC;
  // Unlocked Device Required
  public static final short UNLOCKED_DEVICE_REQUIRED = (short) 0x01FD;
  // Reset Since Id Rotation
  public static final short RESET_SINCE_ID_ROTATION = (short) 0x03EC;
  //Early boot ended.
  public static final short EARLY_BOOT_ONLY = (short) 0x0131;
  //Device unique attestation.
  public static final short DEVICE_UNIQUE_ATTESTATION = (short) 0x02D0;

  // Byte Tag
  // Application Id
  public static final short APPLICATION_ID = (short) 0x0259;
  // Application Data
  public static final short APPLICATION_DATA = (short) 0x02BC;
  // Root Of Trust
  public static final short ROOT_OF_TRUST = (short) 0x02C0;
  // Unique Id
  public static final short UNIQUE_ID = (short) 0x02C3;
  // Attestation Challenge
  public static final short ATTESTATION_CHALLENGE = (short) 0x02C4;
  // Attestation Application Id
  public static final short ATTESTATION_APPLICATION_ID = (short) 0x02C5;
  // Attestation Id Brand
  public static final short ATTESTATION_ID_BRAND = (short) 0x02C6;
  // Attestation Id Device
  public static final short ATTESTATION_ID_DEVICE = (short) 0x02C7;
  // Attestation Id Product
  public static final short ATTESTATION_ID_PRODUCT = (short) 0x02C8;
  // Attestation Id Serial
  public static final short ATTESTATION_ID_SERIAL = (short) 0x02C9;
  // Attestation Id IMEI
  public static final short ATTESTATION_ID_IMEI = (short) 0x02CA;
  // Attestation Id MEID
  public static final short ATTESTATION_ID_MEID = (short) 0x02CB;
  // Attestation Id Manufacturer
  public static final short ATTESTATION_ID_MANUFACTURER = (short) 0x02CC;
  // Attestation Id Model
  public static final short ATTESTATION_ID_MODEL = (short) 0x02CD;
  // Associated Data
  public static final short ASSOCIATED_DATA = (short) 0x03E8;
  // Nonce
  public static final short NONCE = (short) 0x03E9;
  // Confirmation Token
  public static final short CONFIRMATION_TOKEN = (short) 0x03ED;
  // Serial Number - this is a big num but in applet we handle it as byte blob
  public static final short CERTIFICATE_SERIAL_NUM = (short) 0x03EE;
  // Subject Name
  public static final short CERTIFICATE_SUBJECT_NAME = (short) 0x03EF;

  public static final short LENGTH_FROM_PDU = (short) 0xFFFF;

  public static final byte NO_VALUE = (byte) 0xff;
  // Support Curves for Eek Chain validation.
  public static final byte RKP_CURVE_P256 = 1;
  // Type offsets.
  public static final byte KM_TYPE_BASE_OFFSET = 0;
  public static final byte KM_ARRAY_OFFSET = KM_TYPE_BASE_OFFSET;
  public static final byte KM_BOOL_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 1;
  public static final byte KM_BYTE_BLOB_OFFSET = KM_TYPE_BASE_OFFSET + 2;
  public static final byte KM_BYTE_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 3;
  public static final byte KM_ENUM_OFFSET = KM_TYPE_BASE_OFFSET + 4;
  public static final byte KM_ENUM_ARRAY_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 5;
  public static final byte KM_ENUM_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 6;
  public static final byte KM_HARDWARE_AUTH_TOKEN_OFFSET = KM_TYPE_BASE_OFFSET + 7;
  public static final byte KM_HMAC_SHARING_PARAMETERS_OFFSET = KM_TYPE_BASE_OFFSET + 8;
  public static final byte KM_INTEGER_OFFSET = KM_TYPE_BASE_OFFSET + 9;
  public static final byte KM_INTEGER_ARRAY_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 10;
  public static final byte KM_INTEGER_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 11;
  public static final byte KM_KEY_CHARACTERISTICS_OFFSET = KM_TYPE_BASE_OFFSET + 12;
  public static final byte KM_KEY_PARAMETERS_OFFSET = KM_TYPE_BASE_OFFSET + 13;
  public static final byte KM_VERIFICATION_TOKEN_OFFSET = KM_TYPE_BASE_OFFSET + 14;
  public static final byte KM_NEG_INTEGER_OFFSET = KM_TYPE_BASE_OFFSET + 15;
  public static final byte KM_TEXT_STRING_OFFSET = KM_TYPE_BASE_OFFSET + 16;
  public static final byte KM_MAP_OFFSET = KM_TYPE_BASE_OFFSET + 17;
  public static final byte KM_COSE_KEY_OFFSET = KM_TYPE_BASE_OFFSET + 18;
  public static final byte KM_COSE_KEY_INT_VAL_OFFSET = KM_TYPE_BASE_OFFSET + 19;
  public static final byte KM_COSE_KEY_NINT_VAL_OFFSET = KM_TYPE_BASE_OFFSET + 20;
  public static final byte KM_COSE_KEY_BYTE_BLOB_VAL_OFFSET = KM_TYPE_BASE_OFFSET + 21;
  public static final byte KM_COSE_KEY_COSE_KEY_VAL_OFFSET = KM_TYPE_BASE_OFFSET + 22;
  public static final byte KM_COSE_KEY_SIMPLE_VAL_OFFSET = KM_TYPE_BASE_OFFSET + 23;
  public static final byte KM_SIMPLE_VALUE_OFFSET = KM_TYPE_BASE_OFFSET + 24;
  public static final byte KM_COSE_HEADERS_OFFSET = KM_TYPE_BASE_OFFSET + 25;
  public static final byte KM_COSE_KEY_TXT_STR_VAL_OFFSET = KM_TYPE_BASE_OFFSET + 26;
  public static final byte KM_COSE_CERT_PAYLOAD_OFFSET = KM_TYPE_BASE_OFFSET + 27;
  public static final byte KM_BIGNUM_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 28;
  public static final byte KM_SEMANTIC_TAG_OFFSET = KM_TYPE_BASE_OFFSET + 29;

  // Attestation types
  public static final byte NO_CERT = 0;
  public static final byte ATTESTATION_CERT = 1;
  public static final byte SELF_SIGNED_CERT = 2;
  public static final byte FAKE_CERT = 3;
  public static final byte FACTORY_ATTESTATION_CERT = 4;
  // Buffering Mode
  public static final byte BUF_NONE = 0;
  public static final byte BUF_RSA_DECRYPT_OR_NO_DIGEST = 1;
  public static final byte BUF_EC_NO_DIGEST = 2;
  public static final byte BUF_AES_ENCRYPT_PKCS7_BLOCK_ALIGN = 3;
  public static final byte BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGN = 4;
  public static final byte BUF_DES_ENCRYPT_PKCS7_BLOCK_ALIGN = 5;
  public static final byte BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGN = 6;
  public static final byte BUF_AES_GCM_DECRYPT_BLOCK_ALIGN = 7;

  // MAX ApplicationID or Application Data size
  public static final short MAX_APP_ID_APP_DATA_SIZE = 64;
  // Max attestation challenge size.
  public static final short MAX_ATTESTATION_CHALLENGE_SIZE = 128;
  // Max certificate serial size.
  public static final short MAX_CERTIFICATE_SERIAL_SIZE = 20;
  // Attestation Application ID
  public static final short MAX_ATTESTATION_APP_ID_SIZE = 1024;


  protected static KMRepository repository;
  protected static byte[] heap;
  // Instance table
  public static final byte INSTANCE_TABLE_SIZE = 30;
  protected static short[] instanceTable;

  public static void initialize() {
    instanceTable = JCSystem.makeTransientShortArray(INSTANCE_TABLE_SIZE, JCSystem.CLEAR_ON_RESET);
    KMType.repository = KMRepository.instance();
    KMType.heap = repository.getHeap();
  }

  public static byte getType(short ptr) {
    return heap[ptr];
  }

  public static short length(short ptr) {
    return Util.getShort(heap, (short) (ptr + 1));
  }

  public static short getValue(short ptr) {
    return Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
  }

  protected static short instance(byte type, short length) {
    if (length < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short ptr = repository.alloc((short) (length + TLV_HEADER_SIZE));
    heap[ptr] = type;
    Util.setShort(heap, (short) (ptr + 1), length);
    return ptr;
  }

  protected static short exp(byte type) {
    short ptr = repository.alloc(TLV_HEADER_SIZE);
    heap[ptr] = type;
    Util.setShort(heap, (short) (ptr + 1), INVALID_VALUE);
    return ptr;
  }
}
