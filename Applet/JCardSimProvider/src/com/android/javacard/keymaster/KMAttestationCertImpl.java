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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMAESKey;
import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMMasterKey;
import com.android.javacard.seprovider.KMSEProvider;

import javacard.framework.JCSystem;
import javacard.framework.Util;

// The class encodes strongbox generated amd signed attestation certificate. This only encodes
// required fields of the certificates. It is not meant to be generic X509 cert encoder.
// Whatever fields that are fixed are added as byte arrays. The Extensions are encoded as per
// the values.
// The certificate is assembled with leafs first and then the sequences.

public class KMAttestationCertImpl implements KMAttestationCert {

  private static final byte MAX_PARAMS = 30;
  // DER encoded object identifiers required by the cert.
  // rsaEncryption - 1.2.840.113549.1.1.1
  private static final byte[] rsaEncryption = {
      0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01
  };
  // ecPublicKey -  1.2.840.10045.2.1
  private static final byte[] eccPubKey = {
      0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01
  };
  // prime256v1 curve - 1.2.840.10045.3.1.7
  private static final byte[] prime256v1 = {
      0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07
  };
  // Key Usage Extn - 2.5.29.15
  private static final byte[] keyUsageExtn = {0x06, 0x03, 0x55, 0x1D, 0x0F};
  // Android Extn - 1.3.6.1.4.1.11129.2.1.17
  private static final byte[] androidExtn = {
      0x06, 0x0A, 0X2B, 0X06, 0X01, 0X04, 0X01, (byte) 0XD6, 0X79, 0X02, 0X01, 0X11
  };
  private static final short RSA_SIG_LEN = 256;
  private static final byte ECDSA_MAX_SIG_LEN = 72;
  //Signature algorithm identifier - ecdsaWithSha256 - 1.2.840.10045.4.3.2
  //SEQUENCE of alg OBJ ID and parameters = NULL.
  private static final byte[] X509EcdsaSignAlgIdentifier = {
      0x30,
      0x0A,
      0x06,
      0x08,
      0x2A,
      (byte) 0x86,
      0x48,
      (byte) 0xCE,
      (byte) 0x3D,
      0x04,
      0x03,
      0x02
  };
  // Signature algorithm identifier - sha256WithRSAEncryption - 1.2.840.113549.1.1.11
  // SEQUENCE of alg OBJ ID and parameters = NULL.
  private static final byte[] X509RsaSignAlgIdentifier = {
      0x30,
      0x0D,
      0x06,
      0x09,
      0x2A,
      (byte) 0x86,
      0x48,
      (byte) 0x86,
      (byte) 0xF7,
      0x0D,
      0x01,
      0x01,
      0x0B,
      0x05,
      0x00
  };


  // Below are the allowed softwareEnforced Authorization tags inside the attestation certificate's extension.
  private static final short[] swTagIds = {
      KMType.ATTESTATION_APPLICATION_ID,
      KMType.CREATION_DATETIME,
      KMType.ALLOW_WHILE_ON_BODY,
      KMType.USAGE_COUNT_LIMIT,
      KMType.USAGE_EXPIRE_DATETIME,
      KMType.ORIGINATION_EXPIRE_DATETIME,
      KMType.ACTIVE_DATETIME,
  };

  // Below are the allowed hardwareEnforced Authorization tags inside the attestation certificate's extension.
  private static final short[] hwTagIds = {
      KMType.ATTESTATION_ID_SECOND_IMEI,
      KMType.BOOT_PATCH_LEVEL, KMType.VENDOR_PATCH_LEVEL,
      KMType.ATTESTATION_ID_MODEL, KMType.ATTESTATION_ID_MANUFACTURER,
      KMType.ATTESTATION_ID_MEID, KMType.ATTESTATION_ID_IMEI,
      KMType.ATTESTATION_ID_SERIAL, KMType.ATTESTATION_ID_PRODUCT,
      KMType.ATTESTATION_ID_DEVICE, KMType.ATTESTATION_ID_BRAND,
      KMType.OS_PATCH_LEVEL, KMType.OS_VERSION, KMType.ROOT_OF_TRUST,
      KMType.ORIGIN, KMType.UNLOCKED_DEVICE_REQUIRED,
      KMType.TRUSTED_CONFIRMATION_REQUIRED,
      KMType.AUTH_TIMEOUT, KMType.USER_AUTH_TYPE,
      KMType.NO_AUTH_REQUIRED, KMType.EARLY_BOOT_ONLY,
      KMType.ROLLBACK_RESISTANCE, KMType.RSA_OAEP_MGF_DIGEST,
      KMType.RSA_PUBLIC_EXPONENT, KMType.ECCURVE,
      KMType.PADDING, KMType.DIGEST,
      KMType.KEYSIZE, KMType.ALGORITHM, KMType.PURPOSE
  };

  private static final byte keyUsageSign = (byte) 0x80; // 0 bit
  private static final byte keyUsageKeyEncipher = (byte) 0x20; // 2nd- bit
  private static final byte keyUsageDataEncipher = (byte) 0x10; // 3rd- bit
  private static final byte keyUsageKeyAgreement = (byte) 0x08; // 4th- bit
  private static final byte keyUsageCertSign = (byte) 0x04; // 5th- bit

  private static final short KEYMINT_VERSION = 300;
  private static final short ATTESTATION_VERSION = 300;
  private static final byte[] pubExponent = {0x01, 0x00, 0x01};
  private static final byte X509_VERSION = (byte) 0x02;

  // Buffer indexes in transient array
  private static final byte NUM_INDEX_ENTRIES = 21;
  private static final byte CERT_START = (byte) 0;
  private static final byte CERT_LENGTH = (byte) 1;
  private static final byte TBS_START = (byte) 2;
  private static final byte TBS_LENGTH = (byte) 3;
  private static final byte BUF_START = (byte) 4;
  private static final byte BUF_LENGTH = (byte) 5;
  private static final byte SW_PARAM_INDEX = (byte) 6;
  private static final byte HW_PARAM_INDEX = (byte) 7;
  // Data indexes in transient array
  private static final byte STACK_PTR = (byte) 8;
  private static final byte UNIQUE_ID = (byte) 9;
  private static final byte ATT_CHALLENGE = (byte) 10;
  private static final byte NOT_BEFORE = (byte) 11;
  private static final byte NOT_AFTER = (byte) 12;
  private static final byte PUB_KEY = (byte) 13;
  private static final byte VERIFIED_BOOT_KEY = (byte) 14;
  private static final byte VERIFIED_HASH = (byte) 15;
  private static final byte ISSUER = (byte) 16;
  private static final byte SUBJECT_NAME = (byte) 17;
  private static final byte SERIAL_NUMBER = (byte) 18;
  private static final byte CERT_ATT_KEY_SECRET = (byte) 19;
  private static final byte CERT_ATT_KEY_RSA_PUB_MOD = (byte) 20;
  // State indexes in transient array
  private static final byte NUM_STATE_ENTRIES = 7;
  private static final byte KEY_USAGE = (byte) 0;
  private static final byte UNUSED_BITS = (byte) 1;
  private static final byte DEVICE_LOCKED = (byte) 2;
  private static final byte VERIFIED_STATE = (byte) 3;
  private static final byte CERT_MODE = (byte) 4;
  private static final byte RSA_CERT = (byte) 5;
  private static final byte CERT_RSA_SIGN = (byte) 6;

  private static KMAttestationCert inst;
  private static KMSEProvider seProvider;

  private static short[] indexes;
  private static byte[] states;

  private static byte[] stack;
  private static short[] swParams;
  private static short[] hwParams;

  private static final byte SERIAL_NUM_MAX_LEN = 20;

  private KMAttestationCertImpl() {
  }

  public static KMAttestationCert instance(boolean rsaCert, KMSEProvider provider) {
    if (inst == null) {
      inst = new KMAttestationCertImpl();
      seProvider = provider;

      // Allocate transient memory
      indexes = JCSystem.makeTransientShortArray(NUM_INDEX_ENTRIES, JCSystem.CLEAR_ON_RESET);
      states = JCSystem.makeTransientByteArray(NUM_STATE_ENTRIES, JCSystem.CLEAR_ON_RESET);
      swParams = JCSystem.makeTransientShortArray(MAX_PARAMS, JCSystem.CLEAR_ON_RESET);
      hwParams = JCSystem.makeTransientShortArray(MAX_PARAMS, JCSystem.CLEAR_ON_RESET);
    }
    init(rsaCert);
    return inst;
  }

  private static void init(boolean rsaCert) {
    for (short i = 0; i < NUM_INDEX_ENTRIES; i++) {
      indexes[i] = 0;
    }
    Util.arrayFillNonAtomic(states, (short) 0, NUM_STATE_ENTRIES, (byte) 0);
    stack = null;
    states[CERT_MODE] = KMType.NO_CERT;
    states[UNUSED_BITS] = 8;
    states[RSA_CERT] = rsaCert ? (byte) 1 : (byte) 0;
    states[CERT_RSA_SIGN] = 1;
    indexes[CERT_ATT_KEY_SECRET] = KMType.INVALID_VALUE;
    indexes[CERT_ATT_KEY_RSA_PUB_MOD] = KMType.INVALID_VALUE;
    indexes[ISSUER] = KMType.INVALID_VALUE;
    indexes[SUBJECT_NAME] = KMType.INVALID_VALUE;
    indexes[SERIAL_NUMBER] = KMType.INVALID_VALUE;
  }

  @Override
  public KMAttestationCert verifiedBootHash(short obj) {
    indexes[VERIFIED_HASH] = obj;
    return this;
  }

  @Override
  public KMAttestationCert verifiedBootKey(short obj) {
    indexes[VERIFIED_BOOT_KEY] = obj;
    return this;
  }

  @Override
  public KMAttestationCert verifiedBootState(byte val) {
    states[VERIFIED_STATE] = val;
    return this;
  }

  private KMAttestationCert uniqueId(short obj) {
    indexes[UNIQUE_ID] = obj;
    return this;
  }

  @Override
  public KMAttestationCert notBefore(short obj, boolean derEncoded, byte[] scratchpad) {
    if (!derEncoded) {
      // convert milliseconds to UTC date
      indexes[NOT_BEFORE] = KMUtils.convertToDate(obj, scratchpad, true);
    } else {
      indexes[NOT_BEFORE] = KMByteBlob.instance(KMByteBlob.cast(obj).getBuffer(),
          KMByteBlob.cast(obj).getStartOff(), KMByteBlob.cast(obj).length());
    }
    return this;
  }

  @Override
  public KMAttestationCert notAfter(short usageExpiryTimeObj, boolean derEncoded,
      byte[] scratchPad) {
    if (!derEncoded) {
      if (usageExpiryTimeObj != KMType.INVALID_VALUE) {
        // compare if the expiry time is greater then 2050 then use generalized
        // time format else use utc time format.
        short tmpVar = KMInteger.uint_64(KMUtils.firstJan2050, (short) 0);
        if (KMInteger.compare(usageExpiryTimeObj, tmpVar) >= 0) {
          usageExpiryTimeObj = KMUtils.convertToDate(usageExpiryTimeObj, scratchPad,
              false);
        } else {
          usageExpiryTimeObj = KMUtils
              .convertToDate(usageExpiryTimeObj, scratchPad, true);
        }
        indexes[NOT_AFTER] = usageExpiryTimeObj;
      } else {
        //notAfter = certExpirtyTimeObj;
      }
    } else {
      indexes[NOT_AFTER] = usageExpiryTimeObj;
    }
    return this;
  }

  @Override
  public KMAttestationCert deviceLocked(boolean val) {
    if (val) {
      states[DEVICE_LOCKED] = (byte) 0xFF;
    } else {
      states[DEVICE_LOCKED] = 0;
    }
    return this;
  }

  @Override
  public KMAttestationCert publicKey(short obj) {
    indexes[PUB_KEY] = obj;
    return this;
  }

  @Override
  public KMAttestationCert attestationChallenge(short obj) {
    indexes[ATT_CHALLENGE] = obj;
    return this;
  }

  @Override
  public KMAttestationCert extensionTag(short tag, boolean hwEnforced) {
    if (hwEnforced) {
      hwParams[indexes[HW_PARAM_INDEX]] = tag;
      indexes[HW_PARAM_INDEX]++;
    } else {
      swParams[indexes[SW_PARAM_INDEX]] = tag;
      indexes[SW_PARAM_INDEX]++;
    }
    if (KMTag.getKey(tag) == KMType.PURPOSE) {
      createKeyUsage(tag);
    }
    return this;
  }

  @Override
  public KMAttestationCert issuer(short obj) {
    indexes[ISSUER] = obj;
    return this;
  }

  private void createKeyUsage(short tag) {
    short len = KMEnumArrayTag.cast(tag).length();
    byte index = 0;
    while (index < len) {
      if (KMEnumArrayTag.cast(tag).get(index) == KMType.SIGN) {
        states[KEY_USAGE] = (byte) (states[KEY_USAGE] | keyUsageSign);
      } else if (KMEnumArrayTag.cast(tag).get(index) == KMType.WRAP_KEY) {
        states[KEY_USAGE] = (byte) (states[KEY_USAGE] | keyUsageKeyEncipher);
      } else if (KMEnumArrayTag.cast(tag).get(index) == KMType.DECRYPT) {
        states[KEY_USAGE] = (byte) (states[KEY_USAGE] | keyUsageDataEncipher);
      } else if (KMEnumArrayTag.cast(tag).get(index) == KMType.AGREE_KEY) {
        states[KEY_USAGE] = (byte) (states[KEY_USAGE] | keyUsageKeyAgreement);
      } else if (KMEnumArrayTag.cast(tag).get(index) == KMType.ATTEST_KEY) {
        states[KEY_USAGE] = (byte) (states[KEY_USAGE] | keyUsageCertSign);
      }
      index++;
    }
    index = states[KEY_USAGE];
    while (index != 0) {
      index = (byte) (index << 1);
      states[UNUSED_BITS]--;
    }
  }

  private static void pushTbsCert(boolean rsaCert, boolean rsa) {
    short last = indexes[STACK_PTR];
    pushExtensions();
    // subject public key info
    if (rsaCert) {
      pushRsaSubjectKeyInfo();
    } else {
      pushEccSubjectKeyInfo();
    }
    // subject
    pushBytes(KMByteBlob.cast(indexes[SUBJECT_NAME]).getBuffer(),
        KMByteBlob.cast(indexes[SUBJECT_NAME]).getStartOff(),
        KMByteBlob.cast(indexes[SUBJECT_NAME]).length());
    pushValidity();
    // issuer - der encoded
    pushBytes(
        KMByteBlob.cast(indexes[ISSUER]).getBuffer(),
        KMByteBlob.cast(indexes[ISSUER]).getStartOff(),
        KMByteBlob.cast(indexes[ISSUER]).length());
    // Algorithm Id
    if (rsa) {
      pushAlgorithmId(X509RsaSignAlgIdentifier);
    } else {
      pushAlgorithmId(X509EcdsaSignAlgIdentifier);
    }
    // Serial Number
    pushBytes(KMByteBlob.cast(indexes[SERIAL_NUMBER]).getBuffer(),
        KMByteBlob.cast(indexes[SERIAL_NUMBER]).getStartOff(),
        KMByteBlob.cast(indexes[SERIAL_NUMBER]).length());
    pushIntegerHeader(KMByteBlob.cast(indexes[SERIAL_NUMBER]).length());
    // Version
    pushByte(X509_VERSION);
    pushIntegerHeader((short) 1);
    pushByte((byte) 0x03);
    pushByte((byte) 0xA0);
    // Finally sequence header.
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushExtensions() {
    short last = indexes[STACK_PTR];
    // Push KeyUsage extension
    if (states[KEY_USAGE] != 0) {
      pushKeyUsage(states[KEY_USAGE], states[UNUSED_BITS]);
    }
    if (states[CERT_MODE] == KMType.ATTESTATION_CERT) {
      pushKeyDescription();
    }
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
    // Extensions have explicit tag of [3]
    pushLength((short) (last - indexes[STACK_PTR]));
    pushByte((byte) 0xA3);
  }

  // Time SEQUENCE{UTCTime, UTC or Generalized Time)
  private static void pushValidity() {
    short last = indexes[STACK_PTR];
    if (indexes[NOT_AFTER] != 0) {
      pushBytes(
          KMByteBlob.cast(indexes[NOT_AFTER]).getBuffer(),
          KMByteBlob.cast(indexes[NOT_AFTER]).getStartOff(),
          KMByteBlob.cast(indexes[NOT_AFTER]).length());
    } else {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    pushTimeHeader(KMByteBlob.cast(indexes[NOT_AFTER]).length());
    pushBytes(
        KMByteBlob.cast(indexes[NOT_BEFORE]).getBuffer(),
        KMByteBlob.cast(indexes[NOT_BEFORE]).getStartOff(),
        KMByteBlob.cast(indexes[NOT_BEFORE]).length());
    pushTimeHeader(KMByteBlob.cast(indexes[NOT_BEFORE]).length());
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushTimeHeader(short len) {
    if (len == 13) { // UTC Time
      pushLength((short) 0x0D);
      pushByte((byte) 0x17);
    } else if (len == 15) { // Generalized Time
      pushLength((short) 0x0F);
      pushByte((byte) 0x18);
    } else {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
  }

  // SEQUENCE{SEQUENCE{algId, NULL}, bitString{SEQUENCE{ modulus as positive integer, public
  // exponent
  // as positive integer}
  private static void pushRsaSubjectKeyInfo() {
    short last = indexes[STACK_PTR];
    pushBytes(pubExponent, (short) 0, (short) pubExponent.length);
    pushIntegerHeader((short) pubExponent.length);
    pushBytes(
        KMByteBlob.cast(indexes[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(indexes[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(indexes[PUB_KEY]).length());

    // encode modulus as positive if the MSB is 1.
    if (KMByteBlob.cast(indexes[PUB_KEY]).get((short) 0) < 0) {
      pushByte((byte) 0x00);
      pushIntegerHeader((short) (KMByteBlob.cast(indexes[PUB_KEY]).length() + 1));
    } else {
      pushIntegerHeader(KMByteBlob.cast(indexes[PUB_KEY]).length());
    }
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
    pushBitStringHeader((byte) 0x00, (short) (last - indexes[STACK_PTR]));
    pushRsaEncryption();
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  // SEQUENCE{SEQUENCE{ecPubKey, prime256v1}, bitString{pubKey}}
  private static void pushEccSubjectKeyInfo() {
    short last = indexes[STACK_PTR];
    pushBytes(
        KMByteBlob.cast(indexes[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(indexes[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(indexes[PUB_KEY]).length());
    pushBitStringHeader((byte) 0x00, KMByteBlob.cast(indexes[PUB_KEY]).length());
    pushEcDsa();
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushEcDsa() {
    short last = indexes[STACK_PTR];
    pushBytes(prime256v1, (short) 0, (short) prime256v1.length);
    pushBytes(eccPubKey, (short) 0, (short) eccPubKey.length);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushRsaEncryption() {
    short last = indexes[STACK_PTR];
    pushNullHeader();
    pushBytes(rsaEncryption, (short) 0, (short) rsaEncryption.length);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  // KeyDescription ::= SEQUENCE {
  //         attestationVersion         INTEGER, # Value 200
  //         attestationSecurityLevel   SecurityLevel, # See below
  //         keymasterVersion           INTEGER, # Value 200
  //         keymasterSecurityLevel     SecurityLevel, # See below
  //         attestationChallenge       OCTET_STRING, # Tag::ATTESTATION_CHALLENGE from attestParams
  //         uniqueId                   OCTET_STRING, # Empty unless key has Tag::INCLUDE_UNIQUE_ID
  //         softwareEnforced           AuthorizationList, # See below
  //         hardwareEnforced           AuthorizationList, # See below
  //     }
  private static void pushKeyDescription() {
    short last = indexes[STACK_PTR];
    pushHWParams();
    pushSWParams();
    if (indexes[UNIQUE_ID] != 0) {
      pushOctetString(
          KMByteBlob.cast(indexes[UNIQUE_ID]).getBuffer(),
          KMByteBlob.cast(indexes[UNIQUE_ID]).getStartOff(),
          KMByteBlob.cast(indexes[UNIQUE_ID]).length());
    } else {
      pushOctetStringHeader((short) 0);
    }
    pushOctetString(
        KMByteBlob.cast(indexes[ATT_CHALLENGE]).getBuffer(),
        KMByteBlob.cast(indexes[ATT_CHALLENGE]).getStartOff(),
        KMByteBlob.cast(indexes[ATT_CHALLENGE]).length());
    pushEnumerated(KMType.STRONGBOX);
    pushShort(KEYMINT_VERSION);
    pushIntegerHeader((short) 2);
    pushEnumerated(KMType.STRONGBOX);
    pushShort(ATTESTATION_VERSION);
    pushIntegerHeader((short) 2);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
    pushOctetStringHeader((short) (last - indexes[STACK_PTR]));
    pushBytes(androidExtn, (short) 0, (short) androidExtn.length);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushSWParams() {
    short last = indexes[STACK_PTR];
    byte index = 0;
    short length = (short) swTagIds.length;
    do {
      pushParams(swParams, indexes[SW_PARAM_INDEX], swTagIds[index]);
    } while (++index < length);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushHWParams() {
    short last = indexes[STACK_PTR];
    byte index = 0;
    short length = (short) hwTagIds.length;
    do {
      if (hwTagIds[index] == KMType.ROOT_OF_TRUST) {
        pushRoT();
        continue;
      }
      if (pushParams(hwParams, indexes[HW_PARAM_INDEX], hwTagIds[index])) {
        continue;
      }
    } while (++index < length);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static boolean pushParams(short[] params, short len, short tagId) {
    short index = 0;
    while (index < len) {
      if (tagId == KMTag.getKey(params[index])) {
        pushTag(params[index]);
        return true;
      }
      index++;
    }
    return false;
  }

  private static void pushTag(short tag) {
    short type = KMTag.getTagType(tag);
    short tagId = KMTag.getKey(tag);
    short val;
    switch (type) {
      case KMType.BYTES_TAG:
        val = KMByteTag.cast(tag).getValue();
        pushBytesTag(
            tagId,
            KMByteBlob.cast(val).getBuffer(),
            KMByteBlob.cast(val).getStartOff(),
            KMByteBlob.cast(val).length());
        break;
      case KMType.ENUM_TAG:
        val = KMEnumTag.cast(tag).getValue();
        pushEnumTag(tagId, (byte) val);
        break;
      case KMType.ENUM_ARRAY_TAG:
        val = KMEnumArrayTag.cast(tag).getValues();
        pushEnumArrayTag(
            tagId,
            KMByteBlob.cast(val).getBuffer(),
            KMByteBlob.cast(val).getStartOff(),
            KMByteBlob.cast(val).length());
        break;
      case KMType.UINT_TAG:
      case KMType.ULONG_TAG:
      case KMType.DATE_TAG:
        val = KMIntegerTag.cast(tag).getValue();
        pushIntegerTag(
            tagId,
            KMInteger.cast(val).getBuffer(),
            KMInteger.cast(val).getStartOff(),
            KMInteger.cast(val).length());
        break;
      case KMType.UINT_ARRAY_TAG:
      case KMType.ULONG_ARRAY_TAG:
        // According to KeyMint hal only one user secure id is used but this conflicts with
        //  tag type which is ULONG-REP. Currently this is encoded as SET OF INTEGERS
        val = KMIntegerArrayTag.cast(tag).getValues();
        pushIntegerArrayTag(tagId, val);
        break;
      case KMType.BOOL_TAG:
        val = KMBoolTag.cast(tag).getVal();
        pushBoolTag(tagId);
        break;
      default:
        KMException.throwIt(KMError.INVALID_TAG);
        break;
    }
  }

  // RootOfTrust ::= SEQUENCE {
  //          verifiedBootKey            OCTET_STRING,
  //          deviceLocked               BOOLEAN,
  //          verifiedBootState          VerifiedBootState,
  //          verifiedBootHash           OCTET_STRING,
  //      }
  // VerifiedBootState ::= ENUMERATED {
  //          Verified                   (0),
  //          SelfSigned                 (1),
  //          Unverified                 (2),
  //          Failed                     (3),
  //      }
  private static void pushRoT() {
    short last = indexes[STACK_PTR];
    // verified boot hash
    pushOctetString(
        KMByteBlob.cast(indexes[VERIFIED_HASH]).getBuffer(),
        KMByteBlob.cast(indexes[VERIFIED_HASH]).getStartOff(),
        KMByteBlob.cast(indexes[VERIFIED_HASH]).length());

    pushEnumerated(states[VERIFIED_STATE]);

    pushBoolean(states[DEVICE_LOCKED]);
    // verified boot Key
    pushOctetString(
        KMByteBlob.cast(indexes[VERIFIED_BOOT_KEY]).getBuffer(),
        KMByteBlob.cast(indexes[VERIFIED_BOOT_KEY]).getStartOff(),
        KMByteBlob.cast(indexes[VERIFIED_BOOT_KEY]).length());

    // Finally sequence header
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
    // ... and tag Id
    pushTagIdHeader(KMType.ROOT_OF_TRUST, (short) (last - indexes[STACK_PTR]));
  }

  private static void pushOctetString(byte[] buf, short start, short len) {
    pushBytes(buf, start, len);
    pushOctetStringHeader(len);
  }

  private static void pushBoolean(byte val) {
    pushByte(val);
    pushBooleanHeader((short) 1);
  }

  private static void pushBooleanHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x01);
  }

  // Only SET of INTEGERS supported are padding, digest, purpose and blockmode
  // All of these are enum array tags i.e. byte long values
  private static void pushEnumArrayTag(short tagId, byte[] buf, short start, short len) {
    short last = indexes[STACK_PTR];
    short index = 0;
    while (index < len) {
      pushByte(buf[(short) (start + index)]);
      pushIntegerHeader((short) 1);
      index++;
    }
    pushSetHeader((short) (last - indexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - indexes[STACK_PTR]));
  }

  // Only SET of INTEGERS supported are padding, digest, purpose and blockmode
  // All of these are enum array tags i.e. byte long values
  private static void pushIntegerArrayTag(short tagId, short arr) {
    short last = indexes[STACK_PTR];
    short index = 0;
    short len = KMArray.cast(arr).length();
    short ptr;
    while (index < len) {
      ptr = KMArray.cast(arr).get(index);
      pushInteger(
          KMInteger.cast(ptr).getBuffer(),
          KMInteger.cast(ptr).getStartOff(),
          KMInteger.cast(ptr).length());
      index++;
    }
    pushSetHeader((short) (last - indexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - indexes[STACK_PTR]));
  }

  private static void pushSetHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x31);
  }

  private static void pushEnumerated(byte val) {
    short last = indexes[STACK_PTR];
    pushByte(val);
    pushEnumeratedHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushEnumeratedHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x0A);
  }

  private static void pushBoolTag(short tagId) {
    short last = indexes[STACK_PTR];
    pushNullHeader();
    pushTagIdHeader(tagId, (short) (last - indexes[STACK_PTR]));
  }

  private static void pushNullHeader() {
    pushByte((byte) 0);
    pushByte((byte) 0x05);
  }

  private static void pushEnumTag(short tagId, byte val) {
    short last = indexes[STACK_PTR];
    pushByte(val);
    pushIntegerHeader((short) (last - indexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - indexes[STACK_PTR]));
  }

  private static void pushIntegerTag(short tagId, byte[] buf, short start, short len) {
    short last = indexes[STACK_PTR];
    pushInteger(buf, start, len);
    pushTagIdHeader(tagId, (short) (last - indexes[STACK_PTR]));
  }

  // Ignore leading zeros. Only Unsigned Integers are required hence if MSB is set then add 0x00
  // as most significant byte.
  private static void pushInteger(byte[] buf, short start, short len) {
    short last = indexes[STACK_PTR];
    byte index = 0;
    while (index < (byte) len) {
      if (buf[(short) (start + index)] != 0) {
        break;
      }
      index++;
    }
    if (index == (byte) len) {
      pushByte((byte) 0x00);
    } else {
      pushBytes(buf, (short) (start + index), (short) (len - index));
      if (buf[(short) (start + index)] < 0) { // MSB is 1
        pushByte((byte) 0x00); // always unsigned int
      }
    }
    pushIntegerHeader((short) (last - indexes[STACK_PTR]));
  }

  // Bytes Tag is a octet string and tag id is added explicitly
  private static void pushBytesTag(short tagId, byte[] buf, short start, short len) {
    short last = indexes[STACK_PTR];
    pushBytes(buf, start, len);
    pushOctetStringHeader((short) (last - indexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - indexes[STACK_PTR]));
  }

  // tag id <= 30 ---> 0xA0 | {tagId}
  // 30 < tagId < 128 ---> 0xBF 0x{tagId}
  // tagId >= 128 ---> 0xBF 0x80+(tagId/128) 0x{tagId - (128*(tagId/128))}
  private static void pushTagIdHeader(short tagId, short len) {
    pushLength(len);
    short count = (short) (tagId / 128);
    if (count > 0) {
      pushByte((byte) (tagId - (128 * count)));
      pushByte((byte) (0x80 + count));
      pushByte((byte) 0xBF);
    } else if (tagId > 30) {
      pushByte((byte) tagId);
      pushByte((byte) 0xBF);
    } else {
      pushByte((byte) (0xA0 | (byte) tagId));
    }
  }

  // SEQUENCE {ObjId, OCTET STRING{BIT STRING{keyUsage}}}
  private static void pushKeyUsage(byte keyUsage, byte unusedBits) {
    short last = indexes[STACK_PTR];
    pushByte(keyUsage);
    pushBitStringHeader(unusedBits, (short) (last - indexes[STACK_PTR]));
    pushOctetStringHeader((short) (last - indexes[STACK_PTR]));
    pushBytes(keyUsageExtn, (short) 0, (short) keyUsageExtn.length);
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
  }

  private static void pushAlgorithmId(byte[] algId) {
    pushBytes(algId, (short) 0, (short) algId.length);
  }

  private static void pushIntegerHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x02);
  }

  private static void pushOctetStringHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x04);
  }

  private static void pushSequenceHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x30);
  }

  private static void pushBitStringHeader(byte unusedBits, short len) {
    pushByte(unusedBits);
    pushLength((short) (len + 1)); // 1 extra byte for unused bits byte
    pushByte((byte) 0x03);
  }

  private static void pushLength(short len) {
    if (len < 128) {
      pushByte((byte) len);
    } else if (len < 256) {
      pushByte((byte) len);
      pushByte((byte) 0x81);
    } else {
      pushShort(len);
      pushByte((byte) 0x82);
    }
  }

  private static void pushShort(short val) {
    decrementStackPtr((short) 2);
    Util.setShort(stack, indexes[STACK_PTR], val);
  }

  private static void pushByte(byte val) {
    decrementStackPtr((short) 1);
    stack[indexes[STACK_PTR]] = val;
  }

  private static void pushBytes(byte[] buf, short start, short len) {
    decrementStackPtr(len);
    if (buf != null) {
      Util.arrayCopyNonAtomic(buf, start, stack, indexes[STACK_PTR], len);
    }
  }

  private static void decrementStackPtr(short cnt) {
    indexes[STACK_PTR] = (short) (indexes[STACK_PTR] - cnt);
    if (indexes[BUF_START] > indexes[STACK_PTR]) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }

  @Override
  public KMAttestationCert buffer(byte[] buf, short start, short maxLen) {
    stack = buf;
    indexes[BUF_START] = start;
    indexes[BUF_LENGTH] = maxLen;
    indexes[STACK_PTR] = (short) (indexes[BUF_START] + indexes[BUF_LENGTH]);
    return this;
  }

  @Override
  public short getCertStart() {
    return indexes[CERT_START];
  }

  @Override
  public short getCertLength() {
    return indexes[CERT_LENGTH];
  }

  public void build(short attSecret, short attMod, boolean rsaSign, boolean fakeCert) {
    indexes[STACK_PTR] = (short) (indexes[BUF_START] + indexes[BUF_LENGTH]);
    short last = indexes[STACK_PTR];
    short sigLen = 0;
    if (fakeCert) {
      rsaSign = true;
      pushByte((byte) 0);
      sigLen = 1;
    }
    // Push placeholder signature Bit string header
    // This will potentially change at the end
    else if (rsaSign) {
      decrementStackPtr(RSA_SIG_LEN);
    } else {
      decrementStackPtr(ECDSA_MAX_SIG_LEN);
    }
    short signatureOffset = indexes[STACK_PTR];
    pushBitStringHeader((byte) 0, (short) (last - indexes[STACK_PTR]));
    if (rsaSign) {
      pushAlgorithmId(X509RsaSignAlgIdentifier);
    } else {
      pushAlgorithmId(X509EcdsaSignAlgIdentifier);
    }
    indexes[TBS_LENGTH] = indexes[STACK_PTR];
    pushTbsCert((states[RSA_CERT] == 0 ? false : true), rsaSign);
    indexes[TBS_START] = indexes[STACK_PTR];
    indexes[TBS_LENGTH] = (short) (indexes[TBS_LENGTH] - indexes[TBS_START]);
    if (attSecret != KMType.INVALID_VALUE) {
      // Sign with the attestation key
      // The pubKey is the modulus.
      if (rsaSign) {
        sigLen = seProvider
            .rsaSign256Pkcs1(
                KMByteBlob.cast(attSecret).getBuffer(),
                KMByteBlob.cast(attSecret).getStartOff(),
                KMByteBlob.cast(attSecret).length(),
                KMByteBlob.cast(attMod).getBuffer(),
                KMByteBlob.cast(attMod).getStartOff(),
                KMByteBlob.cast(attMod).length(),
                stack,
                indexes[TBS_START],
                indexes[TBS_LENGTH],
                stack,
                signatureOffset);
        if (sigLen > RSA_SIG_LEN) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
      } else {
        sigLen = seProvider
            .ecSign256(
                KMByteBlob.cast(attSecret).getBuffer(),
                KMByteBlob.cast(attSecret).getStartOff(),
                KMByteBlob.cast(attSecret).length(),
                stack,
                indexes[TBS_START],
                indexes[TBS_LENGTH],
                stack,
                signatureOffset);
        if (sigLen > ECDSA_MAX_SIG_LEN) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
      }
      // Adjust signature length
      indexes[STACK_PTR] = signatureOffset;
      pushBitStringHeader((byte) 0, sigLen);
    } else if (!fakeCert) { // No attestation key provisioned in the factory
      KMException.throwIt(KMError.ATTESTATION_KEYS_NOT_PROVISIONED);
    }
    last = (short) (signatureOffset + sigLen);
    // Add certificate sequence header
    indexes[STACK_PTR] = indexes[TBS_START];
    pushSequenceHeader((short) (last - indexes[STACK_PTR]));
    indexes[CERT_START] = indexes[STACK_PTR];
    indexes[CERT_LENGTH] = (short) (last - indexes[CERT_START]);
  }

  @Override
  public void build() {
    if (states[CERT_MODE] == KMType.FAKE_CERT) {
      build(KMType.INVALID_VALUE, KMType.INVALID_VALUE, true, true);
    } else {
      build(indexes[CERT_ATT_KEY_SECRET], indexes[CERT_ATT_KEY_RSA_PUB_MOD],
          (states[CERT_RSA_SIGN] == 0 ? false : true), false);
    }
  }

  @Override
  public KMAttestationCert makeUniqueId(byte[] scratchPad, short scratchPadOff,
      byte[] creationTime, short timeOffset, short creationTimeLen,
      byte[] attestAppId, short appIdOff, short attestAppIdLen,
      byte resetSinceIdRotation, KMMasterKey masterKey) {
    // Concatenate T||C||R
    // temporal count T
    short temp = KMUtils.countTemporalCount(creationTime, timeOffset,
        creationTimeLen, scratchPad, scratchPadOff);
    Util.setShort(scratchPad, (short) scratchPadOff, temp);
    temp = scratchPadOff;
    scratchPadOff += 2;

    // Application Id C
    Util.arrayCopyNonAtomic(attestAppId, appIdOff, scratchPad, scratchPadOff,
        attestAppIdLen);
    scratchPadOff += attestAppIdLen;

    // Reset After Rotation R
    scratchPad[scratchPadOff] = resetSinceIdRotation;
    scratchPadOff++;

    //Get the key data from the master key
    KMAESKey aesKey = (KMAESKey) masterKey;
    short mKeyData = KMByteBlob.instance((short) (aesKey.aesKey.getSize() / 8));
    aesKey.aesKey.getKey(
        KMByteBlob.cast(mKeyData).getBuffer(), /* Key */
        KMByteBlob.cast(mKeyData).getStartOff()); /* Key start*/
    timeOffset = KMByteBlob.instance((short) 32);
    appIdOff = seProvider.hmacSign(
        KMByteBlob.cast(mKeyData).getBuffer(), /* Key */
        KMByteBlob.cast(mKeyData).getStartOff(), /* Key start*/
        KMByteBlob.cast(mKeyData).length(), /* Key length*/
        scratchPad, /* data */
        temp, /* data start */
        scratchPadOff, /* data length */
        KMByteBlob.cast(timeOffset).getBuffer(), /* signature buffer */
        KMByteBlob.cast(timeOffset).getStartOff()); /* signature start */
    if (appIdOff != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return uniqueId(timeOffset);
  }

  @Override
  public boolean serialNumber(short number) {
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
    short length = KMByteBlob.cast(number).length();
    if (length > SERIAL_NUM_MAX_LEN) {
      return false;
    }
    // The serial number Must be a positive integer.
    byte msb = KMByteBlob.cast(number).get((short) 0);
    if (msb < 0 && length > (SERIAL_NUM_MAX_LEN - 1)) {
      return false;
    }
    indexes[SERIAL_NUMBER] = number;
    return true;
  }

  @Override
  public boolean subjectName(short sub) {
    if (sub == KMType.INVALID_VALUE || KMByteBlob.cast(sub).length() == 0) {
      return false;
    }
    indexes[SUBJECT_NAME] = sub;
    return true;
  }

  @Override
  public KMAttestationCert ecAttestKey(short attestKey, byte mode) {
    states[CERT_MODE] = mode;
    indexes[CERT_ATT_KEY_SECRET] = attestKey;
    indexes[CERT_ATT_KEY_RSA_PUB_MOD] = KMType.INVALID_VALUE;
    states[CERT_RSA_SIGN] = 0;
    return this;
  }

  @Override
  public KMAttestationCert rsaAttestKey(short attestPrivExp, short attestMod, byte mode) {
    states[CERT_MODE] = mode;
    indexes[CERT_ATT_KEY_SECRET] = attestPrivExp;
    indexes[CERT_ATT_KEY_RSA_PUB_MOD] = attestMod;
    states[CERT_RSA_SIGN] = 1;
    return this;
  }

}
