package com.android.javacard.keymaster;

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
  // Authority Key Identifier Extn - 2.5.29.35
  private static final byte[] authKeyIdExtn = {0x06, 0x03, 0X55, 0X1D, 0X23};

  // Signature algorithm identifier - always sha256WithRSAEncryption - 1.2.840.113549.1.1.11
  // SEQUENCE of alg OBJ ID and parameters = NULL.
  private static final byte[] X509SignAlgIdentifier = {
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
  // Validity is not fixed field
  // Subject is a fixed field with only CN= Android Keystore Key - same for all the keys
  private static final byte[] X509Subject = {
    0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B, 0x65,
    0x79
  };

  private static final byte keyUsageSign = (byte) 0x80; // 0 bit
  private static final byte keyUsageKeyEncipher = (byte) 0x20; // 2nd- bit
  private static final byte keyUsageDataEncipher = (byte) 0x10; // 3rd- bit

  private static final byte KEYMASTER_VERSION = 4;
  private static final byte ATTESTATION_VERSION = 3;
  private static final byte[] pubExponent = {0x01, 0x00, 0x01};
  private static final byte SERIAL_NUM = (byte) 0x01;
  private static final byte X509_VERSION = (byte) 0x02;

  private static short certStart;
  private static short signatureOffset;
  private static short tbsOffset;
  private static short tbsLength;

  private static short stackPtr;
  private static byte[] stack;
  private static short start;
  private static short length;
  //  private static KMRepository repo;
  private static short uniqueId;
  private static short attChallenge;
  private static short notBefore;
  private static short notAfter;
  private static short pubKey;
  private static short[] swParams;
  private static short swParamsIndex;
  private static short[] hwParams;
  private static short hwParamsIndex;
  private static byte keyUsage;
  private static byte unusedBits;
  private static KMAttestationCert inst;
  private static boolean rsaCert;
  private static byte deviceLocked;
  private static short verifiedBootKey;
  private static byte verifiedState;
  private static short verifiedHash;
  private static short authKey;
  private static short issuer;
  private static short signPriv;
  private static short signMod;

  private KMAttestationCertImpl() {}

  public static KMAttestationCert instance(boolean rsaCert) {
    if (inst == null) inst = new KMAttestationCertImpl();
    init();
    KMAttestationCertImpl.rsaCert = rsaCert;
    return inst;
  }

  private static void init() {
    //    if (repo == null) repo = KMRepository.instance();
    stack = null;
    stackPtr = 0;
    certStart = 0;
    signatureOffset = 0;
    start = 0;
    length = 0;
    tbsLength = 0;
    if (swParams == null) {
      swParams = JCSystem.makeTransientShortArray((short) MAX_PARAMS, JCSystem.CLEAR_ON_RESET);
    }
    if (hwParams == null) {
      hwParams = JCSystem.makeTransientShortArray((short) MAX_PARAMS, JCSystem.CLEAR_ON_RESET);
    }

    swParamsIndex = 0;
    hwParamsIndex = 0;
    keyUsage = 0;
    unusedBits = 8;
    attChallenge = 0;
    notBefore = 0;
    notAfter = 0;
    pubKey = 0;
    uniqueId = 0;
    verifiedBootKey = 0;
    verifiedHash = 0;
    verifiedState = 0;
    rsaCert = true;
    deviceLocked = 0;
    authKey = 0;
    signPriv = 0;
    signMod = 0;
  }

  @Override
  public KMAttestationCert verifiedBootHash(short obj) {
    verifiedHash = obj;
    return this;
  }

  @Override
  public KMAttestationCert authKey(short obj) {
    authKey = obj;
    return this;
  }

  @Override
  public KMAttestationCert verifiedBootKey(short obj) {
    verifiedBootKey = obj;
    return this;
  }

  @Override
  public KMAttestationCert verifiedBootState(byte val) {
    verifiedState = val;
    return this;
  }

  @Override
  public KMAttestationCert uniqueId(short obj) {
    uniqueId = obj;
    return this;
  }

  @Override
  public KMAttestationCert notBefore(short obj) {
    notBefore = obj;
    return this;
  }

  @Override
  public KMAttestationCert notAfter(short obj) {
    notAfter = obj;
    return this;
  }

  @Override
  public KMAttestationCert deviceLocked(boolean val) {
    if (val) deviceLocked = (byte) 0xFF;
    else deviceLocked = 0;
    return this;
  }

  @Override
  public KMAttestationCert publicKey(short obj) {
    pubKey = obj;
    return this;
  }

  @Override
  public KMAttestationCert attestationChallenge(short obj) {
    attChallenge = obj;
    return this;
  }

  @Override
  public KMAttestationCert extensionTag(short tag, boolean hwEnforced) {
    if (hwEnforced) {
      hwParams[hwParamsIndex] = tag;
      hwParamsIndex++;
    } else {
      swParams[swParamsIndex] = tag;
      swParamsIndex++;
    }
    if (KMTag.getKey(tag) == KMType.PURPOSE) {
      createKeyUsage(tag);
    }
    return this;
  }

  @Override
  public KMAttestationCert issuer(short obj) {
    issuer = obj;
    return this;
  }

  private void createKeyUsage(short tag) {
    short len = KMEnumArrayTag.cast(tag).length();
    byte index = 0;
    while (index < len) {
      if (KMEnumArrayTag.cast(tag).get(index) == KMType.SIGN) {
        keyUsage = (byte) (keyUsage | keyUsageSign);
      } else if (KMEnumArrayTag.cast(tag).get(index) == KMType.WRAP_KEY) {
        keyUsage = (byte) (keyUsage | keyUsageKeyEncipher);
      } else if (KMEnumArrayTag.cast(tag).get(index) == KMType.DECRYPT) {
        keyUsage = (byte) (keyUsage | keyUsageDataEncipher);
      }
      index++;
    }
    index = keyUsage;
    while (index != 0) {
      index = (byte) (index << 1);
      unusedBits--;
    }
  }

  private static void encodeCert(
      short buf,
      short keyChar,
      short uniqueId,
      short notBefore,
      short notAfter,
      short pubKey,
      short attChallenge,
      short attAppId,
      boolean rsaCert) {
    init();
    stack = KMByteBlob.cast(buf).getBuffer();
    start = KMByteBlob.cast(buf).getStartOff();
    length = KMByteBlob.cast(buf).length();
    stackPtr = (short) (start + length);
    /*    KMAttestationCertImpl.attChallenge = attChallenge;
       KMAttestationCertImpl.attAppId = attAppId;
       KMAttestationCertImpl.hwParams = KMKeyCharacteristics.cast(keyChar).getHardwareEnforced();
       KMAttestationCertImpl.swParams = KMKeyCharacteristics.cast(keyChar).getSoftwareEnforced();
       KMAttestationCertImpl.notBefore = notBefore;
       KMAttestationCertImpl.notAfter = notAfter;
       KMAttestationCertImpl.pubKey = pubKey;
       KMAttestationCertImpl.uniqueId = uniqueId;

    */
    short last = stackPtr;
    decrementStackPtr((short) 256);
    signatureOffset = stackPtr;
    pushBitStringHeader((byte) 0, (short) (last - stackPtr));
    // signatureOffset = pushSignature(null, (short) 0, (short) 256);
    pushAlgorithmId(X509SignAlgIdentifier);
    tbsLength = stackPtr;
    pushTbsCert(rsaCert);
    tbsOffset = stackPtr;
    tbsLength = (short) (tbsLength - tbsOffset);
    pushSequenceHeader((short) (last - stackPtr));
    // print(stack, stackPtr, (short)(last - stackPtr));
    certStart = stackPtr;
  }

  private static void pushTbsCert(boolean rsaCert) {
    short last = stackPtr;
    pushExtensions();
    // subject public key info
    if (rsaCert) {
      pushRsaSubjectKeyInfo();
    } else {
      pushEccSubjectKeyInfo();
    }
    // subject
    pushBytes(X509Subject, (short) 0, (short) X509Subject.length);
    pushValidity();
    // issuer - der encoded
    //    pushBytes(repo.getCertDataBuffer(), repo.getIssuer(), repo.getIssuerLen());
    pushBytes(
        KMByteBlob.cast(issuer).getBuffer(),
        KMByteBlob.cast(issuer).getStartOff(),
        KMByteBlob.cast(issuer).length());
    // Algorithm Id
    pushAlgorithmId(X509SignAlgIdentifier);
    // Serial Number
    pushByte(SERIAL_NUM);
    pushIntegerHeader((short) 1);
    // Version
    pushByte(X509_VERSION);
    pushIntegerHeader((short) 1);
    pushByte((byte) 0x03);
    pushByte((byte) 0xA0);
    // Finally sequence header.
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushExtensions() {
    short last = stackPtr;
    //    byte keyusage = 0;
    //    byte unusedBits = 8;
    pushAuthKeyId();
    /*
    if (KMEnumArrayTag.contains(KMType.PURPOSE, KMType.SIGN, hwParams)) {
      keyusage = (byte) (keyusage | keyUsageSign);
      unusedBits = 7;
    }
    if (KMEnumArrayTag.contains(KMType.PURPOSE, KMType.WRAP_KEY, hwParams)) {
      keyusage = (byte) (keyusage | keyUsageKeyEncipher);
      unusedBits = 5;
    }
    if (KMEnumArrayTag.contains(KMType.PURPOSE, KMType.DECRYPT, hwParams)) {
      keyusage = (byte) (keyusage | keyUsageDataEncipher);
      unusedBits = 4;
    }

     */
    if (keyUsage != 0) pushKeyUsage(keyUsage, unusedBits);
    pushKeyDescription();
    pushSequenceHeader((short) (last - stackPtr));
    // Extensions have explicit tag of [3]
    pushLength((short) (last - stackPtr));
    pushByte((byte) 0xA3);
  }

  // Time SEQUENCE{UTCTime, UTC or Generalized Time)
  private static void pushValidity() {
    short last = stackPtr;
    if (notAfter != 0) {
      pushBytes(
          KMByteBlob.cast(notAfter).getBuffer(),
          KMByteBlob.cast(notAfter).getStartOff(),
          KMByteBlob.cast(notAfter).length());
    } else {
      // TODO move this to keymaster applet
      // pushBytes(repo.getCertDataBuffer(), repo.getCertExpiryTime(), repo.getCertExpiryTimeLen());
    }
    pushTimeHeader(KMByteBlob.cast(notAfter).length());
    pushBytes(
        KMByteBlob.cast(notBefore).getBuffer(),
        KMByteBlob.cast(notBefore).getStartOff(),
        KMByteBlob.cast(notBefore).length());
    pushTimeHeader(KMByteBlob.cast(notBefore).length());
    pushSequenceHeader((short) (last - stackPtr));
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
    short last = stackPtr;
    pushBytes(pubExponent, (short) 0, (short) pubExponent.length);
    pushIntegerHeader((short) pubExponent.length);
    pushBytes(
        KMByteBlob.cast(pubKey).getBuffer(),
        KMByteBlob.cast(pubKey).getStartOff(),
        KMByteBlob.cast(pubKey).length());

    // encode modulus as positive if the MSB is 1.
    if (KMByteBlob.cast(pubKey).get((short) 0) < 0) {
      pushByte((byte) 0x00);
      pushIntegerHeader((short) (KMByteBlob.cast(pubKey).length() + 1));
    } else {
      pushIntegerHeader(KMByteBlob.cast(pubKey).length());
    }
    pushSequenceHeader((short) (last - stackPtr));
    pushBitStringHeader((byte) 0x00, (short) (last - stackPtr));
    pushRsaEncryption();
    pushSequenceHeader((short) (last - stackPtr));
  }
  // SEQUENCE{SEQUENCE{ecPubKey, prime256v1}, bitString{pubKey}}
  private static void pushEccSubjectKeyInfo() {
    short last = stackPtr;
    pushBytes(
        KMByteBlob.cast(pubKey).getBuffer(),
        KMByteBlob.cast(pubKey).getStartOff(),
        KMByteBlob.cast(pubKey).length());
    pushBitStringHeader((byte) 0x00, KMByteBlob.cast(pubKey).length());
    pushEcDsa();
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushEcDsa() {
    short last = stackPtr;
    pushBytes(prime256v1, (short) 0, (short) prime256v1.length);
    pushBytes(eccPubKey, (short) 0, (short) eccPubKey.length);
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushRsaEncryption() {
    short last = stackPtr;
    pushNullHeader();
    pushBytes(rsaEncryption, (short) 0, (short) rsaEncryption.length);
    pushSequenceHeader((short) (last - stackPtr));
  }
  // KeyDescription ::= SEQUENCE {
  //         attestationVersion         INTEGER, # Value 3
  //         attestationSecurityLevel   SecurityLevel, # See below
  //         keymasterVersion           INTEGER, # Value 4
  //         keymasterSecurityLevel     SecurityLevel, # See below
  //         attestationChallenge       OCTET_STRING, # Tag::ATTESTATION_CHALLENGE from attestParams
  //         uniqueId                   OCTET_STRING, # Empty unless key has Tag::INCLUDE_UNIQUE_ID
  //         softwareEnforced           AuthorizationList, # See below
  //         hardwareEnforced           AuthorizationList, # See below
  //     }
  private static void pushKeyDescription() {
    short last = stackPtr;
    pushHWParams();
    pushSWParams();
    if (uniqueId != 0) {
      pushOctetString(
          KMByteBlob.cast(uniqueId).getBuffer(),
          KMByteBlob.cast(uniqueId).getStartOff(),
          KMByteBlob.cast(uniqueId).length());
    } else {
      pushOctetStringHeader((short) 0);
    }
    pushOctetString(
        KMByteBlob.cast(attChallenge).getBuffer(),
        KMByteBlob.cast(attChallenge).getStartOff(),
        KMByteBlob.cast(attChallenge).length());
    pushEnumerated(KMType.STRONGBOX);
    pushByte(KEYMASTER_VERSION);
    pushIntegerHeader((short) 1);
    pushEnumerated(KMType.STRONGBOX);
    pushByte(ATTESTATION_VERSION);
    pushIntegerHeader((short) 1);
    pushSequenceHeader((short) (last - stackPtr));
    pushOctetStringHeader((short) (last - stackPtr));
    pushBytes(androidExtn, (short) 0, (short) androidExtn.length);
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushSWParams() {
    short last = stackPtr;
    // ATTESTATION_APPLICATION_ID 709 is softwareEnforced.
    short[] tagIds = {
      709, 706, 705, 704, 703, 702, 701, 601, 600, 509, 508, 507, 506, 505, 504, 503, 402, 401, 400,
      303, 200, 10, 6, 5, 3, 2, 1
    };
    byte index = 0;
    do {
      /*
       if(tagIds[index] == KMType.ATTESTATION_APPLICATION_ID) {
      pushAttIds(tagIds[index]);
      continue;
       }
        */
      pushParams(swParams, swParamsIndex, tagIds[index]);
    } while (++index < tagIds.length);
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushHWParams() {
    short last = stackPtr;
    // Attestation ids are not included. As per VTS attestation ids are not supported currenlty.
    short[] tagIds = {
      706, 705, 704, 703, 702, 701, 601, 600, 509, 508, 507, 506, 505, 504, 503, 402, 401, 400, 303,
      200, 10, 6, 5, 3, 2, 1
    };
    byte index = 0;
    do {
      // if(pushAttIds(tagIds[index])) continue;
      if (tagIds[index] == KMType.ROOT_OF_TRUST) {
        pushRoT();
        continue;
      }
      if (pushParams(hwParams, hwParamsIndex, tagIds[index])) continue;
    } while (++index < tagIds.length);
    pushSequenceHeader((short) (last - stackPtr));
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
        // TODO According to keymaster hal only one user secure id is used but this conflicts with
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
    short last = stackPtr;
    byte val = 0x00;
    // verified boot hash
    // pushOctetString(repo.verifiedBootHash, (short) 0, (short) repo.verifiedBootHash.length);
    pushOctetString(
        KMByteBlob.cast(verifiedHash).getBuffer(),
        KMByteBlob.cast(verifiedHash).getStartOff(),
        KMByteBlob.cast(verifiedHash).length());
    /*
    // verified boot state
    // TODO change this once verifiedBootState is supported in repo
    if (repo.selfSignedBootFlag) val = KMType.SELF_SIGNED_BOOT;
    else if (repo.verifiedBootFlag) val = KMType.VERIFIED_BOOT;
    else val = KMType.UNVERIFIED_BOOT;

    pushEnumerated(val);

     */
    pushEnumerated(verifiedState);
    // device locked
    /*val = 0x00;
    if (repo.deviceLockedFlag) val = (byte) 0xFF;
    pushBoolean(val);
     */
    pushBoolean(deviceLocked);
    // verified boot Key
    pushOctetString(
        KMByteBlob.cast(verifiedBootKey).getBuffer(),
        KMByteBlob.cast(verifiedBootKey).getStartOff(),
        KMByteBlob.cast(verifiedBootKey).length());
    // pushOctetString(repo.verifiedBootKey, (short) 0, (short) repo.verifiedBootKey.length);
    // Finally sequence header
    pushSequenceHeader((short) (last - stackPtr));
    // ... and tag Id
    pushTagIdHeader(KMType.ROOT_OF_TRUST, (short) (last - stackPtr));
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
  /*
    // All Attestation Id tags are byte tags/octet strings
    private static boolean pushAttIds(short tagId) {
      if(!repo.isAttIdSupported()) return true;
      byte index = 0;
      while (index < repo.ATT_ID_TABLE_SIZE) {
        if (repo.getAttIdLen(index) != 0) {
      	if(tagId == repo.getAttIdTag(index)) {
            pushBytesTag(
                repo.getAttIdTag(index),
                repo.getAttIdBuffer(index),
                repo.getAttIdOffset(index),
                repo.getAttIdLen(index));
            return true;
      	}
        }
        index++;
      }
      return false;
    }
  */
  // Only SET of INTEGERS supported are padding, digest, purpose and blockmode
  // All of these are enum array tags i.e. byte long values
  private static void pushEnumArrayTag(short tagId, byte[] buf, short start, short len) {
    short last = stackPtr;
    short index = 0;
    while (index < len) {
      pushByte(buf[(short) (start + index)]);
      pushIntegerHeader((short) 1);
      index++;
    }
    pushSetHeader((short) (last - stackPtr));
    pushTagIdHeader(tagId, (short) (last - stackPtr));
  }
  // Only SET of INTEGERS supported are padding, digest, purpose and blockmode
  // All of these are enum array tags i.e. byte long values
  private static void pushIntegerArrayTag(short tagId, short arr) {
    short last = stackPtr;
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
    pushSetHeader((short) (last - stackPtr));
    pushTagIdHeader(tagId, (short) (last - stackPtr));
  }

  private static void pushSetHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x31);
  }

  private static void pushEnumerated(byte val) {
    short last = stackPtr;
    pushByte(val);
    pushEnumeratedHeader((short) (last - stackPtr));
  }

  private static void pushEnumeratedHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x0A);
  }

  private static void pushBoolTag(short tagId) {
    short last = stackPtr;
    pushNullHeader();
    pushTagIdHeader(tagId, (short) (last - stackPtr));
  }

  private static void pushNullHeader() {
    pushByte((byte) 0);
    pushByte((byte) 0x05);
  }

  private static void pushEnumTag(short tagId, byte val) {
    short last = stackPtr;
    pushByte(val);
    pushIntegerHeader((short) (last - stackPtr));
    pushTagIdHeader(tagId, (short) (last - stackPtr));
  }

  private static void pushIntegerTag(short tagId, byte[] buf, short start, short len) {
    short last = stackPtr;
    pushInteger(buf, start, len);
    //    pushIntegerHeader((short) (last - stackPtr));
    pushTagIdHeader(tagId, (short) (last - stackPtr));
  }
  // Ignore leading zeros. Only Unsigned Integers are required hence if MSB is set then add 0x00
  // as most significant byte.
  private static void pushInteger(byte[] buf, short start, short len) {
    short last = stackPtr;
    byte index = 0;
    while (index < (byte) len) {
      if (buf[(short) (start + index)] != 0) break;
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
    pushIntegerHeader((short) (last - stackPtr));
  }
  // Bytes Tag is a octet string and tag id is added explicitly
  private static void pushBytesTag(short tagId, byte[] buf, short start, short len) {
    short last = stackPtr;
    pushBytes(buf, start, len);
    pushOctetStringHeader((short) (last - stackPtr));
    pushTagIdHeader(tagId, (short) (last - stackPtr));
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
    short last = stackPtr;
    pushByte(keyUsage);
    pushBitStringHeader(unusedBits, (short) (last - stackPtr));
    pushOctetStringHeader((short) (last - stackPtr));
    pushBytes(keyUsageExtn, (short) 0, (short) keyUsageExtn.length);
    pushSequenceHeader((short) (last - stackPtr));
  }

  // SEQUENCE {ObjId, OCTET STRING{SEQUENCE{[0]keyIdentifier}}}
  private static void pushAuthKeyId() {
    short last = stackPtr;
    // if (repo.getAuthKeyId() == 0) return;
    if (authKey == 0) return;
    /*
     pushKeyIdentifier(
         repo.getCertDataBuffer(),
         repo.getAuthKeyId(),
         repo.getAuthKeyIdLen()); // key identifier is [0]'th tagged in a sequence

    */
    pushKeyIdentifier(
        KMByteBlob.cast(authKey).getBuffer(),
        KMByteBlob.cast(authKey).getStartOff(),
        KMByteBlob.cast(authKey).length());
    pushSequenceHeader((short) (last - stackPtr));
    pushOctetStringHeader((short) (last - stackPtr));
    pushBytes(authKeyIdExtn, (short) 0, (short) authKeyIdExtn.length); // ObjId
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushKeyIdentifier(byte[] buf, short start, short len) {
    pushBytes(buf, start, len); // keyIdentifier
    pushLength(len); // len
    pushByte((byte) 0x80); // Context specific tag [0]
  }

  private static void pushAlgorithmId(byte[] algId) {
    pushBytes(algId, (short) 0, (short) algId.length);
  }

  private static short pushSignature(byte[] buf, short start, short len) {
    pushBytes(buf, start, len);
    short signatureOff = stackPtr;
    pushBitStringHeader((byte) 0, len);
    return signatureOff;
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
    Util.setShort(stack, stackPtr, val);
  }

  private static void pushByte(byte val) {
    decrementStackPtr((short) 1);
    stack[stackPtr] = val;
  }

  private static void pushBytes(byte[] buf, short start, short len) {
    decrementStackPtr(len);
    if (buf != null) {
      Util.arrayCopyNonAtomic(buf, start, stack, stackPtr, len);
    }
  }

  private static void decrementStackPtr(short cnt) {
    stackPtr = (short) (stackPtr - cnt);
    if (start > stackPtr) KMException.throwIt(KMError.UNKNOWN_ERROR);
  }

  public static short sign(
      KMSEProvider seProv,
      byte[] privBuf,
      short privStart,
      short privLength,
      byte[] modBuf,
      short modStart,
      short modLength) {
    // short ret = signer.sign(stack,tbsOffset,tbsLength,stack,signatureOffset);
    // print(getBuffer(),getCertStart(),getCertLength());
    return seProv.rsaSignPKCS1256(
        privBuf,
        privStart,
        privLength,
        modBuf,
        modStart,
        modLength,
        stack,
        tbsOffset,
        tbsLength,
        stack,
        signatureOffset);
  }

  @Override
  public KMAttestationCert buffer(byte[] buf, short bufStart, short maxLen) {
    stack = buf;
    start = bufStart;
    length = maxLen;
    stackPtr = (short) (start + length);
    return this;
  }

  @Override
  public KMAttestationCert signingKey(short privKey, short modulus) {
    signPriv = privKey;
    signMod = modulus;
    return this;
  }

  @Override
  public short getCertStart() {
    return certStart;
  }

  @Override
  public short getCertEnd() {
    return (short) (start + length - 1);
  }

  @Override
  public short getCertLength() {
    return (short) (getCertEnd() - getCertStart() + 1);
  }

  @Override
  public void build() {
    short last = stackPtr;
    decrementStackPtr((short) 256);
    signatureOffset = stackPtr;
    pushBitStringHeader((byte) 0, (short) (last - stackPtr));
    // signatureOffset = pushSignature(null, (short) 0, (short) 256);
    pushAlgorithmId(X509SignAlgIdentifier);
    tbsLength = stackPtr;
    pushTbsCert(rsaCert);
    tbsOffset = stackPtr;
    tbsLength = (short) (tbsLength - tbsOffset);
    pushSequenceHeader((short) (last - stackPtr));
    certStart = stackPtr;
    KMSEProviderImpl.instance()
        .rsaSignPKCS1256(
            KMByteBlob.cast(signPriv).getBuffer(),
            KMByteBlob.cast(signPriv).getStartOff(),
            KMByteBlob.cast(signPriv).length(),
            KMByteBlob.cast(signMod).getBuffer(),
            KMByteBlob.cast(signMod).getStartOff(),
            KMByteBlob.cast(signMod).length(),
            stack,
            tbsOffset,
            tbsLength,
            stack,
            signatureOffset);
    //    print(stack, stackPtr, (short)(last - stackPtr));
  }

  /* private static void print(byte[] buf, short start, short length){
    StringBuilder sb = new StringBuilder();
    for(int i = start; i < (start+length); i++){
      sb.append(String.format("%02X", buf[i])) ;
      //if((i-start)%16 == 0 && (i-start) != 0) sb.append(String.format("\n"));
    }
    System.out.println(sb.toString());
  }

  */
}
