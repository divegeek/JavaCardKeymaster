package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.Signature;

// The class encodes strongbox generated amd signed attestation certificate. This only encodes
// required fields of the certificates. It is not meant to be generic X509 cert encoder.
// Whatever fields that are fixed are added as byte arrays. The Extensions are encoded as per
// the values.
// The certificate is assembled with leafs first and then the sequences.

public class KMX509Certificate {
  // DER encoded object identifiers required by the cert.
  // sha256WithRSAEncryption - 1.2.840.113549.1.1.11
  private static final byte[] sha256WithRSAEncryption = {
    0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B
  };
  // countryName - 2.5.4.6
  private static final byte[] country = {0x06, 0x03, 0x55, 0x04, 0x06};
  // stateOrProvinceName - 2.5.4.8
  private static final byte[] stateName = {0x06, 0x03, 0x55, 0x04, 0x08};
  // organizationName - 2.5.4.10
  private static final byte[] orgName = {0x06, 0x03, 0x55, 0x04, 0x0A};
  // organizationalUnitName - 2.5.4.11
  private static final byte[] orgUnitName = {0x06, 0x03, 0x55, 0x04, 0x0B};
  // commonName - 2.5.4.3
  private static final byte[] commonName = {0x06, 0x03, 0x55, 0x04, 0x03};
  // rsaEncryption - 1.2.840.113549.1.1.1
  private static final byte[] rsaEncryption = {
    0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01
  };
  // ecPublicKey -  1.2.840.10045.2.1
  private static final byte[] eccPubKey = {0x06,0x07,0x2A,(byte)0x86,0x48,(byte)0xCE,0x3D,0x02,0x01};
  // prime256v1 curve - 1.2.840.10045.3.1.7
  private static final byte[] prime256v1 = {0x06,0x08,0x2A,(byte)0x86,0x48,(byte)0xCE,0x3D,0x03,0x01,0x07};
  // Key Usage Extn - 2.5.29.15
  private static final byte[] keyUsageExtn = {0x06, 0x03, 0x55, 0x1D, 0x0F};
  // Android Extn - 1.3.6.1.4.1.11129.2.1.17
  private static final byte[] androidExtn = {
    0x06, 0x0A, 0X2B, 0X06, 0X01, 0X04, 0X01, (byte) 0XD6, 0X79, 0X02, 0X01, 0X11
  };
  // Authority Key Identifier Extn - 2.5.29.35
  private static final byte[] authKeyIdExtn = {0x06, 0x03, 0X55, 0X1D, 0X23};

  // Fixed field values - DER encoded
  // Version with value 2 and EXPLICIT id 0 with INTEGER type- DER encoded
  private static final byte[] X509Version = {(byte) 0XA0, 0x03, 0x02, 0x01, 0x02};
  // Serial Number with value 1
  private static final byte[] X509SerialNum = {0x02, 0x01, 0x01};
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
  // Issuer field is not fixed but it will be given in the provision command in DER Encoded form
  // i.e. subject of the cert for attesting key. Following is the placeholder example sequence of
  // 5 elements: C=US, ST=California, O=Google, Inc.,OU=Android, CN=Android Software Attestation Key
  // TODO move the following to test
  private static final byte[] X509Issuer = {
    0x30, 0x76, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66, 0x6F,
    0x72, 0x6E, 0x69, 0x61, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0C, 0x47,
    0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2C, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x10, 0x30, 0x0E, 0x06,
    0x03, 0x55, 0x04, 0x0B, 0x0C, 0x07, 0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x31, 0x29, 0x30,
    0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x20,
    0x53, 0x6F, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
    0x74, 0x69, 0x6F, 0x6E, 0x20, 0x4B, 0x65, 0x79
  };
  // Validity is not fixed field
  // Subject is a fixed field with only CN= Android Keystore Key - same for all the keys
  private static final byte[] X509Subject = {
    0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B, 0x65,
    0x79
  };
  // Subject Public Key Info is not a fixed field. However the for rsa public key or ec dsa
  // public key the algorithm identifier is always the same.
  // rsaEncryption - 1.2.840.113549.1.1.1 followed by NULL parameters
  private static final byte[] subPubKeyRsaAlgId = {
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
    0x01,
    0x05,
    0x00
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
  private static short attChallenge;
  private static short attAppId;
  private static short hwParams;
  private static short swParams;
  private static short notBefore;
  private static short notAfter;
  private static short pubKey;
  private static short uniqueId;

  private static short stackPtr;
  private static byte[] stack;
  private static short start;
  private static short length;
  private static KMRepository repo;

  private static void init() {
    if (repo == null) repo = KMRepository.instance();
    stack = null;
    stackPtr = 0;
    certStart = 0;
    signatureOffset = 0;
    start = 0;
    length = 0;
    attChallenge = 0;
    attAppId = 0;
    hwParams = 0;
    swParams = 0;
    notBefore = 0;
    notAfter = 0;
    pubKey = 0;
    uniqueId = 0;
    tbsLength = 0;
  }

  public static void encodeCert(
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
    KMX509Certificate.attChallenge = attChallenge;
    KMX509Certificate.attAppId = attAppId;
    KMX509Certificate.hwParams = KMKeyCharacteristics.cast(keyChar).getHardwareEnforced();
    KMX509Certificate.swParams = KMKeyCharacteristics.cast(keyChar).getSoftwareEnforced();
    KMX509Certificate.notBefore = notBefore;
    KMX509Certificate.notAfter = notAfter;
    KMX509Certificate.pubKey = pubKey;
    KMX509Certificate.uniqueId = uniqueId;
    short last = stackPtr;
    decrementStackPtr((short)256);
    signatureOffset = stackPtr;
    pushBitStringHeader((byte) 0, (short)(last - stackPtr));
    //signatureOffset = pushSignature(null, (short) 0, (short) 256);
    pushAlgorithmId(X509SignAlgIdentifier);
    tbsLength = stackPtr;
    pushTbsCert(rsaCert);
    tbsOffset = stackPtr;
    tbsLength = (short)(tbsLength - tbsOffset);
    pushSequenceHeader((short)(last-stackPtr));
    //print(stack, stackPtr, (short)(last - stackPtr));
    certStart = stackPtr;
  }

  private static void pushTbsCert(boolean rsaCert) {
    short last = stackPtr;
    pushExtensions();
    // subject public key info
    if (rsaCert) {
      pushRsaSubjectKeyInfo();
    }else{
      pushEccSubjectKeyInfo();
    }
    // subject
    pushBytes(X509Subject, (short) 0, (short) X509Subject.length);
    pushValidity();
    // issuer - der encoded
    pushBytes(repo.getCertDataBuffer(), repo.getIssuer(), repo.getIssuerLen());
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
  private static void pushExtensions(){
    short last = stackPtr;
    byte keyusage = 0;
    byte unusedBits = 8;
    pushAuthKeyId();
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
    if (keyusage != 0) pushKeyUsage(keyusage, unusedBits);
    pushKeyDescription();
    pushSequenceHeader((short) (last - stackPtr));
    // Extensions have explicit tag of [3]
    pushLength((short)(last-stackPtr));
    pushByte((byte) 0xA3);
  }

  // Time SEQUENCE{UTCTime, UTC or Generalized Time)
  private static void pushValidity(){
    short last = stackPtr;    if (notAfter != 0) {
      pushBytes(
        KMByteBlob.cast(notAfter).getBuffer(),
        KMByteBlob.cast(notAfter).getStartOff(),
        KMByteBlob.cast(notAfter).length());
    } else {
      pushBytes(repo.getCertDataBuffer(), repo.getCertExpiryTime(), repo.getCertExpiryTimeLen());
    }
    pushTimeHeader(KMByteBlob.cast(notAfter).length());
    pushBytes(
      KMByteBlob.cast(notBefore).getBuffer(),
      KMByteBlob.cast(notBefore).getStartOff(),
      KMByteBlob.cast(notBefore).length());
    pushTimeHeader(KMByteBlob.cast(notBefore).length());
    pushSequenceHeader((short)(last-stackPtr));
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
  // SEQUENCE{SEQUENCE{algId, NULL}, bitString{SEQUENCE{ modulus as positive integer, public exponent
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
    if (KMByteBlob.cast(pubKey).get((short) 0) < 0){
      pushByte((byte) 0x00);
      pushIntegerHeader((short)(KMByteBlob.cast(pubKey).length()+1));
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
    pushBitStringHeader((byte)0x00,KMByteBlob.cast(pubKey).length());
    pushEcDsa();
    pushSequenceHeader((short) (last - stackPtr));
  }
  private static void pushEcDsa(){
    short last = stackPtr;
    pushBytes(prime256v1,(short)0,(short)prime256v1.length);
    pushBytes(eccPubKey,(short)0,(short)eccPubKey.length);
    pushSequenceHeader((short)(last - stackPtr));
  }
  private static void pushRsaEncryption(){
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
    }else{
      pushOctetStringHeader((short)0);
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
    pushSequenceHeader((short)(last-stackPtr));
  }

  private static void pushSWParams() {
    short last = stackPtr;
    //ATTESTATION_APPLICATION_ID 709 is softwareenforced.
    short[] tagIds = {709, 706,705,704,703,702,701,601,600,509,508,507,506,505,
	                  504, 503, 402,401,400,303,200,10,6,5,3,2,1
                     };
    byte index = 0;
    do {
      if(tagIds[index] == KMType.ATTESTATION_APPLICATION_ID) {
    	pushAttIds(tagIds[index]);
    	continue;
      }
      pushParams(swParams, tagIds[index]);
    }while(++index < tagIds.length);
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static void pushHWParams() {
    short last = stackPtr;
    //Attestation ids are not included. As per VTS attestation ids are not supported currenlty.
    short[] tagIds = {706,705,704,703,702,701,601,600,509,508,507,506,505,
			          504, 503, 402,401,400,303,200,10,6,5,3,2,1
	                 };
    byte index = 0;
    do {
      if(pushAttIds(tagIds[index])) continue;
      if(tagIds[index] == KMType.ROOT_OF_TRUST) {
    	  pushRoT();
    	  continue;
      }
      if(pushParams(hwParams,tagIds[index])) continue;
    } while (++index < tagIds.length);
    pushSequenceHeader((short) (last - stackPtr));
  }

  private static boolean pushParams(short params, short tagId) {
    short index = 0;
    short arr = KMKeyParameters.cast(params).getVals();
    short len = KMArray.cast(arr).length();
    while (index < len) {
      short tag = KMArray.cast(arr).get(index);
      if(tagId == KMTag.getKey(tag)) {
        pushTag(tag);
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
    pushOctetString(repo.verifiedBootHash, (short) 0, (short) repo.verifiedBootHash.length);
    // verified boot state
    // TODO change this once verifiedBootState is supported in repo
    if (repo.selfSignedBootFlag) val = KMType.SELF_SIGNED_BOOT;
    else if (repo.verifiedBootFlag) val = KMType.VERIFIED_BOOT;
    else val = KMType.UNVERIFIED_BOOT;
    pushEnumerated(val);
    // device locked
    val = 0x00;
    if (repo.deviceLockedFlag) val = (byte) 0xFF;
    pushBoolean(val);
    // verified boot Key
    pushOctetString(repo.verifiedBootKey, (short) 0, (short) repo.verifiedBootKey.length);
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
  // All Attestation Id tags are byte tags/octet strings
  private static boolean pushAttIds(short tagId) {
    if (attAppId != 0 && KMType.ATTESTATION_APPLICATION_ID == tagId) {
      pushBytesTag(
          KMType.ATTESTATION_APPLICATION_ID,
          KMByteBlob.cast(attAppId).getBuffer(),
          KMByteBlob.cast(attAppId).getStartOff(),
          KMByteBlob.cast(attAppId).length());
      return true;
    }
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
    if (repo.getAuthKeyId() == 0) return;

    pushKeyIdentifier(
        repo.getCertDataBuffer(),
        repo.getAuthKeyId(),
        repo.getAuthKeyIdLen()); // key identifier is [0]'th tagged in a sequence
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
    if(len< 128){
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

  public static short sign(Signature signer) {
    short ret = signer.sign(stack,tbsOffset,tbsLength,stack,signatureOffset);
    //print(getBuffer(),getCertStart(),getCertLength());
    return ret;
  }
  public static short getCertStart(){
    return certStart;
  }
  public static short getCertEnd(){
    return (short)(start +length - 1);
  }
  public static short getCertLength(){
    return (short)(getCertEnd() - getCertStart() + 1);
  }
  public static short getBufferStart(){
    return start;
  }
  public static short getBufferLength(){
    return length;
  }
  public static byte[] getBuffer(){
    return stack;
  }

 /* private static void print(byte[] buf, short start, short length){
    StringBuilder sb = new StringBuilder();
    for(int i = start; i < (start+length); i++){
      sb.append(String.format("%02X", buf[i])) ;
      //if((i-start)%16 == 0 && (i-start) != 0) sb.append(String.format("\n"));
    }
    System.out.println(sb.toString());
  }*/
}
