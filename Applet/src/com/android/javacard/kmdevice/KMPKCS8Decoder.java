package com.android.javacard.kmdevice;

import javacard.framework.Util;

public class KMPKCS8Decoder {

  public static final byte ASN1_OCTET_STRING = 0x04;
  public static final byte ASN1_SEQUENCE = 0x30;
  public static final byte ASN1_INTEGER = 0x02;
  public static final byte ASN1_A0_TAG = (byte) 0xA0;
  public static final byte ASN1_A1_TAG = (byte) 0xA1;
  public static final byte ASN1_BIT_STRING = 0x03;
  public static byte[] EC_CURVE;
  public static byte[] RSA_ALGORITHM;
  public static byte[] EC_ALGORITHM;
  private byte[] data;
  private short start;
  private short length;
  private short cur;
  private static KMPKCS8Decoder inst;

  private KMPKCS8Decoder() {
    start = 0;
    length = 0;
    cur = 0;
  }

  public static void initStatics() {
    EC_CURVE = new byte[]{
        0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03,
        0x01, 0x07
    };
    RSA_ALGORITHM = new byte[]{
        0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86,
        (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    EC_ALGORITHM = new byte[]{
        0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48,
        (byte) 0xce, 0x3d, 0x03, 0x01, 0x07
    };
  }

  public short decodeRsa(short blob) {
    init(blob);
    decodeCommon((short) 0, RSA_ALGORITHM);
    return decodeRsaPrivateKey((short) 0);
  }

  public short decodeEc(short blob) {
    init(blob);
    decodeCommon((short) 0, EC_ALGORITHM);
    return decodeEcPrivateKey((short) 1);
  }

  public short decodeEcSubjectPublicKeyInfo(short blob) {
    init(blob);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_SEQUENCE);
    short ecPublicInfo = KMByteBlob.instance(len);
    getBytes(ecPublicInfo);
    if (Util.arrayCompare(
        KMByteBlob.getBuffer(ecPublicInfo),
        KMByteBlob.getStartOff(ecPublicInfo),
        EC_ALGORITHM,
        (short) 0, KMByteBlob.length(ecPublicInfo)) != 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_BIT_STRING);
    if (len < 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // TODO need to handle if unused bits are not zero
    byte unusedBits = getByte();
    if (unusedBits != 0) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    short pubKey = KMByteBlob.instance((short) (len - 1));
    getBytes(pubKey);
    return pubKey;
  }

  //Seq[Int,Int,Int,Int,<ignore rest>]
  public short decodeRsaPrivateKey(short version) {
    short resp = KMArray.instance((short) 3);
    header(ASN1_OCTET_STRING);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short ver = getByte();
    if (ver != version) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_INTEGER);
    short modulus = KMByteBlob.instance(len);
    getBytes(modulus);
    updateModulus(modulus);
    len = header(ASN1_INTEGER);
    short pubKey = KMByteBlob.instance(len);
    getBytes(pubKey);
    len = header(ASN1_INTEGER);
    short privKey = KMByteBlob.instance(len);
    getBytes(privKey);
    KMArray.add(resp, (short) 0, modulus);
    KMArray.add(resp, (short) 1, pubKey);
    KMArray.add(resp, (short) 2, privKey);
    return resp;
  }

  private void updateModulus(short blob) {
    byte[] buffer = KMByteBlob.getBuffer(blob);
    short startOff = KMByteBlob.getStartOff(blob);
    short len = KMByteBlob.length(blob);
    if (0 == buffer[startOff] && len > 256) {
      KMByteBlob.setStartOff(blob, ++startOff);
      KMByteBlob.setLength(blob, --len);
    }
  }

  // Seq [Int, Blob]
  public void decodeCommon(short version, byte[] alg) {
    short len = header(ASN1_SEQUENCE);
    len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short ver = getByte();
    if (ver != version) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_SEQUENCE);
    short blob = KMByteBlob.instance(len);
    getBytes(blob);
    if (Util.arrayCompare(
        KMByteBlob.getBuffer(blob),
        KMByteBlob.getStartOff(blob),
        alg,
        (short) 0, KMByteBlob.length(blob)) != 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }

  //Seq[Int,blob,blob]
  public short decodeEcPrivateKey(short version) {
    short resp = KMArray.instance((short) 2);
    header(ASN1_OCTET_STRING);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short ver = getByte();
    if (ver != version) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_OCTET_STRING);
    short privKey = KMByteBlob.instance(len);
    getBytes(privKey);
    validateTag0IfPresent();
    header(ASN1_A1_TAG);
    len = header(ASN1_BIT_STRING);
    if (len < 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // TODO need to handle if unused bits are not zero
    byte unusedBits = getByte();
    if (unusedBits != 0) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    short pubKey = KMByteBlob.instance((short) (len - 1));
    getBytes(pubKey);
    KMArray.add(resp, (short) 0, pubKey);
    KMArray.add(resp, (short) 1, privKey);
    return resp;
  }

  private void validateTag0IfPresent() {
    if (data[cur] != ASN1_A0_TAG) {
      return;
    }
    ;
    short len = header(ASN1_A0_TAG);
    if (len != EC_CURVE.length) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (Util.arrayCompare(data, cur, EC_CURVE, (short) 0, len) != 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    incrementCursor(len);
  }

  private short header(short tag) {
    short t = getByte();
    if (t != tag) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return getLength();
  }

  private byte getByte() {
    byte d = data[cur];
    incrementCursor((short) 1);
    return d;
  }

  private short getShort() {
    short d = Util.getShort(data, cur);
    incrementCursor((short) 2);
    return d;
  }

  private void getBytes(short blob) {
    short len = KMByteBlob.length(blob);
    Util.arrayCopyNonAtomic(data, cur, KMByteBlob.getBuffer(blob),
        KMByteBlob.getStartOff(blob), len);
    incrementCursor(len);
  }

  private short getLength() {
    byte len = getByte();
    if (len >= 0) {
      return len;
    }
    len = (byte) (len & 0x7F);
    if (len == 1) {
      return (short) (getByte() & 0xFF);
    } else if (len == 2) {
      return getShort();
    } else {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMType.INVALID_VALUE; //should not come here
  }

  public static KMPKCS8Decoder instance() {
    if (inst == null) {
      inst = new KMPKCS8Decoder();
    }
    return inst;
  }

  public void init(short blob) {
    data = KMByteBlob.getBuffer(blob);
    start = KMByteBlob.getStartOff(blob);
    length = KMByteBlob.length(blob);
    cur = start;
  }

  public void incrementCursor(short n) {
    cur += n;
    if (cur > ((short) (start + length))) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }
}
