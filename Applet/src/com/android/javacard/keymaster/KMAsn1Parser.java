package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMException;
import javacard.framework.Util;

public class KMAsn1Parser {
  public static final byte ASN1_OCTET_STRING= 0x04;
  public static final byte ASN1_SEQUENCE= 0x30;
  public static final byte ASN1_SET= 0x31;
  public static final byte ASN1_INTEGER= 0x02;
  public static final byte OBJECT_IDENTIFIER = 0x06;
  public static final byte ASN1_A0_TAG = (byte) 0xA0;
  public static final byte ASN1_A1_TAG = (byte) 0xA1;
  public static final byte ASN1_BIT_STRING = 0x03;

  public static final byte ASN1_UTF8_STRING = 0x0C;
  public static final byte ASN1_TELETEX_STRING = 0x14;
  public static final byte ASN1_PRINTABLE_STRING = 0x13;
  public static final byte ASN1_UNIVERSAL_STRING = 0x1C;
  public static final byte ASN1_BMP_STRING = 0x1E;

  public static final byte[] EC_CURVE = {
      0x06,0x08,0x2a,(byte)0x86,0x48,(byte)0xce,0x3d,0x03,
      0x01,0x07
  };
  public static final byte[] RSA_ALGORITHM = {
      0x06,0x09,0x2A,(byte)0x86,0x48,(byte)0x86,
      (byte)0xF7,0x0D,0x01,0x01,0x01,0x05,0x00
  };
  public static final byte[] EC_ALGORITHM = {
      0x06,0x07,0x2a,(byte)0x86,0x48,(byte)0xce,
      0x3d,0x02,0x01,0x06,0x08,0x2a,(byte)0x86,0x48,
      (byte)0xce,0x3d,0x03,0x01,0x07
  };
  public static final byte[] COMMON_NAME_OID = {
      0x55, 0x04, 0x03  
  };
  private byte[] data;
  private short start;
  private short length;
  private short cur;
  private static KMAsn1Parser inst;
  private KMAsn1Parser(){
    start = 0;
    length =  0;
    cur = 0;
  }

  public short decodeRsa(short blob){
    init(blob);
    decodeCommon((short)0, RSA_ALGORITHM);
    return decodeRsaPrivateKey((short)0);
  }

  public short decodeEc(short blob){
    init(blob);
    decodeCommon((short)0, EC_ALGORITHM);
    return decodeEcPrivateKey((short)1);
  }
  
  public short decodeSubject(short blob) {
    init(blob);
    header(ASN1_SEQUENCE);
    header(ASN1_SET);
    header(ASN1_SEQUENCE);
    objectIdentifier(COMMON_NAME_OID);
    return subjectHeader();
  }

  public short decodeEcSubjectPublicKeyInfo(short blob) {
    init(blob);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_SEQUENCE);
    short ecPublicInfo = KMByteBlob.instance(len);
    getBytes(ecPublicInfo);
    if(Util.arrayCompare(
        KMByteBlob.cast(ecPublicInfo).getBuffer(),
        KMByteBlob.cast(ecPublicInfo).getStartOff(),
        EC_ALGORITHM,
        (short)0,KMByteBlob.cast(ecPublicInfo).length()) !=0){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_BIT_STRING);
    if(len < 1) KMException.throwIt(KMError.UNKNOWN_ERROR);
    // TODO need to handle if unused bits are not zero
    byte unusedBits = getByte();
    if(unusedBits != 0) KMException.throwIt(KMError.UNIMPLEMENTED);
    short pubKey = KMByteBlob.instance((short)(len -1));
    getBytes(pubKey);
    return pubKey;
  }

  //Seq[Int,Int,Int,Int,<ignore rest>]
  public short decodeRsaPrivateKey(short version){
    short resp = KMArray.instance((short)3);
    header(ASN1_OCTET_STRING);
    header(ASN1_SEQUENCE);
    short len =header(ASN1_INTEGER);
    if(len != 1) KMException.throwIt(KMError.UNKNOWN_ERROR);
    short ver = getByte();
    if(ver != version) KMException.throwIt(KMError.UNKNOWN_ERROR);
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
    KMArray.cast(resp).add((short)0, modulus);
    KMArray.cast(resp).add((short)1, pubKey);
    KMArray.cast(resp).add((short)2, privKey);
    return resp;
  }
  
  private void updateModulus(short blob) {
	  byte[] buffer = KMByteBlob.cast(blob).getBuffer();
	  short startOff = KMByteBlob.cast(blob).getStartOff();
	  short len = KMByteBlob.cast(blob).length();
	  if(0 == buffer[startOff] && len > 256) {
		  KMByteBlob.cast(blob).setStartOff(++startOff);
		  KMByteBlob.cast(blob).setLength(--len);
	  }
  }
  
  private short readEcdsa256SigIntegerHeader() {
    short len = header(ASN1_INTEGER);
    if (len == 33) {
      if (0 != getByte()) {
        KMException.throwIt(KMError.INVALID_DATA);
      }
      len--;
    } else if (len > 33) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return len;
  }
  
  // Seq [Int, Int]
  public short decodeEcdsa256Signature(short blob, byte[] scratchPad, short scratchPadOff) {
    init(blob);
    short len = header(ASN1_SEQUENCE);
    len = readEcdsa256SigIntegerHeader();
    // concatenate r and s in the buffer (r||s)
    Util.arrayFillNonAtomic(scratchPad, scratchPadOff, (short) 64, (byte) 0);
    // read r
    getBytes(scratchPad, (short) (scratchPadOff + 32 - len), len);
    len = readEcdsa256SigIntegerHeader();
    // read s 
    getBytes(scratchPad, (short) (scratchPadOff + 64 - len), len);
    return (short) 64;
  }

  // Seq [Int, Blob]
  public void decodeCommon(short version, byte[] alg){
    short len = header(ASN1_SEQUENCE);
    len = header(ASN1_INTEGER);
    if(len != 1) KMException.throwIt(KMError.UNKNOWN_ERROR);
    short ver = getByte();
    if(ver !=version) KMException.throwIt(KMError.UNKNOWN_ERROR);
    len = header(ASN1_SEQUENCE);
    short blob = KMByteBlob.instance(len);
    getBytes(blob);
    if(Util.arrayCompare(
        KMByteBlob.cast(blob).getBuffer(),
        KMByteBlob.cast(blob).getStartOff(),
        alg,
        (short)0,KMByteBlob.cast(blob).length()) !=0){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }

  //Seq[Int,blob,blob]
  public short decodeEcPrivateKey(short version){
    short resp = KMArray.instance((short)2);
    header(ASN1_OCTET_STRING);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_INTEGER);
    if(len != 1) KMException.throwIt(KMError.UNKNOWN_ERROR);
    short ver = getByte();
    if(ver != version) KMException.throwIt(KMError.UNKNOWN_ERROR);
    len = header(ASN1_OCTET_STRING);
    short privKey = KMByteBlob.instance(len);
    getBytes(privKey);
    validateTag0IfPresent();
    header(ASN1_A1_TAG);
    len = header(ASN1_BIT_STRING);
    if(len < 1) KMException.throwIt(KMError.UNKNOWN_ERROR);
    // TODO need to handle if unused bits are not zero
    byte unusedBits = getByte();
    if(unusedBits != 0) KMException.throwIt(KMError.UNIMPLEMENTED);
    short pubKey = KMByteBlob.instance((short)(len -1));
    getBytes(pubKey);
    KMArray.cast(resp).add((short)0, pubKey);
    KMArray.cast(resp).add((short)1, privKey);
    return resp;
  }
  private void validateTag0IfPresent(){
    if(data[cur] != ASN1_A0_TAG) return;;
    short len = header(ASN1_A0_TAG);
    if(len != EC_CURVE.length) KMException.throwIt(KMError.UNKNOWN_ERROR);
    if(Util.arrayCompare(data, cur, EC_CURVE, (short)0, len) != 0) KMException.throwIt(KMError.UNKNOWN_ERROR);
    incrementCursor(len);
  }
  
  private short objectIdentifier(byte[] oid) {
     short length = header(OBJECT_IDENTIFIER);
     if (length != oid.length) {
       KMException.throwIt(KMError.UNKNOWN_ERROR);
     }
     if(Util.arrayCompare(data, cur, oid, (short)0, length) != 0) KMException.throwIt(KMError.UNKNOWN_ERROR);
     incrementCursor(length);
     return length;
  }

  private short header(short tag){
    short t = getByte();
    if(t != tag) KMException.throwIt(KMError.UNKNOWN_ERROR);
    return getLength();
  }

  private short subjectHeader(){
    short t = getByte();
    if(t != ASN1_UTF8_STRING &&
	t != ASN1_TELETEX_STRING &&
	t != ASN1_PRINTABLE_STRING &&
	t != ASN1_UNIVERSAL_STRING &&
	t != ASN1_BMP_STRING) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return getLength();
  }

  private byte getByte(){
    byte d = data[cur];
    incrementCursor((short)1);
    return d;
  }

  private short getShort(){
    short d = Util.getShort(data, cur);
    incrementCursor((short)2);
    return d;
  }

  private void getBytes(short blob){
    short len = KMByteBlob.cast(blob).length();
    Util.arrayCopyNonAtomic(data, cur, KMByteBlob.cast(blob).getBuffer(),
        KMByteBlob.cast(blob).getStartOff(), len);
    incrementCursor(len);
  }

  private void getBytes(byte[] buffer, short offset, short len) {
    Util.arrayCopyNonAtomic(data, cur, buffer, offset, len);
    incrementCursor(len);
  }

  private short getLength(){
    byte len = getByte();
    if(len >= 0) return len;
    len = (byte)(len & 0x7F);
    if(len == 1) return (short)(getByte() & 0xFF);
    else if(len == 2) return getShort();
    else KMException.throwIt(KMError.UNKNOWN_ERROR);
    return KMType.INVALID_VALUE; //should not come here
  }
  public static KMAsn1Parser instance() {
    if (inst == null) {
      inst = new KMAsn1Parser();
    }
    return inst;
  }

  public void init(short blob) {
    data = KMByteBlob.cast(blob).getBuffer();
    start = KMByteBlob.cast(blob).getStartOff();
    length = KMByteBlob.cast(blob).length();
    cur = start;
  }

  public void incrementCursor(short n){
    cur += n;
    if(cur > ((short)(start+length))) KMException.throwIt(KMError.UNKNOWN_ERROR);
  }
}
