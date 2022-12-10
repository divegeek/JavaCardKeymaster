package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMAsn1Parser;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMCose;
import com.android.javacard.keymaster.KMCoseCertPayload;
import com.android.javacard.keymaster.KMCoseHeaders;
import com.android.javacard.keymaster.KMCoseKey;
import com.android.javacard.keymaster.KMCosePairIntegerTag;
import com.android.javacard.keymaster.KMCosePairNegIntegerTag;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMMap;
import com.android.javacard.keymaster.KMNInteger;
import com.android.javacard.keymaster.KMSemanticTag;
import com.android.javacard.keymaster.KMSimpleValue;
import com.android.javacard.keymaster.KMTextString;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.seprovider.KMDeviceUniqueKeyPair;
import com.android.javacard.seprovider.KMECPrivateKey;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;

public class KMTestUtils {

  public static byte[] kCoseEncodedEcdsa256RootCert = {
      (byte) 0x84, (byte) 0x43, (byte) 0xa1, (byte) 0x01, (byte) 0x26, (byte) 0xa0, (byte) 0x58,
      (byte) 0x4d, (byte) 0xa5, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x26, (byte) 0x20,
      (byte) 0x01, (byte) 0x21,
      0x58, (byte) 0x20, (byte) 0xf7, (byte) 0x14, (byte) 0x8a, (byte) 0xdb, (byte) 0x97,
      (byte) 0xf4, (byte) 0xcc, (byte) 0x53, (byte) 0xef, (byte) 0xd2, (byte) 0x64, (byte) 0x11,
      (byte) 0xc4, (byte) 0xe3,
      0x75, (byte) 0x1f, (byte) 0x66, (byte) 0x1f, (byte) 0xa4, (byte) 0x71, (byte) 0x0c,
      (byte) 0x6c, (byte) 0xcf, (byte) 0xfa, (byte) 0x09, (byte) 0x46, (byte) 0x80, (byte) 0x74,
      (byte) 0x87, (byte) 0x54,
      (byte) 0xf2, (byte) 0xad, (byte) 0x22, (byte) 0x58, (byte) 0x20, (byte) 0x5e, (byte) 0x7f,
      (byte) 0x5b, (byte) 0xf6, (byte) 0xec, (byte) 0xe4, (byte) 0xf6, (byte) 0x19, (byte) 0xcc,
      (byte) 0xff, (byte) 0x13,
      0x37, (byte) 0xfd, (byte) 0x0f, (byte) 0xa1, (byte) 0xc8, (byte) 0x93, (byte) 0xdb,
      (byte) 0x18, (byte) 0x06, (byte) 0x76, (byte) 0xc4, (byte) 0x5d, (byte) 0xe6, (byte) 0xd7,
      (byte) 0x6a, (byte) 0x77,
      (byte) 0x86, (byte) 0xc3, (byte) 0x2d, (byte) 0xaf, (byte) 0x8f, (byte) 0x58, (byte) 0x40,
      (byte) 0x2f, (byte) 0x97, (byte) 0x8e, (byte) 0x42, (byte) 0xfb, (byte) 0xbe, (byte) 0x07,
      (byte) 0x2d, (byte) 0x95,
      0x47, (byte) 0x85, (byte) 0x47, (byte) 0x93, (byte) 0x40, (byte) 0xb0, (byte) 0x1f,
      (byte) 0xd4, (byte) 0x9b, (byte) 0x47, (byte) 0xa4, (byte) 0xc4, (byte) 0x44, (byte) 0xa9,
      (byte) 0xf2, (byte) 0xa1,
      0x07, (byte) 0x87, (byte) 0x10, (byte) 0xc7, (byte) 0x9f, (byte) 0xcb, (byte) 0x11,
      (byte) 0xf4, (byte) 0xbf, (byte) 0x9f, (byte) 0xe8, (byte) 0x3b, (byte) 0xe0, (byte) 0xe7,
      (byte) 0x34, (byte) 0x4c,
      0x15, (byte) 0xfc, (byte) 0x7b, (byte) 0xc3, (byte) 0x7e, (byte) 0x33, (byte) 0x05,
      (byte) 0xf4, (byte) 0xd1, (byte) 0x34, (byte) 0x3c, (byte) 0xed, (byte) 0x02, (byte) 0x04,
      (byte) 0x60, (byte) 0x7a,
      0x15, (byte) 0xe0, (byte) 0x79, (byte) 0xd3, (byte) 0x8a, (byte) 0xff, (byte) 0x24};

  // The Google ECDSA P256 Endpoint Encryption Key certificate, encoded as COSE_Sign1
  public static byte[] kCoseEncodedEcdsa256GeekCert = {
      (byte) 0x84, (byte) 0x43, (byte) 0xa1, (byte) 0x01, (byte) 0x26, (byte) 0xa0, (byte) 0x58,
      (byte) 0x71, (byte) 0xa6, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x58, (byte) 0x20,
      (byte) 0x35, (byte) 0x73,
      (byte) 0xb7, (byte) 0x3f, (byte) 0xa0, (byte) 0x8a, (byte) 0x80, (byte) 0x89, (byte) 0xb1,
      (byte) 0x26, (byte) 0x67, (byte) 0xe9, (byte) 0xcb, (byte) 0x7c, (byte) 0x75, (byte) 0xa1,
      (byte) 0xaf, (byte) 0x02,
      0x61, (byte) 0xfc, (byte) 0x6e, (byte) 0x65, (byte) 0x03, (byte) 0x91, (byte) 0x3b,
      (byte) 0xd3, (byte) 0x4b, (byte) 0x7d, (byte) 0x14, (byte) 0x94, (byte) 0x3e, (byte) 0x46,
      (byte) 0x03, (byte) 0x38,
      0x18, (byte) 0x20, (byte) 0x01, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0xe0,
      (byte) 0x41, (byte) 0xcf, (byte) 0x2f, (byte) 0x0f, (byte) 0x34, (byte) 0x0f, (byte) 0x1c,
      (byte) 0x33, (byte) 0x2c,
      0x41, (byte) 0xb0, (byte) 0xcf, (byte) 0xd7, (byte) 0x0c, (byte) 0x30, (byte) 0x55,
      (byte) 0x35, (byte) 0xd2, (byte) 0x1e, (byte) 0x6a, (byte) 0x47, (byte) 0x13, (byte) 0x4b,
      (byte) 0x2e, (byte) 0xd1,
      0x48, (byte) 0x96, (byte) 0x7e, (byte) 0x24, (byte) 0x9c, (byte) 0x68, (byte) 0x22,
      (byte) 0x58, (byte) 0x20, (byte) 0x1f, (byte) 0xce, (byte) 0x45, (byte) 0xc5, (byte) 0xfb,
      (byte) 0x61, (byte) 0xba,
      (byte) 0x81, (byte) 0x21, (byte) 0xf9, (byte) 0xe5, (byte) 0x05, (byte) 0x9b, (byte) 0x9b,
      (byte) 0x39, (byte) 0x0e, (byte) 0x76, (byte) 0x86, (byte) 0x86, (byte) 0x47, (byte) 0xb8,
      (byte) 0x1e, (byte) 0x2f,
      0x45, (byte) 0xf1, (byte) 0xce, (byte) 0xaf, (byte) 0xda, (byte) 0x3f, (byte) 0x80,
      (byte) 0x68, (byte) 0xdb, (byte) 0x58, (byte) 0x40, (byte) 0x8c, (byte) 0xb3, (byte) 0xba,
      (byte) 0x7e, (byte) 0x20,
      0x3e, (byte) 0x32, (byte) 0xb0, (byte) 0x68, (byte) 0xdf, (byte) 0x60, (byte) 0xd1,
      (byte) 0x1d, (byte) 0x7d, (byte) 0xf0, (byte) 0xac, (byte) 0x38, (byte) 0x8e, (byte) 0x51,
      (byte) 0xbc, (byte) 0xff,
      0x6c, (byte) 0xe1, (byte) 0x67, (byte) 0x3b, (byte) 0x4a, (byte) 0x79, (byte) 0xbc,
      (byte) 0x56, (byte) 0x78, (byte) 0xb3, (byte) 0x99, (byte) 0xd8, (byte) 0x7c, (byte) 0x8a,
      (byte) 0x07, (byte) 0xd8,
      (byte) 0xda, (byte) 0xb5, (byte) 0xb5, (byte) 0x7f, (byte) 0x71, (byte) 0xf4, (byte) 0xd8,
      (byte) 0x6b, (byte) 0xdf, (byte) 0x33, (byte) 0x27, (byte) 0x34, (byte) 0x7b, (byte) 0x65,
      (byte) 0xd1, (byte) 0x2a,
      (byte) 0xeb, (byte) 0x86, (byte) 0x99, (byte) 0x98, (byte) 0xab, (byte) 0x3a, (byte) 0xb4,
      (byte) 0x80, (byte) 0xaa, (byte) 0xbd, (byte) 0x50};

  public static final byte APDU_P1 = 0x60;
  public static final byte APDU_P2 = 0x00;
  public static final short ADDITIONAL_MASK = 0x1F;
  private static final short UINT8_LENGTH = 0x18;
  private static final short UINT16_LENGTH = 0x19;
  public static final short MAJOR_TYPE_MASK = 0xE0;
  public static final byte CBOR_ARRAY_MAJOR_TYPE = (byte) 0x80;
  public static final byte CBOR_UINT_MAJOR_TYPE = 0x00;
  public static final short SE_POWER_RESET_FLAG = (short) 0x4000;
  public static final String PROD_EEK_ID =
      "3573B73FA08A8089B12667E9CB7C75A1AF0261FC6E6503913BD34B7D14943E46";
  public static final String PROD_PUB_KEY =
      "04E041CF2F0F340F1C332C41B0CFD70C305535D21E6A47134B2ED148967E249C681FCE45C5FB61BA812"
          + "1F9E5059B9B390E76868647B81E2F45F1CEAFDA3F8068DB";
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final short AES_GCM_AUTH_TAG_LENGTH = 16;

  public static CommandAPDU encodeApdu(KMEncoder encoder, byte ins, short cmd) {
    byte[] buf = new byte[2500];
    buf[0] = (byte) 0x80;
    buf[1] = ins;
    buf[2] = APDU_P1;
    buf[3] = APDU_P2;
    buf[4] = 0;
    short len = encoder.encode(cmd, buf, (short) 7, (short) 2500);
    Util.setShort(buf, (short) 5, len);
    byte[] apdu = new byte[7 + len];
    Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0, (short) (7 + len));
    print(buf, (short) 0, (short) (len + 7));
    return new CommandAPDU(apdu);
  }

  public static CommandAPDU encodeApdu(KMEncoder encoder, byte ins, byte[] encodedCmd) {
    byte[] buf = new byte[2500];
    buf[0] = (byte) 0x80;
    buf[1] = ins;
    buf[2] = APDU_P1;
    buf[3] = APDU_P2;
    buf[4] = 0;
    Util.arrayCopyNonAtomic(encodedCmd, (short) 0, buf, (short) 7, (short) encodedCmd.length);
    Util.setShort(buf, (short) 5, (short) encodedCmd.length);
    byte[] apdu = new byte[7 + (short) encodedCmd.length];
    Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0,
        (short) (7 + (short) encodedCmd.length));
    return new CommandAPDU(apdu);
  }

  public static byte readMajorType(byte[] resp) {
    byte val = resp[0];
    return (byte) (val & MAJOR_TYPE_MASK);
  }

  // payload length cannot be more then 16 bits.
  public static short readMajorTypeWithPayloadLength(byte[] resp, short majorType) {
    short cur = (short) 0;
    short payloadLength = 0;
    byte val = resp[cur++];
    if ((short) (val & MAJOR_TYPE_MASK) != majorType) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short lenType = (short) (val & ADDITIONAL_MASK);
    if (lenType > UINT16_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (lenType < UINT8_LENGTH) {
      payloadLength = lenType;
    } else if (lenType == UINT8_LENGTH) {
      payloadLength = (short) (resp[cur] & 0xFF);
    } else {
      payloadLength = Util.getShort(resp, cur);
    }
    return payloadLength;
  }

  public static short decodeCoseMac(KMDecoder decoder, byte[] coseMac, short coseMacOff,
      short coseMacLen) {
    short arrPtr = KMArray.instance((short) 4);
    short coseHeadersExp = KMCoseHeaders.exp();
    KMArray.cast(arrPtr).add((short) 0, KMByteBlob.exp());
    KMArray.cast(arrPtr).add((short) 1, coseHeadersExp);
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.exp());
    KMArray.cast(arrPtr).add((short) 3, KMByteBlob.exp());
    short ret = decoder.decode(arrPtr, coseMac, coseMacOff, coseMacLen);
    return ret;
  }

  public static short getCoseKeyFromCoseMac(KMDecoder decoder, short coseMacPtr) {
    short payload = KMArray.cast(coseMacPtr).get((short) 2);
    return decoder.decode(KMCoseKey.exp(), KMByteBlob.cast(payload).getBuffer(),
        KMByteBlob.cast(payload).getStartOff(),
        KMByteBlob.cast(payload).length());
  }

  public static short getDeviceInfoExp() {
    short textStrExp = KMTextString.exp();
    short byteBlobExp = KMByteBlob.exp();
    short intExp = KMInteger.exp();
    short map = KMMap.instance((short) 15);
    // Canonical order is hard-coded.
    //brand
    KMMap.cast(map).add((short) 0, textStrExp, textStrExp);
    // fused
    KMMap.cast(map).add((short) 1, textStrExp, intExp);
    // model
    KMMap.cast(map).add((short) 2, textStrExp, textStrExp);
    // device
    KMMap.cast(map).add((short) 3, textStrExp, textStrExp);
    //product
    KMMap.cast(map).add((short) 4, textStrExp, textStrExp);
    // device info version
    KMMap.cast(map).add((short) 5, textStrExp, intExp);
    // vb state
    KMMap.cast(map).add((short) 6, textStrExp, textStrExp);
    // osVersion
    KMMap.cast(map).add((short) 7, textStrExp, textStrExp);
    //manufacturer
    KMMap.cast(map).add((short) 8, textStrExp, textStrExp);
    // verified boot hash
    KMMap.cast(map).add((short) 9, textStrExp, byteBlobExp);
    // security level
    KMMap.cast(map).add((short) 10, textStrExp, textStrExp);
    // boot patch level
    KMMap.cast(map).add((short) 11, textStrExp, intExp);
    // bootloader state
    KMMap.cast(map).add((short) 12, textStrExp, textStrExp);
    // system patch level
    KMMap.cast(map).add((short) 13, textStrExp, intExp);
    // vendor patch level
    KMMap.cast(map).add((short) 14, textStrExp, intExp);
    return map;
  }

  public static short generateEEk(KMSEProvider cryptoProvider, KMEncoder encoder, KeyPair eekKey,
      byte[] eekId, short length) {
    byte[] pub = new byte[65]; // EC Public key
    byte[] priv = new byte[32]; // EC Private Key
    short[] lengths = new short[2];
    KeyPair signingKey = null;
    short alg = KMNInteger.uint_8(KMCose.COSE_ALG_ES256);
    short xPtr = 0;
    short yPtr = 0;
    short keyId = KMType.INVALID_VALUE;
    short eekChainArr = KMArray.instance(length);

    for (short i = 0; i < length; i++) {
      KeyPair keyPair;
      if (i == (length - 1)) {
        keyPair = eekKey;
        getEcKeys(keyPair, pub, priv, lengths);
      } else {
        keyPair = generateEcKeyPair(cryptoProvider, pub, priv, lengths);
      }
      if (i == 0) { // First key is self signed.
        signingKey = keyPair;
      }
      // prepare coseKey and encode it.
      if (pub[0] == 0x04) { // uncompressed
        short pubLen = lengths[1];
        pubLen = (short) ((pubLen - 1) / 2);
        xPtr = KMByteBlob.instance(pub, (short) 1, pubLen);
        yPtr = KMByteBlob.instance(pub, (short) (pubLen + 1), pubLen);
      } else {
        Assert.fail("Not in uncompressed form.");
      }
      if (i == length - 1) {
        alg = KMNInteger.uint_8(KMCose.COSE_ALG_ECDH_ES_HKDF_256);
        keyId = KMByteBlob.instance(eekId, (short) 0, (short) eekId.length);
      }
      short[] scratchBufferEncode = new short[20];
      short coseKey =
          KMCose.constructCoseKey(scratchBufferEncode,
              KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
              keyId,
              alg,
              KMType.INVALID_VALUE,
              KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
              xPtr,
              yPtr,
              KMType.INVALID_VALUE);
      byte[] scratchpad = new byte[200];
      short coseKeyEncodedLen = encoder.encode(coseKey, scratchpad, (short) 0, (short) 200);
      short payload = KMByteBlob.instance(scratchpad, (short) 0, coseKeyEncodedLen);
      //print(KMByteBlob.cast(payload).getBuffer(), KMByteBlob.cast(payload).getStartOff(),
      //    KMByteBlob.cast(payload).length());

      // Prepare protectedHeader
      short headerPtr = KMCose.constructHeaders(scratchBufferEncode,
          KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
          KMType.INVALID_VALUE,
          KMType.INVALID_VALUE,
          KMType.INVALID_VALUE);
      // Encode the protected header as byte blob.
      byte[] coseHeaders = new byte[200];
      short coseHeadersLen = encoder.encode(headerPtr, coseHeaders, (short) 0, (short) 200);
      short protectedHeader = KMByteBlob.instance(coseHeadersLen);
      Util.arrayCopyNonAtomic(coseHeaders, (short) 0, KMByteBlob.cast(protectedHeader).getBuffer(),
          KMByteBlob.cast(protectedHeader).getStartOff(), coseHeadersLen);

      // prepare Cose Sign_Structure
      byte[] coseSignStructureEncoded = new byte[200];
      short coseSignStructureEncodedLen;
      short coseSignStructure =
          KMCose.constructCoseSignStructure(protectedHeader, KMByteBlob.instance((short) 0),
              payload);
      coseSignStructureEncodedLen = encoder.encode(coseSignStructure, coseSignStructureEncoded,
          (short) 0, (short) 200);

      // Sign the Sign_structure with signingKey.
      KMECPrivateKey privateKey = new KMECPrivateKey(signingKey);
      short signLen =
          cryptoProvider.ecSign256(privateKey,
              coseSignStructureEncoded, (short) 0, coseSignStructureEncodedLen, scratchpad,
              (short) 0);
      short signPtr = KMByteBlob.instance(scratchpad, (short) 0, signLen);
      KMAsn1Parser asn1Parser = KMAsn1Parser.instance();
      signLen = asn1Parser.decodeEcdsa256Signature(signPtr, scratchpad, (short) 0);
      KMByteBlob.cast(signPtr).setValue(scratchpad, (short) 0, signLen);

      // prepare Cose_Sign1
      short emptyArr = KMArray.instance((short) 0);
      KMCoseHeaders.instance(emptyArr);
      short coseSign1 =
          KMCose.constructCoseSign1(protectedHeader,
              KMCoseHeaders.instance(emptyArr),
              payload,
              signPtr);

      KMArray.cast(eekChainArr).add(i, coseSign1);

      // copy signing key
      signingKey = keyPair;
    }
    return eekChainArr;
  }

  public static short receiveErrorCodeExp() {
    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMInteger.exp());
    return arr;
  }

  public static short getErrorCode(short arr) {
    return KMInteger.cast(KMArray.cast(arr).get((short) 0)).getShort();
  }

  public static X509Certificate decodeCert(byte[] cert, short certOff, short certLen)
      throws IOException {
    byte[] certificate = new byte[certLen];
    Util.arrayCopyNonAtomic(cert, certOff, certificate, (short) 0, certLen);
    InputStream inStream = new ByteArrayInputStream(certificate);
    CertificateFactory certFactory;
    try {
      certFactory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      // Should not happen, as X.509 is mandatory for all providers.
      throw new RuntimeException(e);
    }
    try {
      return (X509Certificate) certFactory.generateCertificate(inStream);
    } catch (CertificateException e) {
      throw new IOException(e);
    }
  }

  public static boolean validateCertChain(short certChainArr) {
    short arrLen = KMArray.cast(certChainArr).length();
    PublicKey previousKey = null;
    for (short i = 0; i < arrLen; i++) {
      short byteBlob = KMArray.cast(certChainArr).get((short) i);

      X509Certificate x509Cert = null;
      try {
        x509Cert = decodeCert(KMByteBlob.cast(byteBlob).getBuffer(),
            KMByteBlob.cast(byteBlob).getStartOff(),
            KMByteBlob.cast(byteBlob).length());
      } catch (IOException e) {
        Assert.fail("Failed to parse certificate");
      }
      if (i == 0) {
        previousKey = x509Cert.getPublicKey();
      }
      try {
        x509Cert.checkValidity();
      } catch (CertificateException e) {
        Assert.fail("Certificate validity expired.");
      }
      try {
        x509Cert.verify(previousKey);
      } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
          NoSuchProviderException | SignatureException e) {
        Assert.fail("Certificate verification failed.");
        e.printStackTrace();
      }
      previousKey = x509Cert.getPublicKey();
    }
    return true;
  }

  public static boolean isSignedByte(byte b) {
    return ((b & 0x0080) != 0);
  }

  public static short writeIntegerHeader(short valueLen, byte[] data, short offset) {
    // write length
    data[offset] = (byte) valueLen;
    // write INTEGER tag
    offset--;
    data[offset] = 0x02;
    return offset;
  }

  public static short writeSequenceHeader(short valueLen, byte[] data, short offset) {
    // write length
    data[offset] = (byte) valueLen;
    // write INTEGER tag
    offset--;
    data[offset] = 0x30;
    return offset;
  }

  public static short writeSignatureData(byte[] input, short inputOff, short inputlen,
      byte[] output,
      short offset) {
    Util.arrayCopyNonAtomic(input, inputOff, output, offset, inputlen);
    if (isSignedByte(input[inputOff])) {
      offset--;
      output[offset] = (byte) 0;
    }
    return offset;
  }

  public static short encodeES256CoseSignSignature(byte[] input, short offset, short len,
      byte[] scratchPad, short scratchPadOff) {
    // SEQ [ INTEGER(r), INTEGER(s)]
    // write from bottom to the top
    if (len != 64) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short maxTotalLen = 72;
    short end = (short) (scratchPadOff + maxTotalLen);
    // write s.
    short start = (short) (end - 32);
    start = writeSignatureData(input, (short) (offset + 32), (short) 32, scratchPad, start);
    // write length and header
    short length = (short) (end - start);
    start--;
    start = writeIntegerHeader(length, scratchPad, start);
    // write r
    short rEnd = start;
    start = (short) (start - 32);
    start = writeSignatureData(input, offset, (short) 32, scratchPad, start);
    // write length and header
    length = (short) (rEnd - start);
    start--;
    start = writeIntegerHeader(length, scratchPad, start);
    // write length and sequence header
    length = (short) (end - start);
    start--;
    start = writeSequenceHeader(length, scratchPad, start);
    length = (short) (end - start);
    if (start > scratchPadOff) {
      // re adjust the buffer
      Util.arrayCopyNonAtomic(scratchPad, start, scratchPad, scratchPadOff, length);
    }
    return length;
  }

  public static short getDccPublicKey(KMSEProvider cryptoProvider, KMEncoder encoder,
      KMDecoder decoder, short dccPtr, byte[] pub, short pubOff) {
    short len = KMArray.cast(dccPtr).length();
    short pubKeyLen = 0;
    short prevCoseKey = KMArray.cast(dccPtr).get((short) 0);
    for (short index = 1; index < len; index++) {
      //--------------------------------------------
      //  Validate Cose_Sign1
      //--------------------------------------------
      short coseSign1Arr = KMArray.cast(dccPtr).get(index);
      // Validate protected Header.
      short headers = KMArray.cast(coseSign1Arr).get((short) 0);
      short protectedHeader = headers;
      headers =
          decoder.decode(KMCoseHeaders.exp(), KMByteBlob.cast(headers).getBuffer(),
              KMByteBlob.cast(headers).getStartOff(), KMByteBlob.cast(headers).length());
      Assert.assertEquals(KMCose.COSE_ALG_ES256,
          (byte) KMNInteger.cast(KMCoseHeaders.cast(headers).getAlgorithm()).getShort());
      // Validate unprotected header.
      headers = KMArray.cast(coseSign1Arr).get((short) 1);
      Assert.assertEquals(0, KMCoseHeaders.cast(headers).length());
      // Get the payload.
      short payload = KMArray.cast(coseSign1Arr).get((short) 2);
      // Get the signature
      short signature = KMArray.cast(coseSign1Arr).get((short) 3);
      // Construct COSE_Struct.
      short signStructure =
          KMCose.constructCoseSignStructure(protectedHeader, KMByteBlob.instance((short) 0),
              payload);
      byte[] input = new byte[1024];
      short inputLen = encoder.encode(signStructure, input, (short) 0, (short) 1024);
      //Get public key from the coseKey.
      pubKeyLen = KMCoseKey.cast(prevCoseKey).getEcdsa256PublicKey(pub, pubOff);
      byte[] scratchPad = new byte[80];
      short signatureLen =
          encodeES256CoseSignSignature(
              KMByteBlob.cast(signature).getBuffer(),
              KMByteBlob.cast(signature).getStartOff(),
              KMByteBlob.cast(signature).length(),
              scratchPad,
              (short) 0);
      // Verify the signature of cose sign1.
      Assert.assertTrue(
          cryptoProvider.ecVerify256(pub, pubOff, pubKeyLen, input, (short) 0, inputLen,
              scratchPad, (short) 0, signatureLen));

      // Get the public key from the payload.
      short certPayload = KMCoseCertPayload.exp();
      short payloadPtr =
          decoder.decode(certPayload, KMByteBlob.cast(payload).getBuffer(),
              KMByteBlob.cast(payload).getStartOff(),
              KMByteBlob.cast(payload).length());
      short coseKeyPtr = KMCoseCertPayload.cast(payloadPtr).getSubjectPublicKey();
      coseKeyPtr = decoder.decode(KMCoseKey.exp(), KMByteBlob.cast(coseKeyPtr).getBuffer(),
          KMByteBlob.cast(coseKeyPtr).getStartOff(), KMByteBlob.cast(coseKeyPtr).length());
      prevCoseKey = coseKeyPtr;
    }
    return pubKeyLen;
  }

  public static void validateSignedMac(KMSEProvider cryptoProvider, KMEncoder encoder,
      KMDecoder decoder,
      byte[] csrChallenge, byte[] encodedCoseKeysArray, short signedMacPtr, byte[] pub,
      short pubOff, short pubLen,
      short deviceInfoMapPtr, short pubKeysToSignMac) {
    //--------------------------------------------
    //  Validate Cose_Sign1
    //--------------------------------------------
    short headers = KMArray.cast(signedMacPtr).get((short) 0);
    short protectedHeader = headers;
    headers =
        decoder.decode(KMCoseHeaders.exp(), KMByteBlob.cast(headers).getBuffer(),
            KMByteBlob.cast(headers).getStartOff(), KMByteBlob.cast(headers).length());
    Assert.assertEquals(KMCose.COSE_ALG_ES256,
        (byte) KMNInteger.cast(KMCoseHeaders.cast(headers).getAlgorithm()).getShort());
    // Validate unprotected header.
    headers = KMArray.cast(signedMacPtr).get((short) 1);
    Assert.assertEquals(0, KMCoseHeaders.cast(headers).length());
    // Get the payload.
    short payload = KMArray.cast(signedMacPtr).get((short) 2);
    // Get the signature
    short signature = KMArray.cast(signedMacPtr).get((short) 3);
    // Prepare Aad [Challenge + deviceInfoMap]
    short aad = KMArray.instance((short) 3);
    KMArray.cast(aad).add((short) 0,
        KMByteBlob.instance(csrChallenge, (short) 0, (short) csrChallenge.length));
    KMArray.cast(aad).add((short) 1, deviceInfoMapPtr);
    KMArray.cast(aad).add((short) 2, pubKeysToSignMac);
    byte[] aadBuf = new byte[512];
    short aadLen = encoder.encode(aad, aadBuf, (short) 0, (short) 512);
    aad = KMByteBlob.instance(aadBuf, (short) 0, aadLen);
    // Construct COSE_Struct.
    short signStructure =
        KMCose.constructCoseSignStructure(protectedHeader, aad, payload);
    byte[] input = new byte[1024];
    short inputLen = encoder.encode(signStructure, input, (short) 0, (short) 1024);
    byte[] signatureBuf = new byte[80];
    short signatureLen =
        encodeES256CoseSignSignature(KMByteBlob.cast(signature).getBuffer(),
            KMByteBlob.cast(signature).getStartOff(),
            KMByteBlob.cast(signature).length(), signatureBuf, (short) 0);
    // Verify the signature of cose sign1.
    Assert.assertTrue(cryptoProvider.ecVerify256(pub, pubOff, pubLen, input, (short) 0, inputLen,
        signatureBuf, (short) 0, signatureLen));
    //--------------------------------------------
    //  Get the ephemeral mac key and verify the signed mac keys.
    //--------------------------------------------
    short mac =
        constructPubKeysToSignMac(cryptoProvider, encoder,
            KMByteBlob.cast(payload).getBuffer(),
            KMByteBlob.cast(payload).getStartOff(),
            KMByteBlob.cast(payload).length(),
            KMByteBlob.instance(encodedCoseKeysArray, (short) 0,
                (short) encodedCoseKeysArray.length));
    Assert.assertEquals(0,
        Util.arrayCompare(
            KMByteBlob.cast(mac).getBuffer(),
            KMByteBlob.cast(mac).getStartOff(),
            KMByteBlob.cast(pubKeysToSignMac).getBuffer(),
            KMByteBlob.cast(pubKeysToSignMac).getStartOff(),
            KMByteBlob.cast(pubKeysToSignMac).length()
        )
    );
  }

  public static short constructPubKeysToSignMac(KMSEProvider cryptoProvider, KMEncoder encoder,
      byte[] ephemeralKey,
      short ephemeralKeyOff, short ephemeralKeyLen, short pubKeysToSign) {
    short ptr;
    short len;
    byte[] scratchPad = new byte[2048];
    short[] headerScratchpad = new short[15];
    short headerPtr = KMCose.constructHeaders(headerScratchpad,
        KMInteger.uint_8(KMCose.COSE_ALG_HMAC_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    len = encoder.encode(headerPtr, scratchPad, (short) 0, (short) 2048);
    short protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, len);
    // create MAC_Structure
    ptr =
        KMCose.constructCoseMacStructure(protectedHeader, KMByteBlob.instance((short) 0),
            pubKeysToSign);
    // Encode the Mac_structure and do HMAC_Sign to produce the tag for COSE_MAC0
    len = encoder.encode(ptr, scratchPad, (short) 0, (short) 2048);
    ptr =
        cryptoProvider.hmacSign(
            ephemeralKey,
            ephemeralKeyOff,
            ephemeralKeyLen,
            scratchPad,
            (short) 0,
            len,
            scratchPad,
            len // offset
        );
    return KMByteBlob.instance(scratchPad, len, ptr);
  }

  public static short constructCoseSign1(KMSEProvider cryptoProvider, KMEncoder encoder,
      short protectedHeader, short unProtectedHeader, short payload,
      short aad,
      KMDeviceUniqueKeyPair signingKey) {
    byte[] scratchpad = new byte[500];
    short signStructure = KMCose.constructCoseSignStructure(protectedHeader, aad, payload);
    signStructure = encoder.encode(signStructure, scratchpad, (short) 0, (short) 500);
    short len = cryptoProvider.ecSign256(signingKey, scratchpad, (short) 0, signStructure,
        scratchpad, signStructure);
    signStructure = KMByteBlob.instance(scratchpad, signStructure, len);
    KMAsn1Parser asn1Parser = KMAsn1Parser.instance();
    len = asn1Parser.decodeEcdsa256Signature(signStructure, scratchpad, (short) 0);
    KMByteBlob.cast(signStructure).setValue(scratchpad, (short) 0, len);
    return KMCose.constructCoseSign1(protectedHeader, unProtectedHeader, payload, signStructure);
  }

  public static short constructCoseKey(short keyType, short keyId, short keyAlg, short keyOps,
      short curve,
      byte[] pubKey, short pubKeyOff, short pubKeyLen,
      byte[] priv, short privKeyOff, short privKeyLen) {
    if (pubKey[pubKeyOff] == 0x04) { // uncompressed format
      pubKeyOff += 1;
      pubKeyLen -= 1;
    }
    pubKeyLen = (short) (pubKeyLen / 2);
    short xPtr = KMByteBlob.instance(pubKey, pubKeyOff, pubKeyLen);
    short yPtr = KMByteBlob.instance(pubKey, (short) (pubKeyOff + pubKeyLen), pubKeyLen);
    short privPtr = KMByteBlob.instance(priv, privKeyOff, privKeyLen);
    short[] scratchpad = new short[20];
    short coseKey = KMCose.constructCoseKey(scratchpad, keyType, keyId, keyAlg, keyOps, curve, xPtr,
        yPtr, privPtr);
    KMCoseKey.cast(coseKey).canonicalize();
    return coseKey;
  }

  public static short getSenderPublicKeyAndKeyIdFromRecipientStructure(KMDecoder decoder,
      byte[] EEK_KEY_ID, short protectedDataArrPtr,
      byte[] pub, short pubOff,
      byte[] eekId, short eekIdOff, short eekIdLen) {
    //--------------------------------------------
    // Get Recipients and validate recipients
    //--------------------------------------------
    short recipientsArr = KMArray.cast(protectedDataArrPtr).get((short) 3);
    // recipients array should contain only 1 recipient.
    Assert.assertEquals(1, KMArray.cast(recipientsArr).length());
    short recipient = KMArray.cast(recipientsArr).get((short) 0);
    // The recipient should be an array of length 3.
    Assert.assertEquals(3, KMArray.cast(recipient).length());
    // The 3rd element inside the recipient should be an null value of simple type.
    short simplePtr = KMArray.cast(recipient).get((short) 2);
    Assert.assertEquals(KMSimpleValue.NULL, KMSimpleValue.cast(simplePtr).getValue());
    //--------------------------------------------
    // Get and validate protected parameters inside the recipient structure.
    //--------------------------------------------
    short params = KMArray.cast(recipient).get((short) 0);
    //print(KMByteBlob.cast(params).getBuffer(),
    //KMByteBlob.cast(params).getStartOff(), KMByteBlob.cast(params).length());
    params =
        decoder.decode(KMCoseHeaders.exp(), KMByteBlob.cast(params).getBuffer(),
            KMByteBlob.cast(params).getStartOff(), KMByteBlob.cast(params).length());
    params = KMCoseHeaders.cast(params).getVals();
    // The length of the protected params is 1 and the algorithm should be ECDH_ES_HKDF_256.
    Assert.assertEquals(1, KMArray.cast(params).length());
    short param = KMArray.cast(params).get((short) 0);
    Assert.assertEquals(KMCose.COSE_ALG_ECDH_ES_HKDF_256,
        (byte) KMNInteger.cast(KMCosePairNegIntegerTag.cast(param).getValuePtr()).getShort());
    //--------------------------------------------
    // Get and validate unprotected parameters inside the recipient structure.
    //--------------------------------------------
    params = KMArray.cast(recipient).get((short) 1);
    short coseKey = KMCoseHeaders.cast(params).getCoseKey();
    //--------------------------------------------
    // Validate the COSE_Key.
    //--------------------------------------------
    short[] scratchBuffer = new short[20];
    Assert.assertTrue(
        KMCoseKey.cast(coseKey)
            .isDataValid(scratchBuffer, KMCose.COSE_KEY_TYPE_EC2, KMType.INVALID_VALUE,
                KMCose.COSE_ALG_ES256,
                KMType.INVALID_VALUE, KMCose.COSE_ECCURVE_256));
    //--------------------------------------------
    // Validate the EEK Key id.
    //--------------------------------------------
    short receivedEekId = KMCoseHeaders.cast(params).getKeyIdentifier();
    Assert.assertEquals(eekIdLen, KMByteBlob.cast(receivedEekId).length());
    Assert.assertEquals(0,
        Util.arrayCompare(EEK_KEY_ID, (short) 0, KMByteBlob.cast(receivedEekId).getBuffer(),
            KMByteBlob.cast(receivedEekId).getStartOff(), eekIdLen));
    Util.arrayCopyNonAtomic(KMByteBlob.cast(receivedEekId).getBuffer(),
        KMByteBlob.cast(receivedEekId).getStartOff(), eekId, eekIdOff, eekIdLen);
    return KMCoseKey.cast(coseKey).getEcdsa256PublicKey(pub, pubOff);
  }

  public static short ecdhHkdfDeriveKey(KMSEProvider cryptoProvider, KMEncoder encoder,
      byte[] privKeyA, short privKeyAOff, short privKeyALen,
      byte[] pubKeyA,
      short pubKeyAOff, short pubKeyALen, byte[] pubKeyB, short pubKeyBOff,
      short pubKeyBLen, byte[] sessionKey, short sessionKeyOff) {
    byte[] scratchPad = new byte[1024];
    short key =
        cryptoProvider.ecdhKeyAgreement(privKeyA, privKeyAOff, privKeyALen, pubKeyB, pubKeyBOff,
            pubKeyBLen, scratchPad, (short) 0);
    key = KMByteBlob.instance(scratchPad, (short) 0, key);

    // ignore 0x04 for ephemerical public key as kdfContext should not include 0x04.
    pubKeyAOff += 1;
    pubKeyALen -= 1;
    pubKeyBOff += 1;
    pubKeyBLen -= 1;
    short kdfContext =
        KMCose.constructKdfContext(pubKeyA, pubKeyAOff, pubKeyALen, pubKeyB, pubKeyBOff, pubKeyBLen,
            false);
    kdfContext = encoder.encode(kdfContext, scratchPad, (short) 0, (short) 1024);
    kdfContext = KMByteBlob.instance(scratchPad, (short) 0, kdfContext);

    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 32, (byte) 0);
    cryptoProvider.hkdf(
        KMByteBlob.cast(key).getBuffer(),
        KMByteBlob.cast(key).getStartOff(),
        KMByteBlob.cast(key).length(),
        scratchPad,
        (short) 0,
        (short) 32,
        KMByteBlob.cast(kdfContext).getBuffer(),
        KMByteBlob.cast(kdfContext).getStartOff(),
        KMByteBlob.cast(kdfContext).length(),
        scratchPad,
        (short) 32, // offset
        (short) 32 // Length of expected output.
    );
    Util.arrayCopy(scratchPad, (short) 32, sessionKey, sessionKeyOff, (short) 32);
    return (short) 32;
  }

  public static KeyPair generateEcKeyPair(KMSEProvider cryptoProvider, byte[] pub, byte[] priv,
      short[] lengths) {
    cryptoProvider
        .createAsymmetricKey(KMType.EC, priv, (short) 0, (short) priv.length, pub, (short) 0,
            (short) pub.length,
            lengths);
    KeyPair eekKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPrivateKey ecPrivateKey = (ECPrivateKey) eekKey.getPrivate();
    ecPrivateKey.setS(priv, (short) 0, lengths[0]);
    ECPublicKey ecPublicKey = (ECPublicKey) eekKey.getPublic();
    ecPublicKey.setW(pub, (short) 0, lengths[1]);
    return eekKey;
  }

  public static void getEcKeys(KeyPair ecKeyPair, byte[] pub, byte[] priv, short[] lengths) {
    ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
    lengths[0] = ecPrivateKey.getS(priv, (short) 0);
    ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
    lengths[1] = ecPublicKey.getW(pub, (short) 0);
  }

  public static KeyPair getEcKeyPair(byte[] pub, short pubOff, short pubLen,
      byte[] priv, short privOff, short privLen) {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    if (privLen != 0) {
      ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
      ecPrivateKey.setS(priv, (short) 0, privLen);
    }
    if (pubLen != 0) {
      ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
      ecPublicKey.setW(pub, (short) 0, pubLen);
    }
    return ecKeyPair;
  }

  public static short generateCoseMac0Mac(KMSEProvider cryptoProvider, KMEncoder encoder,
      byte[] macKey, short macKeyOff, short macKeyLen, short extAad, short payload,
      short protectedHeader, byte[] scratchpad, short offset, short outLength) {
    if (macKeyLen == 0) {
      return 0;
    }
    // Create MAC Structure and compute HMAC as per https://tools.ietf.org/html/rfc8152#section-6.3
    //    MAC_structure = [
    //        context : "MAC" / "MAC0",
    //        protected : empty_or_serialized_map,
    //        external_aad : bstr,
    //        payload : bstr
    //   ]
    short arrPtr = KMArray.instance(KMCose.COSE_MAC0_ENTRY_COUNT);
    // 1 - Context
    KMArray.cast(arrPtr).add((short) 0, KMTextString.instance(KMCose.MAC_CONTEXT, (short) 0,
        (short) KMCose.MAC_CONTEXT.length));
    // 2 - Protected headers.
    KMArray.cast(arrPtr).add((short) 1, protectedHeader);
    // 3 - external aad
    KMArray.cast(arrPtr).add((short) 2, extAad);
    // 4 - payload.
    KMArray.cast(arrPtr).add((short) 3, payload);
    // Do encode
    short len = encoder.encode(arrPtr, scratchpad, offset, outLength);
    short hmacLen = cryptoProvider.hmacSign(macKey, macKeyOff, macKeyLen, scratchpad, offset, len,
        scratchpad, (short) (offset + len));
    Util.arrayCopy(scratchpad, (short) (offset + len), scratchpad, offset, hmacLen);
    return hmacLen;
  }

  public static short getEmptyKeyParams() {
    // Empty attest key params
    short emptyArr = KMArray.instance((short) 0);
    return KMKeyParameters.instance(emptyArr);
  }

  public static void print(short blob) {
    print(KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff(),
        KMByteBlob.cast(blob).length());
  }

  public static void print(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format(" 0x%02X", buf[i]));
    }
    System.out.println(sb.toString());
  }

  public static void printCert(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format("%02X", buf[i]));
    }
    System.out.println(sb.toString());
  }

  public static short translateExtendedErrorCodes(short err) {
    switch (err) {
      case KMError.SW_CONDITIONS_NOT_SATISFIED:
      case KMError.UNSUPPORTED_CLA:
      case KMError.INVALID_P1P2:
      case KMError.INVALID_DATA:
      case KMError.CRYPTO_ILLEGAL_USE:
      case KMError.CRYPTO_ILLEGAL_VALUE:
      case KMError.CRYPTO_INVALID_INIT:
      case KMError.CRYPTO_UNINITIALIZED_KEY:
      case KMError.GENERIC_UNKNOWN_ERROR:
        err = KMError.UNKNOWN_ERROR;
        break;
      case KMError.CRYPTO_NO_SUCH_ALGORITHM:
        err = KMError.UNSUPPORTED_ALGORITHM;
        break;
      case KMError.UNSUPPORTED_INSTRUCTION:
      case KMError.CMD_NOT_ALLOWED:
      case KMError.SW_WRONG_LENGTH:
        err = KMError.UNIMPLEMENTED;
        break;
      default:
        break;
    }
    return err;
  }

  public static short extractKeyBlobArray(KMDecoder decoder, byte[] buf, short off, short buflen) {
    short byteBlobExp = KMByteBlob.exp();
    short keyChar = KMKeyCharacteristics.exp();
    short keyParam = KMKeyParameters.exp();
    short ret = KMArray.instance(KMKeymasterApplet.ASYM_KEY_BLOB_SIZE_V2_V3);
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_VERSION_OFFSET, KMInteger.exp());// Version
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_SECRET, byteBlobExp);// Secret
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_NONCE, byteBlobExp);// Nonce
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, byteBlobExp);// AuthTag
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_PARAMS, keyChar);// KeyChars
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_CUSTOM_TAGS, keyParam);// KeyChars
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, byteBlobExp);// PubKey

    ret = decoder.decodeArray(ret, buf, off, buflen);
    return ret;
  }

  public static short getPublicKey(KMDecoder decoder, byte[] keyBlob, short off, short len,
      byte[] pubKey, short pubKeyOff) {
    short keyBlobPtr = extractKeyBlobArray(decoder, keyBlob, off, len);
    short arrayLen = KMArray.cast(keyBlobPtr).length();
    if (arrayLen < KMKeymasterApplet.ASYM_KEY_BLOB_SIZE_V2_V3) {
      return 0;
    }
    short pubKeyPtr = KMArray.cast(keyBlobPtr).get(
        KMKeymasterApplet.KEY_BLOB_PUB_KEY);
    Util.arrayCopy(KMByteBlob.cast(pubKeyPtr).getBuffer(),
        KMByteBlob.cast(pubKeyPtr).getStartOff(), pubKey, pubKeyOff,
        KMByteBlob.cast(pubKeyPtr).length());
    return KMByteBlob.cast(pubKeyPtr).length();
  }

  public static short decodeError(KMDecoder decoder, ResponseAPDU response) {
    byte[] respBuf = response.getBytes();
    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMInteger.exp());
    arr = decoder.decode(arr, respBuf, (short) 0, (short) respBuf.length);
    return KMInteger.cast(KMArray.cast(arr).get((short) 0)).getShort();
  }

  public static String toHexString(byte[] num) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < num.length; i++) {
      sb.append(String.format("%02X", num[i]));
    }
    return sb.toString();
  }
}
