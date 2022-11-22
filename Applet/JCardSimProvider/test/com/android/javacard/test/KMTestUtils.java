package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMAsn1Parser;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMCose;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMMap;
import com.android.javacard.keymaster.KMNInteger;
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
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
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
    buf[2] = (byte) 0x50;
    buf[3] = (byte) 0x00;
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
    buf[2] = (byte) 0x50;
    buf[3] = (byte) 0x00;
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
    System.out.println("Certificate=>");
    print(cert, certOff, certLen);
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

  public static boolean validateCertChain(KMSEProvider cryptoProvider, KMEncoder encoder,
      KMDecoder decoder, byte expCertAlg, byte expLeafCertAlg,
      short certChainArr) throws IOException {
    short arrLen = KMArray.cast(certChainArr).length();
    PublicKey previousKey = null;
    for(short i = 0; i < arrLen; i++) {
      short byteBlob = KMArray.cast(certChainArr).get((short) i);
      X509Certificate x509Cert =
          decodeCert(KMByteBlob.cast(byteBlob).getBuffer(), KMByteBlob.cast(byteBlob).getStartOff(),
          KMByteBlob.cast(byteBlob).length());
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
