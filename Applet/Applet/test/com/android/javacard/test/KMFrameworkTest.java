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

package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMBoolTag;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMSEProvider;
import com.android.javacard.keymaster.KMSEProviderImpl;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMType;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;

public class KMFrameworkTest {
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
  // AttestationApplicationId ::= SEQUENCE {
  //     *     packageInfoRecords SET OF PackageInfoRecord,
  //     *     signatureDigests   SET OF OCTET_STRING,
  //     * }
  //     *
  //     * PackageInfoRecord ::= SEQUENCE {
  //     *     packageName        OCTET_STRING,
  //     *     version            INTEGER,
  //     * }
  private static final byte[] attAppId = {0x30, 0x10, 0x31, 0x0B, 0x30, 0x04, 0x05, 'A', 'B', 'C',
    'D', 'E', 0x02, 0x01, 0x01, 0x31, 0x02, 0x04, 0x00};
  private static final byte[] attChallenge = {'c','h','a','l','l','e','n','g','e'};
  private static final byte[] expiryTime = {0x32,0x30,0x35,0x37,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5A};
  private static final byte[] authKeyId = {1,2,3,4,5,6,7,8,9,1,2,3,4,5,6,7,8,9,1,2};




  private short status;
  private short keyCharacteristics;
  private short keyBlob;
  private KMSEProvider sim;

  @Test
  public void test_Lifecycle_Success() {
    // Create simulator
    //KMJcardSimulator.jcardSim = true;
    sim = KMSEProviderImpl.instance();
    sim.bypassAesGcm();
    CardSimulator simulator = new CardSimulator();

    // Install applet
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMKeymasterApplet.class);

    // Select applet
    simulator.selectApplet(appletAID1);
//    testEncodeDecode();
    testProvisionCmd(simulator);
    testSetBootParams(simulator);
    testGetHwInfoCmd(simulator);
    testAddRngEntropyCmd(simulator);
    testGenerateRsaKey(simulator);
    testImportRsaKey(simulator);
    testGetKeyCharacteristics(simulator);
    testGenerateAesKey(simulator);
    testImportAesKey(simulator);
    testGetKeyCharacteristics(simulator);
    testGenerateEcKey(simulator);
    testImportEcKey(simulator);
    testGetKeyCharacteristics(simulator);
    testGenerate3DesKey(simulator);
    testImportDesKey(simulator);
    testGetKeyCharacteristics(simulator);
    testGenerateHmacKey(simulator);
    testImportHmacKey(simulator);
    testGetKeyCharacteristics(simulator);
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID1);

  }

  private void testEncodeDecode() {
    //128
    //ecb ode - blockmode
    //padding pkcs 7
    short arrPtr = KMArray.instance((short)4);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)128));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ECB);
    short blockMode = KMEnumArrayTag.instance(KMType.BLOCK_MODE,byteBlob);
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.PKCS7);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    KMArray.cast(arrPtr).add((short)0, boolTag);
    KMArray.cast(arrPtr).add((short)1, keySize);
    KMArray.cast(arrPtr).add((short)2, blockMode);
    KMArray.cast(arrPtr).add((short)3, paddingMode);
    byte[] buf = new byte[1024];
    KMEncoder encode = new KMEncoder();
    KMDecoder decode = new KMDecoder();
    short len = encode.encode(arrPtr, buf, (short)0);
    arrPtr = KMArray.instance((short)4);
    KMArray.cast(arrPtr).add((short)0, KMBoolTag.exp());
    KMArray.cast(arrPtr).add((short)1, KMIntegerTag.exp(KMType.UINT_TAG));
    KMArray.cast(arrPtr).add((short)2, KMEnumArrayTag.exp());
    KMArray.cast(arrPtr).add((short)3, KMEnumArrayTag.exp());
    arrPtr = decode.decode(arrPtr,buf,(short)0,len);
    KMArray arr = KMArray.cast(arrPtr);
    short val = 0;
    val = KMBoolTag.cast(arr.get((short)0)).getVal();
    val = KMInteger.cast(KMIntegerTag.cast(arr.get((short)1)).getValue()).getShort();
    val = KMEnumArrayTag.cast(arr.get((short)2)).get((short)0);;
    val = KMEnumArrayTag.cast(arr.get((short)3)).get((short)0);
  }

  private void testGetKeyCharacteristics(CardSimulator simulator) {
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x1D;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short keyChar = keyCharacteristics;
    short len = KMKeyCharacteristics.cast(keyChar).length();
    // test provision command
    short cmd = makeGetKeyCharKeyCmd();
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyChar(response);
    short len2 = KMKeyCharacteristics.cast(keyCharacteristics).length();
    short hwList = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short len3 = KMKeyParameters.cast(hwList).length();
    short swList = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    short len4 = KMKeyParameters.cast(swList).length();
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testProvisionCmd(CardSimulator simulator){

/*
    byte[] buf = new byte[1024];
      // test provision command
      short cmd = makeProvisionCmd();
      KMEncoder enc = new KMEncoder();
      short actualLen = enc.encode(cmd, buf, (short) 0);
      CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x23, 0x40, 0x00, buf, 0, actualLen);
      //print(commandAPDU.getBytes());;
      ResponseAPDU response = simulator.transmitCommand(commandAPDU);
      Assert.assertEquals(0x9000, response.getSW());
      */
    KMSEProvider cryptoProvider = KMSEProviderImpl.instance();
    KMEncoder encoder = new KMEncoder();
    KeyPair rsaKeyPair = cryptoProvider.createRsaKeyPair();
    byte[] pub = new byte[4];
    short len = ((RSAPublicKey)rsaKeyPair.getPublic()).getExponent(pub,(short)1);
    byte[] priv = new byte[256];
    byte[] mod = new byte[256];
    len = ((RSAPrivateKey)rsaKeyPair.getPrivate()).getModulus(mod,(short)0);
    len = ((RSAPrivateKey)rsaKeyPair.getPrivate()).getExponent(priv,(short)0);
    short arrPtr = KMArray.instance((short)15);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short)0));
    short byteBlob1 = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob1).add((short)0, KMType.RSA_PKCS1_1_5_SIGN);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob1);
    short byteBlob2 = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob2).add((short)0, KMType.ATTEST_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob2);
    KMArray.cast(arrPtr).add((short)0, boolTag);
    KMArray.cast(arrPtr).add((short)1, keySize);
    KMArray.cast(arrPtr).add((short)2, digest);
    KMArray.cast(arrPtr).add((short)3, rsaPubExpTag);
    KMArray.cast(arrPtr).add((short)4, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add((short)5, padding);
    KMArray.cast(arrPtr).add((short)6, purpose);
    byte[] buf = "Attestation Id".getBytes();
    //Attestatation Ids.
    KMArray.cast(arrPtr).add((short)7, KMByteTag.instance(KMType.ATTESTATION_ID_BRAND,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)8, KMByteTag.instance(KMType.ATTESTATION_ID_PRODUCT,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)9, KMByteTag.instance(KMType.ATTESTATION_ID_DEVICE,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)10, KMByteTag.instance(KMType.ATTESTATION_ID_MODEL,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)11, KMByteTag.instance(KMType.ATTESTATION_ID_IMEI,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)12, KMByteTag.instance(KMType.ATTESTATION_ID_MEID,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)13, KMByteTag.instance(KMType.ATTESTATION_ID_MANUFACTURER,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    KMArray.cast(arrPtr).add((short)14, KMByteTag.instance(KMType.ATTESTATION_ID_SERIAL,
      KMByteBlob.instance(buf,(short)0, (short)buf.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);// Note: VTS uses PKCS8
    short keyBlob = KMArray.instance((short)2);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(priv,(short)0,(short)256));
    KMArray.cast(keyBlob).add((short)1, KMByteBlob.instance(mod,(short)0,(short)256));
    byte[] blob = new byte[620];
    len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    arrPtr = KMArray.instance((short)6);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    short byteBlob3 = KMByteBlob.instance(X509Issuer, (short)0, (short)X509Issuer.length);
    arg.add((short)3, byteBlob3);
    short byteBlob4 = KMByteBlob.instance(expiryTime, (short)0, (short)expiryTime.length);
    arg.add((short)4, byteBlob4);
    short byteBlob5 = KMByteBlob.instance(authKeyId, (short)0, (short)authKeyId.length);
    arg.add((short)5, byteBlob5);
    CommandAPDU apdu = encodeApdu((byte)0x23, arrPtr);
    //print(apdu.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }
  private CommandAPDU encodeApdu(byte ins, short cmd){
    byte[] buf = new byte[2048];
    buf[0] = (byte)0x80;
    buf[1] = ins;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    KMEncoder encoder = new KMEncoder();
    short len = encoder.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, len);
    byte[] apdu = new byte[7+len];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+len));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    return new CommandAPDU(apdu);
  }


  public void testSetBootParams(CardSimulator simulator){
    byte[] buf = new byte[1024];
    // test provision command
    short cmd = makeSetBootParamsCmd();
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 0);
    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x24, 0x40, 0x00, buf, 0, actualLen);
    //print(commandAPDU.getBytes());;
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    Assert.assertEquals(0x9000, response.getSW());

  }

  public void testGenerateRsaKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x10;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    // test provision command
    short cmd = makeGenerateKeyCmd(KMType.RSA, (short)2048);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testImportRsaKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x11;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short cmd = makeImportKeyRsaCmd();
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testImportEcKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x11;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short cmd = makeImportKeyEcCmd();
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void extractKeyCharAndBlob(ResponseAPDU response) {
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    KMDecoder dec = new KMDecoder();
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = dec.decode(ret, respBuf, (short) 0, len);
    status = KMArray.cast(ret).get((short)0);
    keyBlob = KMArray.cast(ret).get((short)1);
    keyCharacteristics = KMArray.cast(ret).get((short)2);
  }

  private void extractKeyChar(ResponseAPDU response) {
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    KMDecoder dec = new KMDecoder();
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = dec.decode(ret, respBuf, (short) 0, len);
    status = KMArray.cast(ret).get((short)0);
    keyCharacteristics = KMArray.cast(ret).get((short)1);
  }

  public void testGenerateAesKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x10;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    // test provision command
    short cmd = makeGenerateKeyCmd(KMType.AES, (short)256);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testImportAesKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x11;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short cmd = makeImportKeySymmCmd(KMType.AES, (short)128);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }
  public void testImportHmacKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x11;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short cmd = makeImportKeySymmCmd(KMType.HMAC, (short)128);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }
  public void testImportDesKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x11;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short cmd = makeImportKeySymmCmd(KMType.DES, (short)168);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testGenerateHmacKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x10;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    // test provision command
    short cmd = makeGenerateKeyCmdHmac(KMType.HMAC, (short)128);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testGenerate3DesKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x10;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    // test provision command
    short cmd = makeGenerateKeyCmd(KMType.DES, (short)168);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testGenerateEcKey(CardSimulator simulator){
    byte[] buf = new byte[1024];
    buf[0] = (byte)0x80;
    buf[1] = (byte)0x10;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    // test provision command
    short cmd = makeGenerateKeyCmd(KMType.EC, (short)256);
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, actualLen);
    byte[] apdu = new byte[7+actualLen];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+actualLen));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    CommandAPDU commandAPDU = new CommandAPDU(apdu);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    extractKeyCharAndBlob(response);
    Assert.assertEquals(0x9000, response.getSW());
  }

  public void testGetHwInfoCmd(CardSimulator simulator){
    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x1E, 0x40, 0x00);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    KMDecoder dec = new KMDecoder();
    short arrPtr = KMArray.instance((short)3);
    KMArray exp = KMArray.cast(arrPtr);
      exp.add((short)0, KMEnum.instance(KMType.HARDWARE_TYPE));
      exp.add((short)1, KMByteBlob.exp());
      exp.add((short)2, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short)respBuf.length;
    short respPtr = dec.decode(arrPtr,respBuf, (short)0, len);
    Assert.assertEquals(3, KMArray.cast(respPtr).length());
    KMEnum secLevel = KMEnum.cast(KMArray.cast(respPtr).get((short)0));
    short kmName = KMArray.cast(respPtr).get((short)1);
    short authorName = KMArray.cast(respPtr).get((short)2);
    Assert.assertEquals(KMType.HARDWARE_TYPE, secLevel.getEnumType());
    Assert.assertEquals(KMType.STRONGBOX, secLevel.getVal());
    String kmNameStr = byteBlobToString(kmName);
    String authorNameStr = byteBlobToString(authorName);
    Assert.assertEquals( "JavacardKeymasterDevice",kmNameStr);
    Assert.assertEquals( "Google",authorNameStr);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void testAddRngEntropyCmd(CardSimulator simulator){
    byte[] buf = new byte[1024];
    // test provision command
    short cmd = makeAddRngEntropyCmd();
    KMEncoder enc = new KMEncoder();
    short actualLen = enc.encode(cmd, buf, (short) 0);

    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x18, 0x40, 0x00, buf, 0, actualLen);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    Assert.assertEquals(0x9000, response.getSW());
  }


  private String byteBlobToString(short blobPtr) {
    StringBuilder sb = new StringBuilder();
    KMByteBlob blob = KMByteBlob.cast(blobPtr);
    for(short i = 0; i<blob.length(); i++){
      sb.append((char)blob.get(i));
    }
    return sb.toString();
  }

  private void print(byte[] cmdApdu){
    StringBuilder sb = new StringBuilder();
    for(int i = 0; i < cmdApdu.length; i++){
      sb.append(String.format(" 0x%02X", cmdApdu[i])) ;
/*      if(((i-1)%38 == 0) && ((i-1) >0)){
        sb.append(";\n");
      }
*/    }
    System.out.println(sb.toString());
    System.out.println(cmdApdu.length);
  }

  private short makeProvisionCmd() {
    // Argument 1
    short arrPtr = KMArray.instance((short) 1);
    KMArray vals = KMArray.cast(arrPtr);
    vals.add((short) 0, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    short keyparamsPtr = KMKeyParameters.instance(arrPtr);
    // Argument 2
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.X509);
    // Argument 3
    byte[] byteBlob = new byte[48];
    for (short i = 0; i < 48; i++) {
      byteBlob[i] = (byte) i;
    }
    short keyBlobPtr = KMByteBlob.instance(byteBlob, (short) 0, (short)byteBlob.length);
    // Array of expected arguments
    short argPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(argPtr);
    arg.add((short) 0, keyparamsPtr);
    arg.add((short) 1, keyFormatPtr);
    arg.add((short) 2, keyBlobPtr);
    return argPtr;
  }

  private short makeGenerateKeyCmd(byte alg, short keysize) {
    // Argument
    short arrPtr = KMArray.instance((short) 4);
    KMArray vals = KMArray.cast(arrPtr);
    byte[] val = "Test".getBytes();
    byte[] intVal = {1, 2, 3, 4};
    byte[] pubVal = {0x00, 0x01, 0x00, 0x01};
    //byte[] digest = {KMType.SHA1, KMType.SHA2_256};
    byte[] digest = {KMType.DIGEST_NONE};
    byte[] padding = {KMType.PADDING_NONE};
    vals.add((short)0, KMEnumTag.instance(KMType.ALGORITHM, alg));
    vals.add((short)1, KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize)));
    //vals.add((short)1, KMIntegerTag.instance(KMType.UINT_TAG, KMType.USERID, KMInteger.uint_32(intVal, (short)0)));
    //vals.add((short)2, KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(val, (short)0, (short)val.length)));
     vals.add((short)2, KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pubVal,(short)0)));
    vals.add((short)3, KMEnumArrayTag.instance(KMType.DIGEST, KMByteBlob.instance(digest,(short)0, (short)digest.length)));
    //vals.add((short)5, KMEnumArrayTag.instance(KMType.PADDING, KMByteBlob.instance(padding,(short)0, (short)padding.length)));
    short keyParamsPtr = KMKeyParameters.instance(arrPtr);
    // Array of expected arguments
    short argPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(argPtr);
    arg.add((short) 0, keyParamsPtr);
    return argPtr;
  }
  private short makeImportKeySymmCmd(short alg, short size) {
    // Argument 1
    short arrPtr;
    byte digestType;
    if(alg == KMType.HMAC) {
      arrPtr = KMArray.instance((short) 6);
      digestType = KMType.SHA2_256;
    } else{
      arrPtr = KMArray.instance((short) 5);
      digestType = KMType.DIGEST_NONE;
    }
    KMArray vals = KMArray.cast(arrPtr);
    byte[] val = "Test".getBytes();
    byte[] intVal = {1, 2, 3, 4};
    byte[] pubVal = {0x00, 0x01, 0x00, 0x01};
    byte[] digest = new byte[1];
    digest[0] = digestType;
    vals.add((short)0, KMEnumTag.instance(KMType.ALGORITHM, (byte)alg));
    vals.add((short)1, KMIntegerTag.instance(KMType.UINT_TAG, KMType.USERID, KMInteger.uint_32(intVal, (short)0)));
    vals.add((short)2, KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(val, (short)0, (short)val.length)));
    vals.add((short)3, KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(size)));
    vals.add((short)4, KMEnumArrayTag.instance(KMType.DIGEST, KMByteBlob.instance(digest,(short)0, (short)digest.length)));
    if (alg == KMType.HMAC) {
      vals.add(
          (short) 5,KMIntegerTag.instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16(size)));
    }
    short keyParamsPtr = KMKeyParameters.instance(arrPtr);
    // Argument 2
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short len = 0;
    byte[] secret = new byte[32];
    Key key;
    // Argument 3
    switch (alg){
      case KMType.AES:
        key = sim.createAESKey(size);
        len = ((AESKey)key).getKey(secret, (short)0);
        break;
      case KMType.DES:
        key = sim.createTDESKey();
        size = 168;
        len = ((DESKey)key).getKey(secret, (short)0);
        break;
      case KMType.HMAC:
        key = sim.createHMACKey(size);
        len = ((HMACKey)key).getKey(secret, (short)0);
        break;
      default:
        return 0;
    }
    short keyBlob = KMArray.instance((short)1);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(secret,(short)0,len));
    KMEncoder encoder = new KMEncoder();
    byte[] blob = new byte[256];
    len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    // Array of expected arguments
    short argPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(argPtr);
    arg.add((short) 0, keyParamsPtr);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    return argPtr;
  }

  private short makeImportKeyRsaCmd() {
    // Argument 1
    short arrPtr = KMArray.instance((short) 5);
    KMArray vals = KMArray.cast(arrPtr);
    byte[] val = "Test".getBytes();
    byte[] intVal = {1, 2, 3, 4};
    byte[] pubVal = {0x00, 0x01, 0x00, 0x01};
    byte[] digest = {KMType.SHA1, KMType.SHA2_256};
    vals.add((short)0, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    vals.add((short)1, KMIntegerTag.instance(KMType.UINT_TAG, KMType.USERID, KMInteger.uint_32(intVal, (short)0)));
    vals.add((short)2, KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(val, (short)0, (short)val.length)));
    vals.add((short)3, KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pubVal,(short)0)));
    vals.add((short)4, KMBoolTag.instance(KMType.NO_AUTH_REQUIRED));

    //vals.add((short)4, KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048)));
    short keyParamsPtr = KMKeyParameters.instance(arrPtr);
    // Argument 2
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    // Argument 3
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    rsaKeyPair.genKeyPair();
    byte[] secret = new byte[256];
    byte[] modulus = new byte[256];
    short keyBlob = KMArray.instance((short)2);
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    short len = key.getExponent(secret, (short)0);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(secret,(short)0,len));
    len = key.getModulus(modulus, (short)0);
    KMArray.cast(keyBlob).add((short)1, KMByteBlob.instance(modulus,(short)0,len));
    KMEncoder encoder = new KMEncoder();
    byte[] blob = new byte[1024];
    len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    // Array of expected arguments
    short argPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(argPtr);
    arg.add((short) 0, keyParamsPtr);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    return argPtr;
  }

  private short makeImportKeyEcCmd() {
    // Argument 1
    short arrPtr = KMArray.instance((short) 4);
    KMArray vals = KMArray.cast(arrPtr);
    byte[] val = "Test".getBytes();
    byte[] intVal = {1, 2, 3, 4};
    byte[] pubVal = {0x00, 0x01, 0x00, 0x01};
    byte[] digest = {KMType.SHA1, KMType.SHA2_256};
    vals.add((short)0, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    vals.add((short)1, KMIntegerTag.instance(KMType.UINT_TAG, KMType.USERID, KMInteger.uint_32(intVal, (short)0)));
    vals.add((short)2, KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(val, (short)0, (short)val.length)));
    vals.add((short)3, KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pubVal,(short)0)));
    //vals.add((short)4, KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048)));
    short keyParamsPtr = KMKeyParameters.instance(arrPtr);
    // Argument 2
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    // Argument 3
    KeyPair ec192KeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
    ec192KeyPair.genKeyPair();
    byte[] secret = new byte[24];
    byte[] pubKey = new byte[52];
    short keyBlob = KMArray.instance((short)2);
    ECPrivateKey key1 = (ECPrivateKey) ec192KeyPair.getPrivate();
    ECPublicKey key2 = (ECPublicKey) ec192KeyPair.getPublic();
    short len = key1.getS(secret, (short)0);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(secret,(short)0,len));
    len = key2.getW(pubKey, (short)0);
    KMArray.cast(keyBlob).add((short)1, KMByteBlob.instance(pubKey,(short)0,len));
    KMEncoder encoder = new KMEncoder();
    byte[] blob = new byte[256];
    len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    // Array of expected arguments
    short argPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(argPtr);
    arg.add((short) 0, keyParamsPtr);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    return argPtr;
  }

  private short makeGetKeyCharKeyCmd() {
    // Argument
    short argPtr = KMArray.instance((short) 3);
    KMArray vals = KMArray.cast(argPtr);
    byte[] val = "Test".getBytes();
    byte[] intVal = {1, 2, 3, 4};
    byte[] pubVal = {0x00, 0x01, 0x00, 0x01};
    byte[] digest = {KMType.SHA2_256};
    vals.add((short)0, keyBlob);
    vals.add((short)1, KMByteBlob.instance(val, (short)0, (short)val.length));
    vals.add((short)2, KMByteBlob.instance((short)0));// No App Data
    return argPtr;
  }
  private short makeGenerateKeyCmdHmac(byte alg, short keysize) {
    // Argument
    short arrPtr = KMArray.instance((short) 6);
    KMArray vals = KMArray.cast(arrPtr);
    byte[] val = "Test".getBytes();
    byte[] intVal = {1, 2, 3, 4};
    byte[] digest = {KMType.SHA2_256};
    vals.add((short)0, KMEnumTag.instance(KMType.ALGORITHM, alg));
    vals.add((short)1, KMIntegerTag.instance(KMType.UINT_TAG, KMType.USERID, KMInteger.uint_32(intVal, (short)0)));
    vals.add((short)2, KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(val, (short)0, (short)val.length)));
    vals.add((short)3, KMIntegerTag.instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16(keysize)));
    vals.add((short)4, KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize)));
    vals.add((short)5, KMEnumArrayTag.instance(KMType.DIGEST, KMByteBlob.instance(digest,(short)0, (short)digest.length)));
    short keyParamsPtr = KMKeyParameters.instance(arrPtr);
    // Array of expected arguments
    short argPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(argPtr);
    arg.add((short) 0, keyParamsPtr);
    return argPtr;
  }

  private short makeSetBootParamsCmd() {
    // Argument 1 OS Version
    short versionPatchPtr = KMInteger.uint_16((short)1);
//    short versionTagPtr = KMIntegerTag.instance(KMType.UINT_TAG, KMType.OS_VERSION,versionPatchPtr);
    // Argument 2 OS Patch level
//    short patchTagPtr = KMIntegerTag.instance(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, versionPatchPtr);
    // Argument 3 Verified Boot Key
    byte[] bootKeyHash = "00011122233344455566677788899900".getBytes();
    short bootKeyPtr = KMByteBlob.instance(bootKeyHash,(short)0, (short)bootKeyHash.length);
    // Argument 4 Verified Boot Hash
    short bootHashPtr = KMByteBlob.instance(bootKeyHash,(short)0, (short)bootKeyHash.length);
    // Argument 5 Verified Boot State
    short bootStatePtr = KMEnum.instance(KMType.VERIFIED_BOOT_STATE,KMType.VERIFIED_BOOT);
    // Argument 6 Device Locked
    short deviceLockedPtr = KMEnum.instance(KMType.DEVICE_LOCKED, KMType.DEVICE_LOCKED_FALSE);
    // Arguments
    short arrPtr = KMArray.instance((short) 6);
    KMArray vals = KMArray.cast(arrPtr);
    vals.add((short)0, versionPatchPtr);
    vals.add((short) 1, versionPatchPtr);
    vals.add((short) 2, bootKeyPtr);
    vals.add((short) 3, bootHashPtr);
    vals.add((short) 4, bootStatePtr);
    vals.add((short) 5, deviceLockedPtr);
    return arrPtr;
  }

  private short makeAddRngEntropyCmd() {
    // Argument 1
    byte[] byteBlob = new byte[32];
    for (short i = 0; i < 32; i++) {
      byteBlob[i] = (byte) i;
    }
    short keyBlob = KMByteBlob.instance(byteBlob, (short) 0, (short)byteBlob.length);
    // Array of expected arguments
    short arrPtr =  KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    return arrPtr;
  }
}
