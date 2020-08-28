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
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMHardwareAuthToken;
import com.android.javacard.keymaster.KMHmacSharingParameters;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMRepository;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.keymaster.KMVerificationToken;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;

public class KMFunctionalTest {
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

  private KMSEProvider sim;
  private CardSimulator simulator;
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMSEProvider cryptoProvider;

  public KMFunctionalTest(){
    cryptoProvider = KMSEProviderImpl.instance();
    sim = KMSEProviderImpl.instance();
    simulator = new CardSimulator();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
  }

  private void init(){
    // Create simulator
    //KMJcardSimulator.jcardSim = true;
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMKeymasterApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    provisionCmd(simulator);
    // set bootup parameters
    setBootParams(simulator,(short)1,(short)1);
  }

  private void setBootParams(CardSimulator simulator, short osVersion, short osPatchLevel){
    // Argument 1 OS Version
    short versionPtr = KMInteger.uint_16(osVersion);
//    short versionTagPtr = KMIntegerTag.instance(KMType.UINT_TAG, KMType.OS_VERSION,versionPatchPtr);
    // Argument 2 OS Patch level
    short patchPtr = KMInteger.uint_16(osPatchLevel);
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
    vals.add((short)0, versionPtr);
    vals.add((short) 1, patchPtr);
    vals.add((short) 2, bootKeyPtr);
    vals.add((short) 3, bootHashPtr);
    vals.add((short) 4, bootStatePtr);
    vals.add((short) 5, deviceLockedPtr);
    CommandAPDU apdu = encodeApdu((byte)0x24, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());

  }

  //TODO change this
  private void provisionCmd(CardSimulator simulator) {
/*    // Argument 1
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
    CommandAPDU apdu = encodeApdu((byte)0x23, argPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
*/
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
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void cleanUp(){
    AID appletAID1 = AIDUtil.create("A000000062");
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID1);
  }

  private CommandAPDU encodeApdu(byte ins, short cmd){
    byte[] buf = new byte[2048];
    buf[0] = (byte)0x80;
    buf[1] = ins;
    buf[2] = (byte)0x40;
    buf[3] = (byte)0x00;
    buf[4] = 0;
    short len = encoder.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short)5, len);
    byte[] apdu = new byte[7+len];
    Util.arrayCopyNonAtomic(buf,(short)0,apdu,(short)0,(short)(7+len));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    return new CommandAPDU(apdu);
  }

  @Test
  public void testAesImportKeySuccess() {
    init();
    byte[] aesKeySecret = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    short arrPtr = KMArray.instance((short)5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)128));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ECB);
    short blockMode = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.PKCS7);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    KMArray.cast(arrPtr).add((short)0, boolTag);
    KMArray.cast(arrPtr).add((short)1, keySize);
    KMArray.cast(arrPtr).add((short)2, blockMode);
    KMArray.cast(arrPtr).add((short)3, paddingMode);
    KMArray.cast(arrPtr).add((short)4, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short keyBlob = KMArray.instance((short)1);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(aesKeySecret,(short)0,(short)16));
    byte[] blob = new byte[256];
    short len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    arrPtr = KMArray.instance((short)3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte)0x11, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(),0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PKCS7));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.ECB));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.AES);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testHmacImportKeySuccess() {
    init();
    byte[] hmacKeySecret = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    short arrPtr = KMArray.instance((short)5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)128));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short minMacLength = KMIntegerTag.instance(KMType.UINT_TAG,KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)256));
    KMArray.cast(arrPtr).add((short)0, boolTag);
    KMArray.cast(arrPtr).add((short)1, keySize);
    KMArray.cast(arrPtr).add((short)2, digest);
    KMArray.cast(arrPtr).add((short)3, minMacLength);
    KMArray.cast(arrPtr).add((short)4, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short keyBlob = KMArray.instance((short)1);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(hmacKeySecret,(short)0,(short)16));
    byte[] blob = new byte[256];
    short len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    arrPtr = KMArray.instance((short)3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte)0x11, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(),0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.HMAC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testRsaImportKeySuccess() {
    init();
    KeyPair rsaKeyPair = cryptoProvider.createRsaKeyPair();
    byte[] pub = new byte[4];
    short len = ((RSAPublicKey)rsaKeyPair.getPublic()).getExponent(pub,(short)1);
    byte[] priv = new byte[256];
    byte[] mod = new byte[256];
    len = ((RSAPrivateKey)rsaKeyPair.getPrivate()).getModulus(mod,(short)0);
    len = ((RSAPrivateKey)rsaKeyPair.getPrivate()).getExponent(priv,(short)0);
    short arrPtr = KMArray.instance((short)6);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short)0));
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.RSA_PSS);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    KMArray.cast(arrPtr).add((short)0, boolTag);
    KMArray.cast(arrPtr).add((short)1, keySize);
    KMArray.cast(arrPtr).add((short)2, digest);
    KMArray.cast(arrPtr).add((short)3, rsaPubExpTag);
    KMArray.cast(arrPtr).add((short)4, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add((short)5, padding);
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);// Note: VTS uses PKCS8
    short keyBlob = KMArray.instance((short)2);
    KMArray.cast(keyBlob).add((short)0, KMByteBlob.instance(priv,(short)0,(short)256));
    KMArray.cast(keyBlob).add((short)1, KMByteBlob.instance(mod,(short)0,(short)256));
    byte[] blob = new byte[620];
    len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    arrPtr = KMArray.instance((short)3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte)0x11, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(),0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 2048);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.RSA_PSS));
    tag = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getSignificantShort(), 0x01);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 0x01);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.RSA);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testDeviceLocked(){
    init();
    byte[] hmacKey = new byte[32];
    cryptoProvider.newRandomNumber(hmacKey,(short)0,(short)32);
    KMRepository.instance().initComputedHmac(hmacKey,(short)0,(short)32);
    // generate aes key with unlocked_device_required
    short aesKey = generateAesDesKey(KMType.AES,(short)128,null,null, true);
    short keyBlobPtr = KMArray.cast(aesKey).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    // encrypt something
    short inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    byte[] plainData= "Hello World 123!".getBytes();
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.ENCRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,false, false
    );
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      cipherData,(short)0, (short)cipherData.length);
    // create verification token
    short verToken = KMVerificationToken.instance();
    KMVerificationToken.cast(verToken).setTimestamp(KMInteger.uint_16((short)1));
    verToken = signVerificationToken(verToken);
    // device locked request
    deviceLock(verToken);
    // decrypt should fail
    inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    short beginResp = begin(KMType.DECRYPT,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),  KMKeyParameters.instance(inParams), (short)0);
    Assert.assertEquals(beginResp,KMError.DEVICE_LOCKED);
    short hwToken = KMHardwareAuthToken.instance();
    KMHardwareAuthToken.cast(hwToken).setTimestamp(KMInteger.uint_16((byte)2));
    KMHardwareAuthToken.cast(hwToken).setHwAuthenticatorType(KMEnum.instance(KMType.USER_AUTH_TYPE, (byte)KMType.PASSWORD));
    inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    hwToken = signHwToken(hwToken);
      ret = processMessage(cipherData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.DECRYPT,
      KMKeyParameters.instance(inParams),hwToken,null,false, false
    );
    ret = KMArray.cast(ret).get((short)0);
    Assert.assertEquals(KMInteger.cast(ret).getShort(), KMError.OK);
  cleanUp();
  }

  private short signHwToken(short hwToken){
    short len = 0;
    byte[] scratchPad = new byte[256];
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    short ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
    KMInteger.cast(ptr)
      .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getUserId();
    KMInteger.cast(ptr)
      .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getAuthenticatorId();
    KMInteger.cast(ptr)
      .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += 4;
    // concatenate timestamp -8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
    KMInteger.cast(ptr)
      .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // hmac the data
    HMACKey key =
      cryptoProvider.createHMACKey(
        KMRepository.instance().getComputedHmacKey(),
        (short) 0,
        (short) KMRepository.instance().getComputedHmacKey().length);
    byte[] mac = new byte[32];
    len =
      cryptoProvider.hmacSign(key, scratchPad, (short) 0, len,
        mac,
        (short)0);
    KMHardwareAuthToken.cast(hwToken).setMac(KMByteBlob.instance(mac,(short)0,(short)mac.length));
    return hwToken;
  }
  private void deviceLock(short verToken) {
    short req = KMArray.instance((short)2);
    KMArray.cast(req).add((short)0, KMInteger.uint_8((byte)1));
    KMArray.cast(req).add((short)1, verToken);
    CommandAPDU apdu = encodeApdu((byte)0x25,req);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 1);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(respBuf[0],KMError.OK);
  }

  private short signVerificationToken(short verToken) {
    byte[] scratchPad = new byte[256];
    byte[] authVer = "Auth Verification".getBytes();
    //print(authVer,(short)0,(short)authVer.length);
    // concatenation length will be 37 + length of verified parameters list  - which is typically empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    short params = KMVerificationToken.cast(verToken).getParametersVerified();
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopy(authVer,(short)0, scratchPad, (short)0, (short)authVer.length);
    short len = (short)authVer.length;
    // concatenate challenge - 8 bytes
    short ptr = KMVerificationToken.cast(verToken).getChallenge();
    KMInteger.cast(ptr)
      .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.cast(verToken).getTimestamp();
    KMInteger.cast(ptr)
      .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate security level - 4 bytes
    ptr = KMVerificationToken.cast(verToken).getSecurityLevel();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += 4;
    // concatenate Parameters verified - blob of encoded data.
    ptr = KMVerificationToken.cast(verToken).getParametersVerified();
    if (KMByteBlob.cast(ptr).length() != 0) {
      len += KMByteBlob.cast(ptr).getValues(scratchPad, (short) 0);
    }
    // hmac the data
    HMACKey key =
      cryptoProvider.createHMACKey(
        KMRepository.instance().getComputedHmacKey(),
        (short) 0,
        (short) KMRepository.instance().getComputedHmacKey().length);
    ptr = KMVerificationToken.cast(verToken).getMac();
    byte[] mac = new byte[32];
    len =
      cryptoProvider.hmacSign(key, scratchPad, (short) 0, len,
        mac,
        (short)0);
    KMVerificationToken.cast(verToken).setMac(KMByteBlob.instance(mac,(short)0,(short)mac.length));
    return verToken;
  }

  @Test
  public void testEcImportKeySuccess() {
    init();
    KeyPair ecKeyPair = cryptoProvider.createECKeyPair();
    byte[] pub = new byte[128];
    short len = ((ECPublicKey)ecKeyPair.getPublic()).getW(pub,(short)0);
    short pubBlob = KMByteBlob.instance(pub,(short)0,len);
    byte[] priv = new byte[32];
    len = ((ECPrivateKey)ecKeyPair.getPrivate()).getS(priv,(short)0);
    short privBlob = KMByteBlob.instance(priv,(short)0,len);
    short arrPtr = KMArray.instance((short)5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)256));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
    KMArray.cast(arrPtr).add((short)0, boolTag);
    KMArray.cast(arrPtr).add((short)1, keySize);
    KMArray.cast(arrPtr).add((short)2, digest);
    KMArray.cast(arrPtr).add((short)3, ecCurve);
    KMArray.cast(arrPtr).add((short)4, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);// Note: VTS uses PKCS8
    short keyBlob = KMArray.instance((short)2);
    KMArray.cast(keyBlob).add((short)0, privBlob);
    KMArray.cast(keyBlob).add((short)1, pubBlob);
    byte[] blob = new byte[128];
    len = encoder.encode(keyBlob,blob,(short)0);
    keyBlob = KMByteBlob.instance(blob, (short)0, len);
    arrPtr = KMArray.instance((short)3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short)1, keyFormatPtr);
    arg.add((short)2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte)0x11, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short blobArr = extractKeyBlobArray(KMArray.cast(ret).get((short)1));
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(),0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ECCURVE, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.P_256);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.EC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  private short extractKeyBlobArray(short keyBlob) {
    short ret = KMArray.instance((short) 5);
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    short ptr = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR, ptr);
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    ret =
      decoder.decodeArray(
        ret,
        KMByteBlob.cast(keyBlob).getBuffer(),
        KMByteBlob.cast(keyBlob).getStartOff(),
        KMByteBlob.cast(keyBlob).length());
    short len = KMArray.cast(ret).length();
    ptr = KMArray.cast(ret).get((short)4);
//    print(KMByteBlob.cast(ptr).getBuffer(),KMByteBlob.cast(ptr).getStartOff(),KMByteBlob.cast(ptr).length());
    return ret;
  }

  @Test
  public void testRsaGenerateKeySuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 2048);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.DIGEST_NONE));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.RSA_PKCS1_1_5_ENCRYPT));
    tag = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getSignificantShort(), 0x01);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 0x01);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.RSA);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  private short generateRsaKey(byte[] clientId, byte[] appData){
    byte[] activeAndCreationDateTime = {0,0,0x01,0x73,0x51,0x7C,(byte)0xCC,0x00};
    short tagCount = 11;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048));
    short byteBlob = KMByteBlob.instance((short)3);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.SHA2_256);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.SHA1);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short)5);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.RSA_PKCS1_1_5_ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.RSA_PKCS1_1_5_SIGN);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.RSA_OAEP);
    KMByteBlob.cast(byteBlob).add((short)3, KMType.RSA_PSS);
    KMByteBlob.cast(byteBlob).add((short)4, KMType.PADDING_NONE);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short)5);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.VERIFY);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)3, KMType.DECRYPT);
    KMByteBlob.cast(byteBlob).add((short)4, KMType.WRAP_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    byte[] pub = {0,1,0,1};
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short)0));
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.INCLUDE_UNIQUE_ID));
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.RESET_SINCE_ID_ROTATION));
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add(tagIndex++, padding);
    short dateTag = KMInteger.uint_64(activeAndCreationDateTime,(short)0);
    KMArray.cast(arrPtr).add(tagIndex++, KMIntegerTag.instance(KMType.DATE_TAG,KMType.ACTIVE_DATETIME,dateTag));
    KMArray.cast(arrPtr).add(tagIndex++, KMIntegerTag.instance(KMType.DATE_TAG,KMType.CREATION_DATETIME,dateTag));

    if(clientId != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(clientId,(short)0,(short)clientId.length)));
    if(appData != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_DATA, KMByteBlob.instance(appData,(short)0,(short)appData.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short)1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x10, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  private short generateAttestationKey(){
    // 15th July 2020 00.00.00
    byte[] activeAndCreationDateTime = {0,0,0x01,0x73,0x51,0x7C,(byte)0xCC,0x00};
    short tagCount = 11;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048));
    short byteBlob = KMByteBlob.instance((short)3);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.SHA2_256);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.SHA1);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.RSA_PKCS1_1_5_SIGN);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ATTEST_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    byte[] pub = {0,1,0,1};
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short)0));
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.INCLUDE_UNIQUE_ID));
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.RESET_SINCE_ID_ROTATION));
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add(tagIndex++, padding);
    short dateTag = KMInteger.uint_64(activeAndCreationDateTime,(short)0);
    KMArray.cast(arrPtr).add(tagIndex++, KMIntegerTag.instance(KMType.ULONG_TAG,KMType.ACTIVE_DATETIME,dateTag));
    KMArray.cast(arrPtr).add(tagIndex++, KMIntegerTag.instance(KMType.ULONG_TAG,KMType.CREATION_DATETIME,dateTag));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short)1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x10, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  @Test
  public void testEcGenerateKeySuccess() {
    init();
    short ret = generateEcKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.DIGEST_NONE));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.EC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }
  public short generateEcKey(byte[] clientId, byte[] appData) {
    byte[] activeAndCreationDateTime = {0,0,0x01,0x73,0x51,0x7C,(byte)0xCC,0x00};
    short tagCount = 6;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)256));
    short byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    short dateTag = KMInteger.uint_64(activeAndCreationDateTime,(short)0);
    KMArray.cast(arrPtr).add(tagIndex++, KMIntegerTag.instance(KMType.DATE_TAG,KMType.CREATION_DATETIME,dateTag));
    if(clientId != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(clientId,(short)0,(short)clientId.length)));
    if(appData != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_DATA, KMByteBlob.instance(appData,(short)0,(short)appData.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short)1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x10, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  @Test
  public void testHmacGenerateKeySuccess() {
    init();
    short ret = generateHmacKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 160);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.HMAC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }
  public short generateHmacKey(byte[] clientId, byte[] appData){
    short tagCount = 6;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)128));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short minMacLen = KMIntegerTag.instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)/*256*/160));
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, minMacLen);
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
    if(clientId != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(clientId,(short)0,(short)clientId.length)));
    if(appData != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_DATA, KMByteBlob.instance(appData,(short)0,(short)appData.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short)1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x10, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }
  public short generateAesDesKey(byte alg, short keysize, byte[] clientId, byte[] appData, boolean unlockReqd) {
    short tagCount = 7;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    if(unlockReqd)tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
    short byteBlob = KMByteBlob.instance((short)3);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ECB);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.CBC);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.CTR);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.PKCS7);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, alg));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    if(unlockReqd)KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.UNLOCKED_DEVICE_REQUIRED));
    if(clientId != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(clientId,(short)0,(short)clientId.length)));
    if(appData != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_DATA, KMByteBlob.instance(appData,(short)0,(short)appData.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short)1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x10, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }
  public short generateAesGcmKey(short keysize, byte[] clientId, byte[] appData) {
    short tagCount = 8;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
    short macLength = KMIntegerTag.instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)96));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.GCM);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, macLength);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    if(clientId != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(clientId,(short)0,(short)clientId.length)));
    if(appData != null)KMArray.cast(arrPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_DATA, KMByteBlob.instance(appData,(short)0,(short)appData.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short)1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x10, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }

  @Test
  public void testComputeHmacParams(){
    init();
    short params1 = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(params1).setSeed(KMByteBlob.instance((short)0));
    short num = KMByteBlob.instance((short)32);
    cryptoProvider.newRandomNumber(
      KMByteBlob.cast(num).getBuffer(),
      KMByteBlob.cast(num).getStartOff(),
      KMByteBlob.cast(num).length());
    KMHmacSharingParameters.cast(params1).setNonce(num);
    short params2 = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(params2).setSeed(KMByteBlob.instance((short)0));
    num = KMByteBlob.instance((short)32);
    cryptoProvider.newRandomNumber(
      KMByteBlob.cast(num).getBuffer(),
      KMByteBlob.cast(num).getStartOff(),
      KMByteBlob.cast(num).length());
    KMHmacSharingParameters.cast(params2).setNonce(num);
    short arr = KMArray.instance((short)2);
    KMArray.cast(arr).add((short)0, params1);
    KMArray.cast(arr).add((short)1,params2);
    short arrPtr = KMArray.instance((short)1);
    KMArray.cast(arrPtr).add((short)0,arr);
    CommandAPDU apdu = encodeApdu((byte)0x19, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);

    cleanUp();
  }
  @Test
  public void testGetHmacSharingParams(){
    init();
    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x1C, 0x40, 0x00);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    KMDecoder dec = new KMDecoder();
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMHmacSharingParameters.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    KMHmacSharingParameters params = KMHmacSharingParameters.cast(KMArray.cast(ret).get((short)1));
    short seed = params.getSeed();
    short nonce = params.getNonce();
    Assert.assertTrue(KMByteBlob.cast(seed).length() == 0);
    Assert.assertTrue(KMByteBlob.cast(nonce).length() == 32);
    //print(seed);
    //print(nonce);
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }
  public short[] getHmacSharingParams(){
    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x1C, 0x40, 0x00);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    KMDecoder dec = new KMDecoder();
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMHmacSharingParameters.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    KMHmacSharingParameters params = KMHmacSharingParameters.cast(KMArray.cast(ret).get((short)1));
    short seed = params.getSeed();
    short nonce = params.getNonce();
    return new short[]{seed, nonce};
  }

  @Test
  public void testImportWrappedKey(){
    init();
    byte[] wrappedKey = new byte[16];
    cryptoProvider.newRandomNumber(wrappedKey,(short)0,(short)16);
    byte[] encWrappedKey = new byte[16];
    AESKey transportKey = cryptoProvider.createAESKey((short)256);
    byte[] transportKeyMaterial = new byte[32];
    cryptoProvider.newRandomNumber(transportKeyMaterial,(short)0,(short)32);
    transportKey.setKey(transportKeyMaterial,(short)0);
    byte[] nonce = new byte[12];
    cryptoProvider.newRandomNumber(nonce,(short)0,(short)12);
    byte[] authData = "Auth Data".getBytes();
    byte[] authTag = new byte[12];
    cryptoProvider.aesGCMEncrypt(transportKey,wrappedKey,(short)0,(short)16,encWrappedKey,(short)0,
      nonce,(short)0, (short)12,authData,(short)0,(short)authData.length,
      authTag, (short)0, (short)12);
    byte[] maskingKey = {1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0};
    byte[] maskedTransportKey = new byte[32];
    for(int i=0; i< maskingKey.length;i++){
      maskedTransportKey[i] = (byte)(transportKeyMaterial[i] ^ maskingKey[i]);
    }
    short rsaKeyArr = generateRsaKey(null,null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short)1);
    byte[] wrappingKeyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),
      wrappingKeyBlob,(short)0, (short)wrappingKeyBlob.length);
    short inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_OAEP);
    short ret = processMessage(maskedTransportKey,
      KMByteBlob.instance(wrappingKeyBlob,(short)0, (short)wrappingKeyBlob.length),
      KMType.ENCRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,false,false
    );
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] encTransportKey = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      encTransportKey,(short)0, (short)encTransportKey.length);
    short tagCount = 7;
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)128));
    short byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ECB);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.CBC);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.PKCS7);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short nullParams = KMArray.instance((short)0);
    nullParams = KMKeyParameters.instance(nullParams);
    short arr = KMArray.instance((short)12);
    KMArray.cast(arr).add((short) 0, keyParams); // Key Params of wrapped key
    KMArray.cast(arr).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT,KMType.RAW)); // Key Format
    KMArray.cast(arr).add((short) 2, KMByteBlob.instance(encWrappedKey,(short)0,(short)encWrappedKey.length)); // Wrapped Import Key Blob
    KMArray.cast(arr).add((short) 3, KMByteBlob.instance(authTag,(short)0,(short)authTag.length)); // Auth Tag
    KMArray.cast(arr).add((short) 4, KMByteBlob.instance(nonce,(short)0,(short)nonce.length)); // IV - Nonce
    KMArray.cast(arr).add((short) 5, KMByteBlob.instance(encTransportKey,(short)0,(short)encTransportKey.length)); // Encrypted Transport Key
    KMArray.cast(arr).add((short) 6, KMByteBlob.instance(wrappingKeyBlob,(short)0, (short)wrappingKeyBlob.length)); // Wrapping Key KeyBlob
    KMArray.cast(arr).add((short) 7, KMByteBlob.instance(maskingKey,(short)0,(short)maskingKey.length)); // Masking Key
    KMArray.cast(arr).add((short) 8, nullParams); // Un-wrapping Params
    KMArray.cast(arr).add((short) 9, KMByteBlob.instance(authData,(short)0,(short)authData.length)); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.cast(arr).add((short) 10, KMInteger.uint_8((byte)0)); // Password Sid
    KMArray.cast(arr).add((short) 11, KMInteger.uint_8((byte)0)); // Biometric Sid
    CommandAPDU apdu = encodeApdu((byte)0x12, arr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(),0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PKCS7));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.ECB));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.AES);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.SECURELY_IMPORTED);
    cleanUp();
  }

  @Test
  public void testGetKeyCharacteristicsWithIdDataSuccess() {
    init();
    byte[] clientId = "clientId".getBytes();
    byte[] appData = "appData".getBytes();
    short ret = generateRsaKey(clientId,appData);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    short keyBlob = KMArray.cast(ret).get((short)1);

    short arrPtr = KMArray.instance((short)3);
    KMArray.cast(arrPtr).add((short)0, keyBlob);
    KMArray.cast(arrPtr).add((short)1, KMByteBlob.instance(clientId,(short)0, (short)clientId.length));
    KMArray.cast(arrPtr).add((short)2, KMByteBlob.instance(appData,(short)0, (short)appData.length));
    CommandAPDU apdu = encodeApdu((byte)0x1D, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  @Test
  public void testGetKeyCharacteristicsSuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    short keyBlob = KMArray.cast(ret).get((short)1);

    short arrPtr = KMArray.instance((short)3);
    KMArray.cast(arrPtr).add((short)0, keyBlob);
    KMArray.cast(arrPtr).add((short)1, KMByteBlob.instance((short)0));
    KMArray.cast(arrPtr).add((short)2, KMByteBlob.instance((short)0));
    CommandAPDU apdu = encodeApdu((byte)0x1D, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  @Test
  public void testDeleteKeySuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(ret).get((short)1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    short len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob, (short)0);
    ret = getKeyCharacteristics(keyBlobPtr);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    ret = deleteKey(KMByteBlob.instance(keyBlob,(short)0,(short)keyBlob.length));
    Assert.assertEquals(ret, KMError.OK);
    ret = getKeyCharacteristics(KMByteBlob.instance(keyBlob,(short)0,(short)keyBlob.length));
    short err = KMByteBlob.cast(ret).get((short)1);
    Assert.assertEquals(KMError.INVALID_KEY_BLOB,err);
    cleanUp();
  }

  @Test
  public void testDeleteAllKeySuccess() {
    init();
    short ret1 = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(ret1).get((short)1);
    byte[] keyBlob1 = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    short len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob1, (short)0);
    short ret2 = generateRsaKey(null, null);
    keyBlobPtr = KMArray.cast(ret2).get((short)1);
    byte[] keyBlob2 = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob2, (short)0);
    CommandAPDU apdu = new CommandAPDU(0x80, 0x17, 0x40, 0x00);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(respBuf[0], KMError.OK);
    short ret = getKeyCharacteristics(KMByteBlob.instance(keyBlob1,(short)0,(short)keyBlob1.length));
    short err = KMByteBlob.cast(ret).get((short)1);
    Assert.assertEquals(KMError.INVALID_KEY_BLOB,err);
    ret = getKeyCharacteristics(KMByteBlob.instance(keyBlob2,(short)0,(short)keyBlob2.length));
    err = KMByteBlob.cast(ret).get((short)1);
    Assert.assertEquals(KMError.INVALID_KEY_BLOB,err);
    cleanUp();
  }

  private short deleteKey(short keyBlob) {
    short arrPtr = KMArray.instance((short)1);
    KMArray.cast(arrPtr).add((short)0, keyBlob);
    CommandAPDU apdu = encodeApdu((byte)0x16, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    return respBuf[0];
  }

  private short abort(short opHandle) {
    short arrPtr = KMArray.instance((short)1);
    KMArray.cast(arrPtr).add((short)0, opHandle);
    CommandAPDU apdu = encodeApdu((byte)0x22, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    return respBuf[0];
  }

  public short getKeyCharacteristics(short keyBlob){
    short arrPtr = KMArray.instance((short)3);
    KMArray.cast(arrPtr).add((short)0, keyBlob);
    KMArray.cast(arrPtr).add((short)1, KMByteBlob.instance((short)0));
    KMArray.cast(arrPtr).add((short)2, KMByteBlob.instance((short)0));
    CommandAPDU apdu = encodeApdu((byte)0x1D, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if( len > 5)
      ret = decoder.decode(ret, respBuf, (short) 0, len);
    else
      ret = KMByteBlob.instance(respBuf, (short)0, len);
    return ret;
  }

  @Test
  public void testWithAesGcmWithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.GCM, KMType.PADDING_NONE,true);
    cleanUp();
  }
  @Test
  public void testWithAesEcbPkcs7WithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7,true);
    cleanUp();
  }

  @Test
  public void testWithAesCtrNoPadWithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CTR, KMType.PADDING_NONE,true);
    cleanUp();
  }

  @Test
  public void testWithAesCtrNoPad(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CTR, KMType.PADDING_NONE,false);
    cleanUp();
  }

  @Test
  public void testWithAesEcbNoPadWithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PADDING_NONE,true);
    cleanUp();
  }
  @Test
  public void testWithDesEcbPkcs7WithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PKCS7,true);
    cleanUp();
  }
  @Test
  public void testWithDesEcbNoPadWithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PADDING_NONE,true);
    cleanUp();
  }
  @Test
  public void testWithAesCbcPkcs7WithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PKCS7,true);
    cleanUp();
  }
  @Test
  public void testWithAesCbcNoPadWithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PADDING_NONE,true);
    cleanUp();
  }
  @Test
  public void testWithDesCbcPkcs7WithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PKCS7,true);
    cleanUp();
  }
  @Test
  public void testWithDesCbcNoPadWithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PADDING_NONE,true);
    cleanUp();
  }

  @Test
  public void testWithAesEcbPkcs7(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7,false);
    cleanUp();
  }
  @Test
  public void testWithAesCbcPkcs7(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PKCS7,false);
    cleanUp();
  }
  @Test
  public void testWithAesEcbNoPad(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PADDING_NONE,false);
    cleanUp();
  }
  @Test
  public void testWithAesCbcNoPad(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PADDING_NONE,false);
    cleanUp();
  }
  @Test
  public void testWithDesCbcPkcs7(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PKCS7,false);
    cleanUp();
  }
  @Test
  public void testWithDesCbcNoPad(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PADDING_NONE,false);
    cleanUp();
  }
  @Test
  public void testWithDesEcbNoPad(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PADDING_NONE,false);
    cleanUp();
  }
  @Test
  public void testWithDesEcbPkcs7(){
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PKCS7,false);
    cleanUp();
  }

  @Test
  public void testWithRsa256Oaep(){
    init();
    testEncryptDecryptWithRsa(KMType.SHA2_256, KMType.RSA_OAEP);
    cleanUp();
  }
  @Test
  public void testWithRsaSha1Oaep(){
    init();
    testEncryptDecryptWithRsa(KMType.SHA1, KMType.RSA_OAEP);
    cleanUp();
  }

  @Test
  public void testWithRsaNonePkcs1(){
    init();
    testEncryptDecryptWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_ENCRYPT);
    cleanUp();
  }
  @Test
  public void testWithRsaNoneNoPad(){
    init();
    testEncryptDecryptWithRsa(KMType.DIGEST_NONE, KMType.PADDING_NONE);
    cleanUp();
  }


  // TODO Signing with no digest is not supported by crypto provider or javacard
  @Test
  public void testSignWithRsaNoneNoPad(){
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.PADDING_NONE,false, false);
    cleanUp();
  }
  @Test
  public void testSignWithRsaNonePkcs1(){
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_SIGN,false, false);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithHmacSHA256WithUpdate(){
    init();
    testSignVerifyWithHmac(KMType.SHA2_256, true);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithHmacSHA256(){
    init();
    testSignVerifyWithHmac(KMType.SHA2_256, false);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithEcdsaSHA256WithUpdate(){
    init();
    testSignVerifyWithEcdsa(KMType.SHA2_256, true);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithEcdsaSHA256(){
    init();
    testSignVerifyWithEcdsa(KMType.SHA2_256, false);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1(){
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN,false, true);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithRsaSHA256Pss(){
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS,false, true);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1WithUpdate(){
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN,true, true);
    cleanUp();
  }

  @Test
  public void testProvisionSuccess(){
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMKeymasterApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    provisionCmd(simulator);
    cleanUp();
  }
  @Test
  public void testAttestRsaKey(){
    init();
    short key = generateRsaKey(null,null);
    short keyBlobPtr = KMArray.cast(key).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(
      KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    testAttestKey(keyBlob);
    cleanUp();
  }

  @Test
  public void testAttestEcKey(){
    init();
    short key = generateEcKey(null,null);
    short keyBlobPtr = KMArray.cast(key).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(
      KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    testAttestKey(keyBlob);
    cleanUp();
  }

  public void testAttestKey(byte[] keyBlob){
    /*
    short key = generateRsaKey(null,null);
    short keyBlobPtr = KMArray.cast(key).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(
      KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
     */
    short arrPtr = KMArray.instance((short)2);
    KMArray.cast(arrPtr).add((short)0, KMByteTag.instance(KMType.ATTESTATION_APPLICATION_ID,
      KMByteBlob.instance(attAppId,(short)0,(short)attAppId.length)));
    KMArray.cast(arrPtr).add((short)1, KMByteTag.instance(KMType.ATTESTATION_CHALLENGE,
      KMByteBlob.instance(attChallenge,(short)0,(short)attChallenge.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short args = KMArray.instance((short)2);
    KMArray.cast(args).add((short)0, KMByteBlob.instance(keyBlob,(short)0,(short)keyBlob.length));
    KMArray.cast(args).add((short)1, keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x14, args);
    //print(apdu.getBytes(),(short)0,(short)apdu.getBytes().length);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 2);
    short arrBlobs = KMArray.instance((short)1);
    KMArray.cast(arrBlobs).add((short)0, KMByteBlob.exp());
    KMArray.cast(ret).add((short)0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, arrBlobs);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
   //(respBuf,(short)0,(short)respBuf.length);
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    arrBlobs = KMArray.cast(ret).get((short)1);
    short cert  = KMArray.cast(arrBlobs).get((short)0);
    //printCert(KMByteBlob.cast(cert).getBuffer(),KMByteBlob.cast(cert).getStartOff(),KMByteBlob.cast(cert).length());
  }

  @Test
  public void testUpgradeKey(){
    init();
    short ret = generateHmacKey(null, null);
    short keyBlobPtr = KMArray.cast(ret).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    short osVersion = KMKeyParameters.findTag(KMType.UINT_TAG,KMType.OS_VERSION,hwParams);
    osVersion = KMIntegerTag.cast(osVersion).getValue();
    short osPatch = KMKeyParameters.findTag(KMType.UINT_TAG,KMType.OS_PATCH_LEVEL,hwParams);
    osPatch = KMIntegerTag.cast(osPatch).getValue();
    Assert.assertEquals(KMInteger.cast(osVersion).getShort(), 1);
    Assert.assertEquals(KMInteger.cast(osPatch).getShort(), 1);
    setBootParams(simulator,(short) 2,(short)2);
    ret = upgradeKey(KMByteBlob.instance(keyBlob, (short)0, (short)keyBlob.length),null, null);
    keyBlobPtr = KMArray.cast(ret).get((short)1);
    ret = getKeyCharacteristics(keyBlobPtr);
    keyCharacteristics = KMArray.cast(ret).get((short)1);
    hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    osVersion = KMKeyParameters.findTag(KMType.UINT_TAG,KMType.OS_VERSION,hwParams);
    osVersion = KMIntegerTag.cast(osVersion).getValue();
    osPatch = KMKeyParameters.findTag(KMType.UINT_TAG,KMType.OS_PATCH_LEVEL,hwParams);
    osPatch = KMIntegerTag.cast(osPatch).getValue();
    Assert.assertEquals(KMInteger.cast(osVersion).getShort(), 2);
    Assert.assertEquals(KMInteger.cast(osPatch).getShort(), 2);
    cleanUp();
  }

  @Test
  public void testDestroyAttIds(){
    init();
    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x1A, 0x40, 0x00);
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(respBuf[0], 0);
    cleanUp();
  }

  private short upgradeKey(short keyBlobPtr, byte[] clientId, byte[] appData){
    short tagCount = 0;
    short clientIdTag = 0;
    short appDataTag = 0;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short keyParams = KMArray.instance(tagCount);
    short tagIndex=0;
    if(clientId != null)KMArray.cast(keyBlobPtr).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_ID, KMByteBlob.instance(clientId,(short)0,(short)clientId.length)));
    if(appData != null)KMArray.cast(keyParams).add(tagIndex++,
      KMByteTag.instance(KMType.APPLICATION_DATA, KMByteBlob.instance(appData,(short)0,(short)appData.length)));
    keyParams = KMKeyParameters.instance(keyParams);
    short arr = KMArray.instance((short)2);
    KMArray.cast(arr).add((short)0,keyBlobPtr);
    KMArray.cast(arr).add((short)1,keyParams);
    CommandAPDU apdu = encodeApdu((byte)0x15, arr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }
  @Test
  public void testSignVerifyWithRsaSHA256PssWithUpdate(){
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS,true, true);
    cleanUp();
  }
  @Test
  public void testAbortOperation(){
    init();
    short aesDesKeyArr = generateAesDesKey(KMType.AES, (short)128,null, null, false);;
    short keyBlobPtr = KMArray.cast(aesDesKeyArr).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    byte[] nonce = new byte[16];
    cryptoProvider.newRandomNumber(nonce,(short)0,(short)16);
    short inParams = getAesDesParams(KMType.AES,KMType.ECB, KMType.PKCS7, nonce);
    byte[] plainData= "Hello World 123!".getBytes();
    short ret = begin(KMType.ENCRYPT, KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length), KMKeyParameters.instance(inParams), (short)0);
    short opHandle = KMArray.cast(ret).get((short) 2);
    opHandle = KMInteger.cast(opHandle).getShort();
    abort(KMInteger.uint_16(opHandle));
    short dataPtr = KMByteBlob.instance(plainData, (short) 0, (short) plainData.length);
    ret = update(KMInteger.uint_16(opHandle), dataPtr, (short) 0, (short) 0, (short) 0);
    Assert.assertEquals(KMError.INVALID_OPERATION_HANDLE,ret);
    cleanUp();
  }

  public void testEncryptDecryptWithAesDes(byte alg, byte blockMode, byte padding, boolean update){
    short aesDesKeyArr;
    boolean aesGcmFlag = false;
    if(alg == KMType.AES){
      if(blockMode == KMType.GCM){
        aesDesKeyArr = generateAesGcmKey((short)128,null,null);
        aesGcmFlag = true;
      } else {
        aesDesKeyArr = generateAesDesKey(alg, (short) 128, null, null, false);
      }
    } else{
      aesDesKeyArr = generateAesDesKey(alg, (short)168,null, null, false);
    }
    short keyBlobPtr = KMArray.cast(aesDesKeyArr).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    byte[] nonce = new byte[16];
    cryptoProvider.newRandomNumber(nonce,(short)0,(short)16);
    short inParams = getAesDesParams(alg,blockMode, padding, nonce);
    byte[] plainData= "Hello World 123!".getBytes();
    if(update) plainData= "Hello World 123! Hip Hip Hoorah!".getBytes();
    //Encrypt
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.ENCRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,update, aesGcmFlag
      );
    inParams = getAesDesParams(alg,blockMode, padding, nonce);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    //print(keyBlobPtr);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      cipherData,(short)0, (short)cipherData.length);
    ret = processMessage(cipherData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.DECRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,update, aesGcmFlag
    );
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    //print(plainData,(short)0,(short)plainData.length);
    //print(keyBlobPtr);
    short equal = Util.arrayCompare(plainData,(short)0,KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),(short)plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testEncryptDecryptWithRsa(byte digest, byte padding){
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    short inParams = getRsaParams(digest, padding);
    byte[] plainData = "Hello World 123!".getBytes();
    //Encrypt
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.ENCRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,false, false
    );
    inParams = getRsaParams(digest, padding);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      cipherData,(short)0, (short)cipherData.length);
    ret = processMessage(cipherData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.DECRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,false,false
    );
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    short len = KMByteBlob.cast(keyBlobPtr).length();
    short start = KMByteBlob.cast(keyBlobPtr).getStartOff();
    short equal = Util.arrayCompare(plainData,(short)0,KMByteBlob.cast(keyBlobPtr).getBuffer(),
      (short)(start+len-plainData.length),(short)plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testSignVerifyWithRsa(byte digest, byte padding, boolean update, boolean verifyFlag){
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    short inParams = getRsaParams(digest, padding);
    byte[] plainData = "Hello World 123!".getBytes();
    if(update) plainData= "Hello World 123! Hip Hip Hoorah!".getBytes();
    //Sign
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.SIGN,
      KMKeyParameters.instance(inParams),
      (short)0,null,update,false
    );
    inParams = getRsaParams(digest, padding);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      signatureData,(short)0, (short)signatureData.length);
    if(verifyFlag == false) {
      Assert.assertEquals(signatureData.length,256);
      return;
    }
    ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.VERIFY,
      KMKeyParameters.instance(inParams),
      (short)0,signatureData,update,false
    );
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
  }

  public void testSignVerifyWithEcdsa(byte digest, boolean update){
    short ecKeyArr = generateEcKey(null, null);
    short keyBlobPtr = KMArray.cast(ecKeyArr).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    short inParams = getEcParams(digest);
    byte[] plainData = "Hello World 123!".getBytes();
    if(update) plainData= "Hello World 123! Hip Hip Hoorah!".getBytes();
    //Sign
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.SIGN,
      KMKeyParameters.instance(inParams),
      (short)0,null,update,false
    );
    inParams = getEcParams(digest);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      signatureData,(short)0, (short)signatureData.length);
    ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.VERIFY,
      KMKeyParameters.instance(inParams),
      (short)0,signatureData,update,false
    );
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
  }
  public void testSignVerifyWithHmac(byte digest, boolean update){
    short hmacKeyArr = generateHmacKey(null, null);
    short keyBlobPtr = KMArray.cast(hmacKeyArr).get((short)1);
    byte[] keyBlob= new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      keyBlob,(short)0, (short)keyBlob.length);
    short inParams = getHmacParams(digest,true);
    byte[] plainData = "Hello World 123!".getBytes();
    if(update) plainData= "Hello World 123! Hip Hip Hoorah!".getBytes();
    //Sign
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.SIGN,
      KMKeyParameters.instance(inParams),
      (short)0,null,update,false
    );
    inParams = getHmacParams(digest,false);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      signatureData,(short)0, (short)signatureData.length);
    ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.VERIFY,
      KMKeyParameters.instance(inParams),
      (short)0,signatureData,update,false
    );
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
  }

  private short getAesDesParams(byte alg, byte blockMode, byte padding, byte[] nonce) {
    short inParams;
    if(blockMode == KMType.GCM){
      inParams = KMArray.instance((short)5);
      short byteBlob = KMByteBlob.instance((short)1);
      KMByteBlob.cast(byteBlob).add((short)0, blockMode);
      KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short)1);
      KMByteBlob.cast(byteBlob).add((short)0, padding);
      KMArray.cast(inParams).add((short)1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
      short nonceLen = 12;
      byteBlob = KMByteBlob.instance(nonce,(short)0, nonceLen);
      KMArray.cast(inParams).add((short)2, KMByteTag.instance(KMType.NONCE, byteBlob));
      short macLen = KMInteger.uint_16((short)128);
      macLen = KMIntegerTag.instance(KMType.UINT_TAG,KMType.MAC_LENGTH,macLen);
      KMArray.cast(inParams).add((short)3, macLen);
      byte[] authData = "AuthData".getBytes();
      short associatedData = KMByteBlob.instance(authData,(short)0,(short)authData.length);
      associatedData = KMByteTag.instance(KMType.ASSOCIATED_DATA,associatedData);
      KMArray.cast(inParams).add((short)4, associatedData);
    }else if(blockMode == KMType.ECB){
      inParams = KMArray.instance((short)2);
      short byteBlob = KMByteBlob.instance((short)1);
      KMByteBlob.cast(byteBlob).add((short)0, blockMode);
      KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short)1);
      KMByteBlob.cast(byteBlob).add((short)0, padding);
      KMArray.cast(inParams).add((short)1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
    }else{
      inParams = KMArray.instance((short)3);
      short byteBlob = KMByteBlob.instance((short)1);
      KMByteBlob.cast(byteBlob).add((short)0, blockMode);
      KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short)1);
      KMByteBlob.cast(byteBlob).add((short)0, padding);
      KMArray.cast(inParams).add((short)1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
      short nonceLen = 16;
      if(alg == KMType.DES) nonceLen = 8;
      byteBlob = KMByteBlob.instance(nonce,(short)0, nonceLen);
      KMArray.cast(inParams).add((short)2, KMByteTag.instance(KMType.NONCE, byteBlob));
    }
    return inParams;
  }

  private short getRsaParams(byte digest, byte padding) {
    short inParams = KMArray.instance((short)2);
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, digest);
    KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, padding);
    KMArray.cast(inParams).add((short)1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
    return inParams;
  }

  private short getEcParams(byte digest) {
    short inParams = KMArray.instance((short)1);
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, digest);
    KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    return inParams;
  }
  private short getHmacParams(byte digest, boolean sign) {
	short paramsize = (short) (sign ? 2 : 1);
    short inParams = KMArray.instance((short)paramsize);
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, digest);
    KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    short macLength = KMIntegerTag.instance(KMType.UINT_TAG,KMType.MAC_LENGTH, KMInteger.uint_16((short)/*256*/160));
    if(sign)
      KMArray.cast(inParams).add((short)1, macLength);
    return inParams;
  }

  public short processMessage(
      byte[] data,
      short keyBlob,
      byte keyPurpose,
      short inParams,
      short hwToken,
      byte[] signature,
      boolean updateFlag,
      boolean aesGcmFlag) {
    short beginResp = begin(keyPurpose, keyBlob, inParams, hwToken);
    short opHandle = KMArray.cast(beginResp).get((short) 2);
    opHandle = KMInteger.cast(opHandle).getShort();
    short dataPtr = KMByteBlob.instance(data, (short) 0, (short) data.length);
    short ret = KMType.INVALID_VALUE;
    byte[] outputData = new byte[128];
    short len=0;
    inParams = 0;
    //Test
    short firstDataLen =16;
    if (keyPurpose == KMType.DECRYPT) {
    	firstDataLen = 32;
    }

    //Test

    if (updateFlag) {
      dataPtr = KMByteBlob.instance(data, (short) 0, (short) /*16*/firstDataLen);
      if(aesGcmFlag){
        byte[] authData = "AuthData".getBytes();
        short associatedData = KMByteBlob.instance(authData,(short)0,(short)authData.length);
        associatedData = KMByteTag.instance(KMType.ASSOCIATED_DATA,associatedData);
        inParams = KMArray.instance((short)1);
        KMArray.cast(inParams).add((short)0, associatedData);
        inParams = KMKeyParameters.instance(inParams);
      }
      ret = update(KMInteger.uint_16(opHandle), dataPtr, inParams, (short) 0, (short) 0);
      dataPtr = KMArray.cast(ret).get((short) 3);
      if (KMByteBlob.cast(dataPtr).length() > 0) {
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(dataPtr).getBuffer(),
            KMByteBlob.cast(dataPtr).getStartOff(),
            outputData,
            (short) 0,
            KMByteBlob.cast(dataPtr).length());
        len = KMByteBlob.cast(dataPtr).length();
        dataPtr = KMByteBlob.instance(data, len, (short) (data.length - len));
      }else{
        dataPtr = KMByteBlob.instance(data, (short)/*16*/firstDataLen, (short) (data.length - /*16*/firstDataLen));
      }
    }

    if (keyPurpose == KMType.VERIFY) {
      ret = finish(KMInteger.uint_16(opHandle), dataPtr, signature, (short) 0, (short) 0, (short) 0);
    } else {
      ret = finish(KMInteger.uint_16(opHandle), dataPtr, null, (short) 0, (short) 0, (short) 0);
    }
    if(len >0){
      dataPtr = KMArray.cast(ret).get((short)2);
      if(KMByteBlob.cast(dataPtr).length() >0){
        Util.arrayCopyNonAtomic(
          KMByteBlob.cast(dataPtr).getBuffer(),
          KMByteBlob.cast(dataPtr).getStartOff(),
          outputData,
          len,
          KMByteBlob.cast(dataPtr).length());
        len = (short)(len + KMByteBlob.cast(dataPtr).length());
      }
      KMArray.cast(ret).add((short)2, KMByteBlob.instance(outputData,(short)0,len));
    }
    return ret;
  }

  public short begin(byte keyPurpose, short keyBlob, short keyParmas, short hwToken) {
    short arrPtr = KMArray.instance((short)4);
    KMArray.cast(arrPtr).add((short)0, KMEnum.instance(KMType.PURPOSE, keyPurpose));
    KMArray.cast(arrPtr).add((short)1, keyBlob);
    KMArray.cast(arrPtr).add((short)2, keyParmas);
    if(hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    KMArray.cast(arrPtr).add((short)3, hwToken);
    CommandAPDU apdu = encodeApdu((byte)0x1F, arrPtr);
    //print(apdu.getBytes(),(short)0,(short)apdu.getBytes().length);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    short outParams = KMKeyParameters.exp();
    KMArray.cast(ret).add((short)0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, outParams);
    KMArray.cast(ret).add((short)2, KMInteger.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if(len > 5){
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    return ret;}else{
      if(len == 3) return respBuf[0];
      if(len == 4) return respBuf[1];
      return Util.getShort(respBuf,(short)0);
    }
  }

  public short finish(short operationHandle, short data, byte[] signature, short inParams, short hwToken, short verToken) {
    if(hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if(verToken == 0){
      verToken = KMVerificationToken.instance();
    }
    short signatureTag;
    if(signature == null){
      signatureTag = KMByteBlob.instance((short)0);
    }else{
      signatureTag = KMByteBlob.instance(signature,(short)0,(short)signature.length);
    }
    if(inParams == 0){
      short arr = KMArray.instance((short)0);
      inParams = KMKeyParameters.instance(arr);
    }
    short arrPtr = KMArray.instance((short)6);
    KMArray.cast(arrPtr).add((short)0, operationHandle);
    KMArray.cast(arrPtr).add((short)1, inParams);
    KMArray.cast(arrPtr).add((short)2, data);
    KMArray.cast(arrPtr).add((short)3, signatureTag);
    KMArray.cast(arrPtr).add((short)4, hwToken);
    KMArray.cast(arrPtr).add((short)5, verToken);
    CommandAPDU apdu = encodeApdu((byte)0x21, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    short outParams = KMKeyParameters.exp();
    KMArray.cast(ret).add((short)0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, outParams);
    KMArray.cast(ret).add((short)2, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }
  public short update(short operationHandle, short data, short inParams, short hwToken, short verToken) {
    if(hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if(verToken == 0){
      verToken = KMVerificationToken.instance();
    }
    if(inParams == 0){
      short arr = KMArray.instance((short)0);
      inParams = KMKeyParameters.instance(arr);
    }
    short arrPtr = KMArray.instance((short)5);
    KMArray.cast(arrPtr).add((short)0, operationHandle);
    KMArray.cast(arrPtr).add((short)1, inParams);
    KMArray.cast(arrPtr).add((short)2, data);
    KMArray.cast(arrPtr).add((short)3, hwToken);
    KMArray.cast(arrPtr).add((short)4, verToken);
    CommandAPDU apdu = encodeApdu((byte)0x20, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 4);
    short outParams = KMKeyParameters.exp();
    KMArray.cast(ret).add((short)0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMInteger.exp());
    KMArray.cast(ret).add((short)2, outParams);
    KMArray.cast(ret).add((short)3, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if (len > 5) {
      ret = decoder.decode(ret, respBuf, (short) 0, len);
      short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
      Assert.assertEquals(error, KMError.OK);
    }else{
      ret = respBuf[1];
    }
    return ret;
  }

  private void print(short blob){
    print(KMByteBlob.cast(blob).getBuffer(),KMByteBlob.cast(blob).getStartOff(),KMByteBlob.cast(blob).length());
  }
  private void print(byte[] buf, short start, short length){
    StringBuilder sb = new StringBuilder();
    for(int i = start; i < (start+length); i++){
      sb.append(String.format(" 0x%02X", buf[i])) ;
    }
    System.out.println(sb.toString());
  }
  private void printCert(byte[] buf, short start, short length){
    StringBuilder sb = new StringBuilder();
    for(int i = start; i < (start+length); i++){
      sb.append(String.format("%02X", buf[i])) ;
    }
    System.out.println(sb.toString());
  }


/*
  @Test
  public void testApdu(){
    init();
    byte[] cmd = {(byte)0x80,0x11,0x40,0x00,0x00,0x00,0x4C,(byte)0x83,(byte)0xA5,0x1A,0x70,0x00,0x01,(byte)0xF7,0x01,0x1A,0x10,
      0x00,0x00,0x02,0x03,0x1A,0x30,0x00,0x00,0x03,0x19,0x01,0x00,0x1A,0x20,0x00,0x00,0x01,0x42,0x02,
      0x03,0x1A,0x20,0x00,0x00,0x05,0x41,0x04,0x03,0x58,0x24,(byte)0x82,0x58,0x20,0x73,0x7C,0x2E,(byte)0xCD,
      0x7B,(byte)0x8D,0x19,0x40,(byte)0xBF,0x29,0x30,(byte)0xAA,(byte)0x9B,0x4E,
      (byte)0xD3,(byte)0xFF,(byte)0x94,0x1E,(byte)0xED,0x09,0x36,0x6B,
      (byte)0xC0,0x32,(byte)0x99,(byte)0x98,0x64,(byte)0x81,(byte)0xF3,(byte)0xA4,(byte)0xD8,0x59,0x40};
    CommandAPDU cmdApdu = new CommandAPDU(cmd);
    ResponseAPDU resp = simulator.transmitCommand(cmdApdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = resp.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short blobArr = extractKeyBlobArray(KMArray.cast(ret).get((short)1));
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    cleanUp();
  }
 */
}
