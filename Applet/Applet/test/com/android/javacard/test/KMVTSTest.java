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
import com.android.javacard.keymaster.KMCryptoProvider;
import com.android.javacard.keymaster.KMCryptoProviderImpl;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMHardwareAuthToken;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.keymaster.KMVerificationToken;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;

public class KMVTSTest {
  private KMCryptoProvider sim;
  private CardSimulator simulator;
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMCryptoProvider cryptoProvider;

  public KMVTSTest(){
    cryptoProvider = KMCryptoProviderImpl.instance();
    sim = KMCryptoProviderImpl.instance();
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

  private void provisionCmd(CardSimulator simulator) {
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
    CommandAPDU apdu = encodeApdu((byte)0x23, argPtr);
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
    byte[] buf = new byte[1024];
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
    short keyBlob = KMArray.instance((short)3);
    KMArray.cast(keyBlob).add((short)0, privBlob);
    KMArray.cast(keyBlob).add((short)1, pubBlob);
    KMArray.cast(keyBlob).add((short)2, ecCurve);
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
    short tagCount = 7;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048));
    short byteBlob = KMByteBlob.instance((short)2);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short)5);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.RSA_PKCS1_1_5_ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.RSA_PKCS1_1_5_SIGN);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.RSA_OAEP);
    KMByteBlob.cast(byteBlob).add((short)3, KMType.RSA_PSS);
    KMByteBlob.cast(byteBlob).add((short)4, KMType.PADDING_NONE);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short)4);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short)1, KMType.VERIFY);
    KMByteBlob.cast(byteBlob).add((short)2, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short)3, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    byte[] pub = {0,1,0,1};
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short)0));
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add(tagIndex++, padding);
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
    short tagCount = 5;
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
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
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
    short minMacLen = KMIntegerTag.instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)128));
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
  public short generateAesDesKey(byte alg, short keysize, byte[] clientId, byte[] appData) {
    short tagCount = 7;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
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
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, alg));
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
  public void testWithAesEcbPkcs7WithUpdate(){
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7,true);
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

  //TODO currently cannot test OAEP SHA256 based encryption/decryption as it is not supported by
  // crypto provider
/*  @Test
  public void testWithRsa256Oaep(){
    init();
    testEncryptDecryptWithRsa(KMType.SHA2_256, KMType.RSA_OAEP);
    cleanUp();
  }
*/
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

  /*
  // TODO Signing with no digest is not supported by crypto provider or javacard
  @Test
  public void testSignVerifyWithRsaNoneNoPad(){
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_SIGN);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithRsaNonePkcs1(){
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_SIGN);
    cleanUp();
  }*/

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
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN,false);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithRsaSHA256Pss(){
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS,false);
    cleanUp();
  }
  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1WithUpdate(){
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN,true);
    cleanUp();
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
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS,true);
    cleanUp();
  }
  @Test
  public void testAbortOperation(){
    init();
    short aesDesKeyArr = generateAesDesKey(KMType.AES, (short)128,null, null);;
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
    ret = KMType.INVALID_VALUE;
    ret = update(KMInteger.uint_16(opHandle), dataPtr, (short) 0, (short) 0, (short) 0);
    Assert.assertEquals(KMError.INVALID_OPERATION_HANDLE,ret);
    cleanUp();
  }

  public void testEncryptDecryptWithAesDes(byte alg, byte blockMode, byte padding, boolean update){
    short aesDesKeyArr;
    if(alg == KMType.AES){
      aesDesKeyArr = generateAesDesKey(alg, (short)128,null, null);
    } else{
      aesDesKeyArr = generateAesDesKey(alg, (short)168,null, null);
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
      (short)0,null,update
      );
    inParams = getAesDesParams(alg,blockMode, padding, nonce);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      cipherData,(short)0, (short)cipherData.length);
    ret = processMessage(cipherData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.DECRYPT,
      KMKeyParameters.instance(inParams),
      (short)0,null,update
    );
    keyBlobPtr = KMArray.cast(ret).get((short)2);
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
      (short)0,null,false
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
      (short)0,null,false
    );
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    short equal = Util.arrayCompare(plainData,(short)0,KMByteBlob.cast(keyBlobPtr).getBuffer(),
      KMByteBlob.cast(keyBlobPtr).getStartOff(),(short)plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testSignVerifyWithRsa(byte digest, byte padding, boolean update){
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
      (short)0,null,update
    );
    inParams = getRsaParams(digest, padding);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      signatureData,(short)0, (short)signatureData.length);
    ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.VERIFY,
      KMKeyParameters.instance(inParams),
      (short)0,signatureData,update
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
      (short)0,null,update
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
      (short)0,signatureData,update
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
    short inParams = getHmacParams(digest);
    byte[] plainData = "Hello World 123!".getBytes();
    if(update) plainData= "Hello World 123! Hip Hip Hoorah!".getBytes();
    //Sign
    short ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.SIGN,
      KMKeyParameters.instance(inParams),
      (short)0,null,update
    );
    inParams = getHmacParams(digest);
    keyBlobPtr = KMArray.cast(ret).get((short)2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(), KMByteBlob.cast(keyBlobPtr).getStartOff(),
      signatureData,(short)0, (short)signatureData.length);
    ret = processMessage(plainData,
      KMByteBlob.instance(keyBlob,(short)0, (short)keyBlob.length),
      KMType.VERIFY,
      KMKeyParameters.instance(inParams),
      (short)0,signatureData,update
    );
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
  }

  private short getAesDesParams(byte alg, byte blockMode, byte padding, byte[] nonce) {
    short inParams;
    if(blockMode == KMType.ECB){
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
  private short getHmacParams(byte digest) {
    short inParams = KMArray.instance((short)2);
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, digest);
    KMArray.cast(inParams).add((short)0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    short macLength = KMIntegerTag.instance(KMType.UINT_TAG,KMType.MAC_LENGTH, KMInteger.uint_16((short)256));
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
      boolean updateFlag) {
    short beginResp = begin(keyPurpose, keyBlob, inParams, hwToken);
    short opHandle = KMArray.cast(beginResp).get((short) 2);
    opHandle = KMInteger.cast(opHandle).getShort();
    short dataPtr = KMByteBlob.instance(data, (short) 0, (short) data.length);
    short ret = KMType.INVALID_VALUE;
    byte[] outputData = new byte[128];
    short len=0;
    if (updateFlag) {
      dataPtr = KMByteBlob.instance(data, (short) 0, (short) 16);
      ret = update(KMInteger.uint_16(opHandle), dataPtr, (short) 0, (short) 0, (short) 0);
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
        dataPtr = KMByteBlob.instance(data, (short)16, (short) (data.length - 16));
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
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    short outParams = KMKeyParameters.exp();
    KMArray.cast(ret).add((short)0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, outParams);
    KMArray.cast(ret).add((short)2, KMInteger.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    return ret;
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

}
