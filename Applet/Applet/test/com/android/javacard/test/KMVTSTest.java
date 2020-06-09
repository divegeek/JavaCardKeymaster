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
    setBootParams(simulator);
  }

  private void setBootParams(CardSimulator simulator){
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
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PADDING_NONE));
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
    short tagCount = 5;
    if(clientId != null) tagCount++;
    if(appData != null) tagCount++;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)2048));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.DIGEST_NONE);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.PADDING_NONE);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byte[] pub = {0,1,0,1};
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short)0));
    short tagIndex = 0;
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
    short arrPtr = KMArray.instance((short)3);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)256));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.DIGEST_NONE);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    KMArray.cast(arrPtr).add((short)0, keySize);
    KMArray.cast(arrPtr).add((short)1, digest);
    KMArray.cast(arrPtr).add((short)2, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
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
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
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

  @Test
  public void testHmacGenerateKeySuccess() {
    init();
    short arrPtr = KMArray.instance((short)4);
    short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short)128));
    short byteBlob = KMByteBlob.instance((short)1);
    KMByteBlob.cast(byteBlob).add((short)0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short minMacLength = KMIntegerTag.instance(KMType.UINT_TAG,KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)128));
    KMArray.cast(arrPtr).add((short)0, keySize);
    KMArray.cast(arrPtr).add((short)1, digest);
    KMArray.cast(arrPtr).add((short)2, minMacLength);
    KMArray.cast(arrPtr).add((short)3, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
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
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
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
}
