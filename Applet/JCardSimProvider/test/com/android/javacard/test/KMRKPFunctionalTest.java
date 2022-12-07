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
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMCose;
import com.android.javacard.keymaster.KMCoseHeaders;
import com.android.javacard.keymaster.KMCoseKey;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMJCardSimApplet;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMMap;
import com.android.javacard.keymaster.KMNInteger;
import com.android.javacard.keymaster.KMRepository;
import com.android.javacard.keymaster.KMSimpleValue;
import com.android.javacard.keymaster.KMTextString;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.seprovider.KMJCardSimulator;
import com.android.javacard.seprovider.KMSEProvider;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;

public class KMRKPFunctionalTest {

  // Provider specific Commands
  private static final byte KEYMINT_CMD_APDU_START = 0x20;
  private static final byte INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1;  //0x21
  private static final byte INS_IMPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 2;    //0x22
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 3; //0x23
  private static final byte INS_EXPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 4; //0x24
  private static final byte INS_ATTEST_KEY_CMD = KEYMINT_CMD_APDU_START + 5; //0x25
  private static final byte INS_UPGRADE_KEY_CMD = KEYMINT_CMD_APDU_START + 6; //0x26
  private static final byte INS_DELETE_KEY_CMD = KEYMINT_CMD_APDU_START + 7; //0x27
  private static final byte INS_DELETE_ALL_KEYS_CMD = KEYMINT_CMD_APDU_START + 8; //0x28
  private static final byte INS_ADD_RNG_ENTROPY_CMD = KEYMINT_CMD_APDU_START + 9; //0x29
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = KEYMINT_CMD_APDU_START + 10; //0x2A
  private static final byte INS_DESTROY_ATT_IDS_CMD = KEYMINT_CMD_APDU_START + 11;  //0x2B
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = KEYMINT_CMD_APDU_START + 12; //0x2C
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = KEYMINT_CMD_APDU_START + 13; //0x2D
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = KEYMINT_CMD_APDU_START + 14; //0x2E
  private static final byte INS_GET_HW_INFO_CMD = KEYMINT_CMD_APDU_START + 15; //0x2F
  private static final byte INS_BEGIN_OPERATION_CMD = KEYMINT_CMD_APDU_START + 16;  //0x30
  private static final byte INS_UPDATE_OPERATION_CMD = KEYMINT_CMD_APDU_START + 17;  //0x31
  private static final byte INS_FINISH_OPERATION_CMD = KEYMINT_CMD_APDU_START + 18; //0x32
  private static final byte INS_ABORT_OPERATION_CMD = KEYMINT_CMD_APDU_START + 19; //0x33
  private static final byte INS_DEVICE_LOCKED_CMD = KEYMINT_CMD_APDU_START + 20;//0x34
  private static final byte INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21; //0x35
  private static final byte INS_GET_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 22; //0x36
  private static final byte INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23; //0x37
  private static final byte INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24; //0x38
  private static final byte INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25; //0x39
  private static final byte INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26; //0x3A
  // RKP
  public static final byte INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27; //0x3B
  public static final byte INS_GENERATE_RKP_KEY_CMD = KEYMINT_CMD_APDU_START + 28; //0x3C
  public static final byte INS_BEGIN_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 29; //0x3D
  public static final byte INS_UPDATE_KEY_CMD = KEYMINT_CMD_APDU_START + 30; //0x3E
  public static final byte INS_UPDATE_EEK_CHAIN_CMD = KEYMINT_CMD_APDU_START + 31; //0x3F
  public static final byte INS_UPDATE_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 32; //0x40
  public static final byte INS_FINISH_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 33; //0x41
  public static final byte INS_GET_RESPONSE_CMD = KEYMINT_CMD_APDU_START + 34; //0x42
  public static final byte INS_GET_UDS_CERTS_CMD = KEYMINT_CMD_APDU_START + 35; //0x43
  public static final byte INS_GET_DICE_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 36; //0x44

  private static final byte KEYMINT_CMD_APDU_END = KEYMINT_CMD_APDU_START + 48; //0x50
  private static final byte INS_END_KM_CMD = 0x7F;

  public static byte[] CSR_CHALLENGE = new byte[32];

  private CardSimulator simulator;
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMSEProvider cryptoProvider;

  public KMRKPFunctionalTest() {
    cryptoProvider = new KMJCardSimulator();
    simulator = new CardSimulator();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
  }

  private void init() {
    // Create simulator
    AID appletAID = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID);
    // provision attest key
    KMProvision.provisionCmd(simulator, cryptoProvider, encoder, decoder);
  }

  private void cleanUp() {
    AID appletAID = AIDUtil.create("A000000062");
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID);
  }

  //----------------------------------------------------------------------------------------------
  //  RKP Tests
  //----------------------------------------------------------------------------------------------
  @Test
  public void testNegativeInteger() {
    init();
    short ptr = KMArray.instance((short) 3);
    byte[] a_b1 = {(byte) 0xF0, 0x00, 0x00, 0x56};
    KMArray.cast(ptr).add((short) 0, KMNInteger.uint_32(a_b1, (short) 0));
    byte[] a_b2 = new byte[]{(byte) 0xF0, 0x00, 0x01, 0x56};
    KMArray.cast(ptr).add((short) 1, KMNInteger.uint_32(a_b2, (short) 0));
    byte[] a_b3 = new byte[]{(byte) 0xF0, 0x10, 0x01, 0x56};
    KMArray.cast(ptr).add((short) 2, KMNInteger.uint_32(a_b3, (short) 0));
    byte[] blob = new byte[256];
    short len = encoder.encode(ptr, blob, (short) 0, (short) 256);

    ptr = KMArray.instance((short) 3);
    KMArray.cast(ptr).add((short) 0, KMNInteger.exp());
    KMArray.cast(ptr).add((short) 1, KMNInteger.exp());
    KMArray.cast(ptr).add((short) 2, KMNInteger.exp());
    ptr = decoder.decode(ptr, blob, (short) 0, len);
    short a_b1_ptr = KMArray.cast(ptr).get((short) 0);
    Assert.assertEquals(0,
        Util.arrayCompare(a_b1, (short) 0,
            KMNInteger.cast(a_b1_ptr).getBuffer(),
            KMNInteger.cast(a_b1_ptr).getStartOff(), (short) 4));
    short a_b2_ptr = KMArray.cast(ptr).get((short) 1);
    Assert.assertEquals(0,
        Util.arrayCompare(a_b2, (short) 0,
            KMNInteger.cast(a_b2_ptr).getBuffer(),
            KMNInteger.cast(a_b2_ptr).getStartOff(), (short) 4));
    short a_b3_ptr = KMArray.cast(ptr).get((short) 2);
    Assert.assertEquals(0,
        Util.arrayCompare(a_b3, (short) 0,
            KMNInteger.cast(a_b3_ptr).getBuffer(),
            KMNInteger.cast(a_b3_ptr).getStartOff(), (short) 4));
    cleanUp();
  }

  @Test
  public void testGetRkpHwInfo() {
    init();
    short arrPtr = KMArray.instance((short) 0);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GET_RKP_HARDWARE_INFO, arrPtr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] resp = response.getBytes();
    KMTestUtils.print(resp, (short) 0, (short) resp.length);
    short blobExp = KMByteBlob.exp();
    arrPtr = KMArray.instance((short) 6);
    KMArray.cast(arrPtr).add((short) 0, KMInteger.exp()); // ErrorCode
    KMArray.cast(arrPtr).add((short) 1, KMInteger.exp()); // Version
    KMArray.cast(arrPtr).add((short) 2, blobExp); // Text string
    KMArray.cast(arrPtr).add((short) 3, KMInteger.exp()); // support Eek Curve.
    KMArray.cast(arrPtr).add((short) 4, blobExp); // unique id
    KMArray.cast(arrPtr).add((short) 5, KMInteger.exp()); // supported number of keys in CSR
    arrPtr = decoder.decode(arrPtr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(arrPtr).get((short) 0)).getShort());
    byte[] authorName = new byte[6];
    KMByteBlob.cast(KMArray.cast(arrPtr).get((short) 2)).getValue(authorName, (short) 0, (short) 6);
    // Validate the author and Eek Curve
    byte[] google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
    Assert.assertArrayEquals(google, authorName);
    Assert.assertEquals(KMType.RKP_CURVE_P256,
        KMInteger.cast(KMArray.cast(arrPtr).get((short) 3)).getShort());
    Assert.assertEquals(3, KMInteger.cast(KMArray.cast(arrPtr).get((short) 1)).getShort());
    if(KMInteger.cast(KMArray.cast(arrPtr).get((short) 5)).getShort() < 20) {
      Assert.fail("supportedNumKeysInCsr is less than MIN_SUPPORTED_NUM_KEYS_IN_CSR(20)");
    }
    cleanUp();
  }

  @Test
  public void testRkpGeneratedEcdsaKeyPair() {
    init();
    // Running this test case in test mode.
    byte[] testHmacKey = new byte[32];
    short ret = generateRkpEcdsaKeyPair(false);
    // Prepare exp() for coseMac.
    short coseMacArrPtr = KMArray.instance((short) 4);
    short coseHeadersExp = KMCoseHeaders.exp();
    KMArray.cast(coseMacArrPtr).add((short) 0, KMByteBlob.exp());
    KMArray.cast(coseMacArrPtr).add((short) 1, coseHeadersExp);
    KMArray.cast(coseMacArrPtr).add((short) 2, KMByteBlob.exp());
    KMArray.cast(coseMacArrPtr).add((short) 3, KMByteBlob.exp());
    short byteBlobMac = KMArray.cast(ret).get((short) 1);
    short arrPtr =
        decoder.decode(coseMacArrPtr, KMByteBlob.cast(byteBlobMac).getBuffer(),
            KMByteBlob.cast(byteBlobMac).getStartOff(),
            KMByteBlob.cast(byteBlobMac).length());
    // Decode CoseMac0
    short bstrPayloadPtr = KMArray.cast(arrPtr).get((short) 2);
    short bstrTagPtr = KMArray.cast(arrPtr).get((short) 3);
    short bstrProtectedHptr = KMArray.cast(arrPtr).get((short) 0);
    short unprotectedHptr = KMArray.cast(arrPtr).get((short) 1);
    // Verify algorithm inside protected header.
    arrPtr = KMCoseHeaders.exp();//KMMap.instance((short) 1);
    ret = decoder.decode(arrPtr, KMByteBlob.cast(bstrProtectedHptr).getBuffer(),
        KMByteBlob.cast(bstrProtectedHptr).getStartOff(),
        KMByteBlob.cast(bstrProtectedHptr).length());
    short[] scratchBuffer = new short[10];
    Assert.assertTrue(KMCoseHeaders.cast(ret)
        .isDataValid(scratchBuffer, KMCose.COSE_ALG_HMAC_256, KMType.INVALID_VALUE));
    // Verify that unprotected header length is 0.
    Assert.assertEquals(0, KMCoseHeaders.cast(unprotectedHptr).length());
    // Generate Cose_Mac0 structure and verify the tag.
    byte[] output = new byte[256];
    short len = KMTestUtils.generateCoseMac0Mac(cryptoProvider, encoder, testHmacKey, (short) 0,
        (short) testHmacKey.length, KMByteBlob.instance((short) 0), bstrPayloadPtr,
        bstrProtectedHptr, output, (short) 0, (short) output.length);
    if (len != 32) {
      Assert.fail("Hmac sign len is not 32");
    }
    cleanUp();
  }

  @Test
  public void testGenerateCsrProdMode() {
    init();
    short[] noOfKeys = {0, 5, 10};
    for (int i = 0; i < noOfKeys.length; i++) {
      testGenerateCsr(noOfKeys[i]);
      KMRepository.instance().clean();
    }
    cleanUp();
  }

  //----------------------------------------------------------------------------------------------
  //  Helper functions
  //----------------------------------------------------------------------------------------------
  public short generateRkpEcdsaKeyPair(boolean testMode) {
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0,
        KMSimpleValue.instance(testMode ? KMSimpleValue.TRUE : KMSimpleValue.FALSE));
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GENERATE_RKP_KEY_CMD, arrPtr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] resp = response.getBytes();
    KMTestUtils.print(resp, (short) 0, (short) resp.length);
    // Prepare exp for output.
    arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, KMInteger.exp());
    KMArray.cast(arrPtr).add((short) 1, KMByteBlob.exp()); // bstr of cose mac0
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.exp()); // keyblob
    short ret = decoder.decode(arrPtr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
    return ret;
  }

  public void testGenerateCsr(short no_keys) {
    byte[][] mackedKeys = new byte[no_keys][];
    short ret;
    short totalEncodedCoseKeysLen = 0;
    for (short i = 0; i < no_keys; i++) {
      // Generate RKP Key
      ret = generateRkpEcdsaKeyPair(false);
      // Store CoseMac0 in buffer.
      short byteBlobCoseMac0 = KMArray.cast(ret).get((short) 1);
      mackedKeys[i] = new byte[KMByteBlob.cast(byteBlobCoseMac0).length()];
      Util.arrayCopy(KMByteBlob.cast(byteBlobCoseMac0).getBuffer(),
          KMByteBlob.cast(byteBlobCoseMac0).getStartOff(), mackedKeys[i], (short) 0,
          KMByteBlob.cast(byteBlobCoseMac0).length());
    }
    short coseKeyArr = KMArray.instance(no_keys);
    short coseMacPtr;
    short coseKey;
    for (short i = 0; i < no_keys; i++) {
      coseMacPtr = KMTestUtils.decodeCoseMac(decoder, mackedKeys[i], (short) 0,
          (short) mackedKeys[i].length);
      coseKey = KMTestUtils.getCoseKeyFromCoseMac(decoder, coseMacPtr);
      short payload = KMArray.cast(coseMacPtr).get((short) 2);
      totalEncodedCoseKeysLen += KMByteBlob.cast(payload).length();
      KMArray.cast(coseKeyArr).add(i, coseKey);
    }
    byte[] coseKeyArrBuf = new byte[1024];
    short coseKeyArrBufLen = encoder.encode(coseKeyArr, coseKeyArrBuf, (short) 0, (short) 1024);
    byte[] encodedCoseKeysArray = new byte[coseKeyArrBufLen];
    Util.arrayCopy(coseKeyArrBuf, (short) 0, encodedCoseKeysArray, (short) 0, coseKeyArrBufLen);

    // challenge
    short challenge = KMByteBlob.instance(CSR_CHALLENGE, (short) 0, (short) CSR_CHALLENGE.length);

    // begin send data
    short arr = KMArray.instance((short) 3);
    KMArray.cast(arr).add((short) 0, KMInteger.uint_8((byte) no_keys));
    KMArray.cast(arr).add((short) 1, KMInteger.uint_16(totalEncodedCoseKeysLen));
    KMArray.cast(arr).add((short) 2, challenge);

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_BEGIN_SEND_DATA_CMD, arr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] resp = response.getBytes();
    arr = KMArray.instance((short) 4);
    KMArray.cast(arr).add((short) 0, KMInteger.exp()); // OK
    KMArray.cast(arr).add((short) 1, KMByteBlob.exp()); // deviceInfo
    KMArray.cast(arr).add((short) 2, KMInteger.exp()); // version
    KMArray.cast(arr).add((short) 3, KMTextString.exp()); // certType
    ret = decoder.decode(arr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMTestUtils.getErrorCode(ret), KMError.OK);

    // get device info
    short deviceInfo = KMArray.cast(ret).get((short) 1);
    byte[] deviceInfoBytes = new byte[512];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(deviceInfo).getBuffer(),
        KMByteBlob.cast(deviceInfo).getStartOff(),
        deviceInfoBytes,
        (short) 0,
        KMByteBlob.cast(deviceInfo).length());
    short deviceInfoBytesLen = KMByteBlob.cast(deviceInfo).length();

    short schemaVersion = KMArray.cast(ret).get((short) 2);
    schemaVersion = KMInteger.cast(schemaVersion).getShort();

    short certType = KMArray.cast(ret).get((short) 3);
    short certTypeLen = KMTextString.cast(certType).length();
    byte[] cerTypeBytes = new byte[certTypeLen];
    Util.arrayCopyNonAtomic(KMTextString.cast(certType).getBuffer(),
        KMTextString.cast(certType).getStartOff(), cerTypeBytes, (short) 0,
        KMTextString.cast(certType).length());

    // update data.
    short cKey;
    byte[] cosyKeyArrayBytes = new byte[2048];
    short coseKeyBytesLen = 0;
    coseKeyBytesLen +=
        encoder.encodeArrayHeader(no_keys, cosyKeyArrayBytes, coseKeyBytesLen, (short) 3);
    for (short i = 0; i < no_keys; i++) {
      coseMacPtr = KMTestUtils.decodeCoseMac(decoder, mackedKeys[i], (short) 0,
          (short) mackedKeys[i].length);
      short coseMacContainer = KMArray.instance((short) 1);
      KMArray.cast(coseMacContainer).add((short) 0, coseMacPtr);
      apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_UPDATE_KEY_CMD, coseMacContainer);
      response = simulator.transmitCommand(apdu);
      resp = response.getBytes();
      arr = KMArray.instance((short) 2);
      KMArray.cast(arr).add((short) 0, KMInteger.exp()); // OK
      KMArray.cast(arr).add((short) 1, KMByteBlob.exp()); // cosekey
      ret = decoder.decode(arr, resp, (short) 0, (short) resp.length);
      Assert.assertEquals(KMTestUtils.getErrorCode(ret), KMError.OK);

      // get cose keys in cosyKeyArrayBytes byte array
      cKey = KMArray.cast(ret).get((short) 1);
      Util.arrayCopyNonAtomic(KMByteBlob.cast(cKey).getBuffer(),
          KMByteBlob.cast(cKey).getStartOff(),
          cosyKeyArrayBytes,
          coseKeyBytesLen,
          KMByteBlob.cast(cKey).length());
      coseKeyBytesLen += KMByteBlob.cast(cKey).length();
    }

    //Clean the heap.
    KMRepository.instance().clean();

    // finish
    // Extended length.
    apdu = new CommandAPDU(0x80, INS_FINISH_SEND_DATA_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2, (byte[]) null, 65536);
    response = simulator.transmitCommand(apdu);

    short coseHeadersExp = KMCoseHeaders.exp();
    arr = KMArray.instance((short) 5);
    KMArray.cast(arr).add((short) 0, KMInteger.exp()); // OK
    KMArray.cast(arr).add((short) 1, KMByteBlob.exp()); // protectedHeaders
    KMArray.cast(arr).add((short) 2, KMByteBlob.exp()); // signature
    KMArray.cast(arr).add((short) 3, KMInteger.exp()); // version
    KMArray.cast(arr).add((short) 4, KMInteger.exp()); // more data
    resp = response.getBytes();
    //KMTestUtils.print(resp, (short) 0, (short) resp.length);
    ret = decoder.decode(arr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMTestUtils.getErrorCode(ret), KMError.OK);
    short protectedHeaders = KMArray.cast(ret).get((short) 1);
    short signatureData = KMArray.cast(ret).get((short) 2);
    short version = KMArray.cast(ret).get((short) 3);

    byte[] signature = new byte[512];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(signatureData).getBuffer(),
        KMByteBlob.cast(signatureData).getStartOff(),
        signature,
        (short) 0,
        KMByteBlob.cast(signatureData).length());
    short signatureLen = KMByteBlob.cast(signatureData).length();

    byte[] tmp = new byte[10];
    byte[] payload = new byte[2048];
    short payloadLen = 0;

    short aad = KMByteBlob.instance(tmp, (short) 0, (short) 0);
    // construct cose sign structure
    short signStructure =
        KMCose.constructCoseSignStructure(protectedHeaders, aad, KMType.INVALID_VALUE);
    //encode sign structure to paload byte array
    payloadLen = KMKeymasterApplet.encodeToApduBuffer(signStructure, payload,
        (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);

    short csrPayloadLen = (short)(1/*Array of 4 elements occupies 1 byte*/
        + 1 /*version*/ + encoder.getEncodedBytesLength(certTypeLen) + certTypeLen + deviceInfoBytesLen
        + coseKeyBytesLen);
    short csrPayloadByteLen = encoder.getEncodedBytesLength(csrPayloadLen);
    short payloadByteLen = (short) ((short) 1 /*Array of 2 elements occupies 1 byte */
        +encoder.getEncodedBytesLength((short) CSR_CHALLENGE.length) +
        (short) CSR_CHALLENGE.length +
        csrPayloadByteLen +
        (short) 1 /*Array of 4 elements occupies 1 byte */ +
        (short) 1 + // Version occupies 1 byte
        encoder.getEncodedBytesLength(certTypeLen) +
        certTypeLen +
        deviceInfoBytesLen +
        coseKeyBytesLen);

    payloadLen += encoder.encodeByteBlobHeader(payloadByteLen, payload, payloadLen, (short) 3);
    payloadLen += encoder.encodeArrayHeader((short) 2, payload, payloadLen, (short) 3);

    payloadLen += encoder.encodeByteBlobHeader((short) CSR_CHALLENGE.length, payload, payloadLen,
            (short) 3);

    Util.arrayCopyNonAtomic(CSR_CHALLENGE,
            (short) 0,
            payload,
            payloadLen,
            (short) CSR_CHALLENGE.length);
    payloadLen += (short) CSR_CHALLENGE.length;

    payloadLen += encoder.encodeByteBlobHeader(csrPayloadLen, payload, payloadLen, (short) 3);
    payloadLen += encoder.encodeArrayHeader((short) 4, payload, payloadLen, (short) 3);

    short payloadSchemaVersion = KMInteger.uint_16(schemaVersion);
    payloadLen +=
        encoder.encode(payloadSchemaVersion, payload, payloadLen,
            KMKeymasterApplet.MAX_COSE_BUF_SIZE);

    short certTypeTstr = KMTextString.instance(cerTypeBytes, (short) 0, certTypeLen);
    payloadLen +=
        encoder.encode(certTypeTstr, payload, payloadLen, KMKeymasterApplet.MAX_COSE_BUF_SIZE);

    Util.arrayCopyNonAtomic(deviceInfoBytes,
        (short) 0,
        payload,
        payloadLen,
        deviceInfoBytesLen);
    payloadLen += deviceInfoBytesLen;

    Util.arrayCopyNonAtomic(cosyKeyArrayBytes,
        (short) 0,
        payload,
        payloadLen,
        coseKeyBytesLen);
    payloadLen += coseKeyBytesLen;

    byte moreData;
    byte[] udsCerts = new byte[2500];
    short offset = 0;
    do {
      apdu = new CommandAPDU(0x80, INS_GET_UDS_CERTS_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2, (byte[]) null, 65536); //Acc
      response = simulator.transmitCommand(apdu);
      arr = KMArray.instance((short) 3);
      KMArray.cast(arr).add((short) 0, KMInteger.exp()); // OK
      KMArray.cast(arr).add((short) 1, KMByteBlob.exp()); // data
      KMArray.cast(arr).add((short) 2, KMInteger.exp()); // more data

      resp = response.getBytes();
      ret = decoder.decode(arr, resp, (short) 0, (short) resp.length);
      Assert.assertEquals(KMTestUtils.getErrorCode(ret), KMError.OK);
      short partialData = KMArray.cast(ret).get((short) 1);
      Util.arrayCopyNonAtomic(KMByteBlob.cast(partialData).getBuffer(),
          KMByteBlob.cast(partialData).getStartOff(),
          udsCerts, offset, KMByteBlob.cast(partialData).length());
      offset += KMByteBlob.cast(partialData).length();

      moreData = KMInteger.cast(KMArray.cast(ret).get((short) 2)).getByte();
    } while (moreData != 0);
    short x509Arr = KMArray.exp(KMByteBlob.exp());
    short udsCertChain = KMMap.instance((short) 1);
    KMMap.cast(udsCertChain).add((short) 0, KMTextString.exp(), x509Arr);
    ret = decoder.decode(udsCertChain, udsCerts, (short) 0, offset);
    if (KMMap.cast(ret).length() > 0) {
      ret = KMMap.cast(ret).getKeyValue((short) 0);
      Assert.assertTrue(KMTestUtils.validateCertChain(ret));
    }
    byte[] diceCerts = new byte[2500];
    offset = 0;
    do {
      apdu = new CommandAPDU(0x80, INS_GET_DICE_CERT_CHAIN_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2, (byte[]) null,
          65536);// BCC
      response = simulator.transmitCommand(apdu);
      arr = KMArray.instance((short) 3);
      KMArray.cast(arr).add((short) 0, KMInteger.exp()); // OK
      KMArray.cast(arr).add((short) 1, KMByteBlob.exp()); // data
      KMArray.cast(arr).add((short) 2, KMInteger.exp()); // more data
      resp = response.getBytes();
      ret = decoder.decode(arr, resp, (short) 0, (short) resp.length);
      Assert.assertEquals(KMTestUtils.getErrorCode(ret), KMError.OK);
      short partialData = KMArray.cast(ret).get((short) 1);
      Util.arrayCopyNonAtomic(KMByteBlob.cast(partialData).getBuffer(),
          KMByteBlob.cast(partialData).getStartOff(),
          diceCerts, offset, KMByteBlob.cast(partialData).length());
      offset += KMByteBlob.cast(partialData).length();

      moreData = KMInteger.cast(KMArray.cast(ret).get((short) 2)).getByte();
    } while (moreData != 0);

    short coseKeyExp = KMCoseKey.exp();
    short signedMacArr = KMArray.instance((short) 4);
    short headersExp = KMCoseHeaders.exp();
    KMArray.cast(signedMacArr).add((short) 0, KMByteBlob.exp());
    KMArray.cast(signedMacArr).add((short) 1, headersExp);
    KMArray.cast(signedMacArr).add((short) 2, KMByteBlob.exp());
    KMArray.cast(signedMacArr).add((short) 3, KMByteBlob.exp());
    short dccArr = KMArray.instance((short) 2);
    KMArray.cast(dccArr).add((short) 0, coseKeyExp);
    KMArray.cast(dccArr).add((short) 1, signedMacArr);

    short dccPtr = decoder.decode(dccArr, diceCerts, (short) 0, offset);

    byte[] pubKey = new byte[100];
    short pubLen = KMTestUtils.getDccPublicKey(cryptoProvider, encoder, decoder,
        dccPtr, pubKey, (short) 0);

    byte[] encodedSignBuf = new byte[512];
    short encodedSignLen =
        KMTestUtils.encodeES256CoseSignSignature(
            signature,
            (short) 0,
            signatureLen,
            encodedSignBuf,
            (short) 0);
    // Verify the signature of cose sign1.
    KMTestUtils.print(payload, (short) 0, payloadLen);
    Assert.assertTrue(
        cryptoProvider.ecVerify256(pubKey, (short) 0, pubLen, payload, (short) 0, payloadLen,
            encodedSignBuf, (short) 0, encodedSignLen));

  }

}
