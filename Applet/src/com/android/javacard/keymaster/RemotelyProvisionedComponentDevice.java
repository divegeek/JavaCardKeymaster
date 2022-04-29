/*
 * Copyright(C) 2021 The Android Open Source Project
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
package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMDeviceUniqueKeyPair;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMOperation;
import com.android.javacard.seprovider.KMSEProvider;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/*
 * This class handles the remote key provisioning. Generates an RKP key and generates a certificate signing
 * request(CSR). The generation of CSR is divided amoung multiple functions to the save the memory inside
 * the Applet. The set of functions to be called sequentially in the order to complete the process of
 * generating the CSR are processBeginSendData, processUpdateKey, processUpdateEekChain,
 * processUpdateChallenge, processFinishSendData and getResponse. ProcessUpdateKey is called N times, where
 * N is the number of keys. Similarly getResponse is called is multiple times till the client receives the
 * response completely.
 */
public class RemotelyProvisionedComponentDevice {

  private static final byte TRUE = 0x01;
  private static final byte FALSE = 0x00;
  // RKP Version
  private static final short RKP_VERSION = (short) 0x01;
  // Boot params
  private static final byte OS_VERSION_ID = 0x00;
  private static final byte SYSTEM_PATCH_LEVEL_ID = 0x01;
  private static final byte BOOT_PATCH_LEVEL_ID = 0x02;
  private static final byte VENDOR_PATCH_LEVEL_ID = 0x03;
  // Device Info labels
  public static final byte[] BRAND = {0x62, 0x72, 0x61, 0x6E, 0x64};
  public static final byte[] MANUFACTURER = {0x6D, 0x61, 0x6E, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75,
      0x72, 0x65, 0x72};
  public static final byte[] PRODUCT = {0x70, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x74};
  public static final byte[] MODEL = {0x6D, 0x6F, 0x64, 0x65, 0x6C};
  public static final byte[] BOARD = {0x62, 0x6F, 0x61, 0x72, 0x64};
  public static final byte[] VB_STATE = {0x76, 0x62, 0x5F, 0x73, 0x74, 0x61, 0x74, 0x65};
  public static final byte[] BOOTLOADER_STATE =
      {0x62, 0x6F, 0x6F, 0x74, 0x6C, 0x6F, 0x61, 0x64, 0x65, 0x72, 0x5F, 0x73, 0x74, 0x61, 0x74,
          0x65};
  public static final byte[] VB_META_DIGEST =
      {0X76, 0X62, 0X6D, 0X65, 0X74, 0X61, 0X5F, 0X64, 0X69, 0X67, 0X65, 0X73, 0X74};
  public static final byte[] OS_VERSION = {0x6F, 0x73, 0x5F, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F,
      0x6E};
  public static final byte[] SYSTEM_PATCH_LEVEL =
      {0x73, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x5F, 0x70, 0x61, 0x74, 0x63, 0x68, 0x5F, 0x6C, 0x65,
          0x76, 0x65, 0x6C};
  public static final byte[] BOOT_PATCH_LEVEL =
      {0x62, 0x6F, 0x6F, 0x74, 0x5F, 0x70, 0x61, 0x74, 0x63, 0x68, 0x5F, 0x6C, 0x65, 0x76, 0x65,
          0x6C};
  public static final byte[] VENDOR_PATCH_LEVEL =
      {0x76, 0x65, 0x6E, 0x64, 0x6F, 0x72, 0x5F, 0x70, 0x61, 0x74, 0x63, 0x68, 0x5F, 0x6C, 0x65,
          0x76, 0x65, 0x6C};
  public static final byte[] DEVICE_INFO_VERSION =
      {0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E};
  public static final byte[] SECURITY_LEVEL =
      {0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5F, 0x6C, 0x65, 0x76, 0x65, 0x6C};
  public static final byte[] ATTEST_ID_STATE =
      {0x61, 0x74, 0x74, 0x5f, 0x69, 0x64, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65};
  // Verified boot state values
  public static final byte[] VB_STATE_GREEN = {0x67, 0x72, 0x65, 0x65, 0x6E};
  public static final byte[] VB_STATE_YELLOW = {0x79, 0x65, 0x6C, 0x6C, 0x6F, 0x77};
  public static final byte[] VB_STATE_ORANGE = {0x6F, 0x72, 0x61, 0x6E, 0x67, 0x65};
  public static final byte[] VB_STATE_RED = {0x72, 0x65, 0x64};
  // Boot loader state values
  public static final byte[] UNLOCKED = {0x75, 0x6E, 0x6C, 0x6F, 0x63, 0x6B, 0x65, 0x64};
  public static final byte[] LOCKED = {0x6C, 0x6F, 0x63, 0x6B, 0x65, 0x64};
  // Device info CDDL schema version
  public static final byte DI_SCHEMA_VERSION = 1;
  public static final byte[] DI_SECURITY_LEVEL = {0x73, 0x74, 0x72, 0x6F, 0x6E, 0x67, 0x62, 0x6F,
      0x78};
  public static final byte[] ATTEST_ID_LOCKED = {0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64};
  public static final byte[] ATTEST_ID_OPEN = {0x6f, 0x70, 0x65, 0x6e};
  private static final short MAX_SEND_DATA = 1024;
  // more data or no data
  private static final byte MORE_DATA = 0x01; // flag to denote more data to retrieve
  private static final byte NO_DATA = 0x00;
  // Response processing states
  private static final byte START_PROCESSING = 0x00;
  private static final byte PROCESSING_BCC_IN_PROGRESS = 0x02;
  private static final byte PROCESSING_BCC_COMPLETE = 0x04;
  private static final byte PROCESSING_ACC_IN_PROGRESS = 0x08; // Additional certificate chain.
  private static final byte PROCESSING_ACC_COMPLETE = 0x0A;
  // data table
  private static final short DATA_SIZE = 512;
  private static final short DATA_INDEX_SIZE = 11;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;
  // data offsets
  private static final short EPHEMERAL_MAC_KEY = 0;
  private static final short TOTAL_KEYS_TO_SIGN = 1;
  private static final short KEYS_TO_SIGN_COUNT = 2;
  private static final short TEST_MODE = 3;
  private static final short EEK_KEY = 4;
  private static final short EEK_KEY_ID = 5;
  private static final short CHALLENGE = 6;
  private static final short GENERATE_CSR_PHASE = 7;
  private static final short EPHEMERAL_PUB_KEY = 8;
  private static final short RESPONSE_PROCESSING_STATE = 9;
  private static final short ACC_PROCESSED_LENGTH = 10;

  // data item sizes
  private static final short MAC_KEY_SIZE = 32;
  private static final short SHORT_SIZE = 2;
  private static final short BYTE_SIZE = 1;
  private static final short TEST_MODE_SIZE = 1;
  // generate csr states
  private static final byte BEGIN = 0x01;
  private static final byte UPDATE = 0x02;
  private static final byte FINISH = 0x04;
  private static final byte GET_RESPONSE = 0x06;
  
  //RKP mac key size
  private static final short RKP_MAC_KEY_SIZE = 32;
  
  // variables
  private byte[] data;
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMRepository repository;
  private KMSEProvider seProvider;
  private KMKeymintDataStore storeDataInst;
  private Object[] operation;
  private short[] dataIndex;
  public static Object[] authorizedEekRoots;

  public RemotelyProvisionedComponentDevice(KMEncoder encoder, KMDecoder decoder,
      KMRepository repository, KMSEProvider seProvider, KMKeymintDataStore storeDInst) {
    this.encoder = encoder;
    this.decoder = decoder;
    this.repository = repository;
    this.seProvider = seProvider;
    this.storeDataInst = storeDInst;
    data = JCSystem.makeTransientByteArray(DATA_SIZE, JCSystem.CLEAR_ON_RESET);
    operation = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    dataIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    // Initialize RKP mac key
    short offset = repository.alloc((short) RKP_MAC_KEY_SIZE);
    byte[] buffer = repository.getHeap();
    seProvider.getTrueRandomNumber(buffer, offset, RKP_MAC_KEY_SIZE);
    storeDataInst.createRkpMacKey(buffer, offset, RKP_MAC_KEY_SIZE);
    operation[0] = null;
    createAuthorizedEEKRoot();
  }

  private void createAuthorizedEEKRoot() {
    if (authorizedEekRoots == null) {
      authorizedEekRoots =
          new Object[]
              {
                  new byte[]{
                      0x04,
                      (byte)0xf7, (byte)0x14, (byte)0x8a, (byte)0xdb, (byte)0x97, (byte)0xf4,
                      (byte)0xcc, (byte)0x53, (byte)0xef, (byte)0xd2, (byte)0x64, (byte)0x11,
                      (byte)0xc4, (byte)0xe3, (byte)0x75, (byte)0x1f, (byte)0x66, (byte)0x1f,
                      (byte)0xa4, (byte)0x71, (byte)0x0c, (byte)0x6c, (byte)0xcf, (byte)0xfa,
                      (byte)0x09, (byte)0x46, (byte)0x80, (byte)0x74, (byte)0x87, (byte)0x54,
                      (byte)0xf2, (byte)0xad,
                      (byte)0x5e, (byte)0x7f, (byte)0x5b, (byte)0xf6, (byte)0xec, (byte)0xe4,
                      (byte)0xf6, (byte)0x19, (byte)0xcc, (byte)0xff, (byte)0x13, (byte)0x37,
                      (byte)0xfd, (byte)0x0f, (byte)0xa1, (byte)0xc8, (byte)0x93, (byte)0xdb,
                      (byte)0x18, (byte)0x06, (byte)0x76, (byte)0xc4, (byte)0x5d, (byte)0xe6,
                      (byte)0xd7, (byte)0x6a, (byte)0x77, (byte)0x86, (byte)0xc3, (byte)0x2d,
                      (byte)0xaf, (byte)0x8f
                  },
              };
    }
  }

  private void initializeDataTable() {
    if (dataIndex[0] != 0) {
      KMException.throwIt(KMError.INVALID_STATE);
    }
    dataIndex[0] = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
  }

  private short dataAlloc(short length) {
    if ((short) (dataIndex[0] + length) > (short) data.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    dataIndex[0] += length;
    return (short) (dataIndex[0] - length);
  }

  private void clearDataTable() {
    Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0x00);
    dataIndex[0] = 0x00;
  }

  private void releaseOperation() {
    if (operation[0] != null) {
      ((KMOperation) operation[0]).abort();
      operation[0] = null;
    }
  }

  private short createEntry(short index, short length) {
    index = (short) (index * DATA_INDEX_ENTRY_SIZE);
    short ptr = dataAlloc(length);
    Util.setShort(data, index, length);
    Util.setShort(data, (short) (index + DATA_INDEX_ENTRY_OFFSET), ptr);
    return ptr;
  }

  private short getEntry(short index) {
    index = (short) (index * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(data, (short) (index + DATA_INDEX_ENTRY_OFFSET));
  }

  private short getEntryLength(short index) {
    index = (short) (index * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(data, index);
  }

  private void processGetRkpHwInfoCmd(APDU apdu) {
    // Make the response
    // Author name - Google.
    final byte[] google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
    short respPtr = KMArray.instance((short) 4);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMInteger.uint_16(KMError.OK));
    resp.add((short) 1, KMInteger.uint_16(RKP_VERSION));
    resp.add((short) 2, KMByteBlob.instance(google, (short) 0, (short) google.length));
    resp.add((short) 3, KMInteger.uint_8(KMType.RKP_CURVE_P256));
    KMKeymasterApplet.sendOutgoing(apdu, respPtr);
  }

  /**
   * This function generates an EC key pair with attest key as purpose and creates an encrypted key
   * blob. It then generates a COSEMac message which includes the ECDSA public key.
   */
  public void processGenerateRkpKey(APDU apdu) {
    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMSimpleValue.exp());
    arr = KMKeymasterApplet.receiveIncoming(apdu, arr);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // test mode flag.
    boolean testMode =
        (KMSimpleValue.TRUE == KMSimpleValue.cast(KMArray.cast(arr).get((short) 0)).getValue());
    KMKeymasterApplet.generateRkpKey(scratchPad, getEcAttestKeyParameters());
    short pubKey = KMKeymasterApplet.getPubKey();
    short coseMac0 = constructCoseMacForRkpKey(testMode, scratchPad, pubKey);
    // Encode the COSE_MAC0 object
    arr = KMArray.instance((short) 3);
    KMArray.cast(arr).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(arr).add((short) 1, coseMac0);
    KMArray.cast(arr).add((short) 2, KMKeymasterApplet.getPivateKey());
    KMKeymasterApplet.sendOutgoing(apdu, arr);
  }

  public void processBeginSendData(APDU apdu) throws Exception {
    try {
      initializeDataTable();
      short arr = KMArray.instance((short) 3);
      KMArray.cast(arr).add((short) 0, KMInteger.exp()); // Array length
      KMArray.cast(arr).add((short) 1, KMInteger.exp()); // Total length of the encoded CoseKeys.
      KMArray.cast(arr).add((short) 2, KMSimpleValue.exp());
      arr = KMKeymasterApplet.receiveIncoming(apdu, arr);
      // Re-purpose the apdu buffer as scratch pad.
      byte[] scratchPad = apdu.getBuffer();
      // Generate ephemeral mac key.
      short dataEntryIndex = createEntry(EPHEMERAL_MAC_KEY, MAC_KEY_SIZE);
      seProvider.newRandomNumber(data, dataEntryIndex, MAC_KEY_SIZE);
      // Initialize hmac operation.
      initHmacOperation();
      // Partially encode CoseMac structure with partial payload.
      constructPartialPubKeysToSignMac(scratchPad,
          KMInteger.cast(KMArray.cast(arr).get((short) 0)).getShort(),
          KMInteger.cast(KMArray.cast(arr).get((short) 1)).getShort());
      // Store the total keys in data table.
      dataEntryIndex = createEntry(TOTAL_KEYS_TO_SIGN, SHORT_SIZE);
      Util.setShort(data, dataEntryIndex,
          KMInteger.cast(KMArray.cast(arr).get((short) 0)).getShort());
      // Store the test mode value in data table.
      dataEntryIndex = createEntry(TEST_MODE, TEST_MODE_SIZE);
      data[dataEntryIndex] =
          (KMSimpleValue.TRUE == KMSimpleValue.cast(KMArray.cast(arr).get((short) 2)).getValue()) ?
              TRUE : FALSE;
      // Store the current csr status, which is BEGIN.
      createEntry(GENERATE_CSR_PHASE, BYTE_SIZE);
      updateState(BEGIN);
      // Send response.
      KMKeymasterApplet.sendError(apdu, KMError.OK);
    } catch (Exception e) {
      clearDataTable();
      releaseOperation();
      throw e;
    }
  }

  public void processUpdateKey(APDU apdu) throws Exception {
    try {
      // The prior state can be BEGIN or UPDATE
      validateState((byte) (BEGIN | UPDATE));
      validateKeysToSignCount();
      short headers = KMCoseHeaders.exp();
      short arrInst = KMArray.instance((short) 4);
      KMArray.cast(arrInst).add((short) 0, KMByteBlob.exp());
      KMArray.cast(arrInst).add((short) 1, headers);
      KMArray.cast(arrInst).add((short) 2, KMByteBlob.exp());
      KMArray.cast(arrInst).add((short) 3, KMByteBlob.exp());
      short arr = KMArray.exp(arrInst);
      arr = KMKeymasterApplet.receiveIncoming(apdu, arr);
      arrInst = KMArray.cast(arr).get((short) 0);
      // Re-purpose the apdu buffer as scratch pad.
      byte[] scratchPad = apdu.getBuffer();

      // Validate and extract the CoseKey from CoseMac0 message.
      short coseKey = validateAndExtractPublicKey(arrInst, scratchPad);
      // Encode CoseKey
      short length = KMKeymasterApplet.encodeToApduBuffer(coseKey, scratchPad, (short) 0,
          KMKeymasterApplet.MAX_COSE_BUF_SIZE);
      // Do Hmac update with input as encoded CoseKey.
      ((KMOperation) operation[0]).update(scratchPad, (short) 0, length);
      // Increment the count each time this function gets executed.
      // Store the count in data table.
      short dataEntryIndex = getEntry(KEYS_TO_SIGN_COUNT);
      if (dataEntryIndex == 0) {
        dataEntryIndex = createEntry(KEYS_TO_SIGN_COUNT, SHORT_SIZE);
      }
      length = Util.getShort(data, dataEntryIndex);
      Util.setShort(data, dataEntryIndex, ++length);
      // Update the csr state
      updateState(UPDATE);
      // Send response.
      KMKeymasterApplet.sendError(apdu, KMError.OK);
    } catch (Exception e) {
      clearDataTable();
      releaseOperation();
      throw e;
    }
  }

  public void processUpdateEekChain(APDU apdu) throws Exception {
    try {
      // The prior state can be BEGIN or UPDATE
      validateState((byte) (BEGIN | UPDATE));
      short headers = KMCoseHeaders.exp();
      short arrInst = KMArray.instance((short) 4);
      KMArray.cast(arrInst).add((short) 0, KMByteBlob.exp());
      KMArray.cast(arrInst).add((short) 1, headers);
      KMArray.cast(arrInst).add((short) 2, KMByteBlob.exp());
      KMArray.cast(arrInst).add((short) 3, KMByteBlob.exp());
      short arrSignPtr = KMArray.exp(arrInst);
      arrInst = KMKeymasterApplet.receiveIncoming(apdu, arrSignPtr);
      if (KMArray.cast(arrInst).length() == 0) {
        KMException.throwIt(KMError.STATUS_INVALID_EEK);
      }
      // Re-purpose the apdu buffer as scratch pad.
      byte[] scratchPad = apdu.getBuffer();
      // Validate eek chain.
      short eekKey = validateAndExtractEekPub(arrInst, scratchPad);
      // Store eek public key and eek id in the data table.
      short eekKeyId = KMCoseKey.cast(eekKey).getKeyIdentifier();
      short dataEntryIndex = createEntry(EEK_KEY_ID, KMByteBlob.cast(eekKeyId).length());
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(eekKeyId).getBuffer(),
          KMByteBlob.cast(eekKeyId).getStartOff(),
          data,
          dataEntryIndex,
          KMByteBlob.cast(eekKeyId).length()
      );
      // Convert the coseKey to a public key.
      short len = KMCoseKey.cast(eekKey).getEcdsa256PublicKey(scratchPad, (short) 0);
      dataEntryIndex = createEntry(EEK_KEY, len);
      Util.arrayCopyNonAtomic(scratchPad, (short) 0, data, dataEntryIndex, len);
      // Update the state
      updateState(UPDATE);
      KMKeymasterApplet.sendError(apdu, KMError.OK);
    } catch (Exception e) {
      clearDataTable();
      releaseOperation();
      throw e;
    }
  }

  public void processUpdateChallenge(APDU apdu) throws Exception {
    try {
      // The prior state can be BEGIN or UPDATE
      validateState((byte) (BEGIN | UPDATE));
      short arr = KMArray.instance((short) 1);
      KMArray.cast(arr).add((short) 0, KMByteBlob.exp());
      arr = KMKeymasterApplet.receiveIncoming(apdu, arr);
      // Store the challenge in the data table.
      short challenge = KMArray.cast(arr).get((short) 0);
      short dataEntryIndex = createEntry(CHALLENGE, KMByteBlob.cast(challenge).length());
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(challenge).getBuffer(),
          KMByteBlob.cast(challenge).getStartOff(),
          data,
          dataEntryIndex,
          KMByteBlob.cast(challenge).length()
      );
      // Update the state
      updateState(UPDATE);
      KMKeymasterApplet.sendError(apdu, KMError.OK);
    } catch (Exception e) {
      clearDataTable();
      releaseOperation();
      throw e;
    }
  }

  // This function returns pubKeysToSignMac, deviceInfo and partially constructed protected data
  // wrapped inside byte blob. The partial protected data contains Headers and encrypted signedMac.
  public void processFinishSendData(APDU apdu) throws Exception {
    try {
      // The prior state should be UPDATE.
      validateState(UPDATE);
      byte[] scratchPad = apdu.getBuffer();
      if (data[getEntry(TOTAL_KEYS_TO_SIGN)] != data[getEntry(KEYS_TO_SIGN_COUNT)]) {
        // Mismatch in the number of keys sent.
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      // PubKeysToSignMac
      byte[] empty = {};
      short len =
          ((KMOperation) operation[0]).sign(empty, (short) 0,
              (short) 0, scratchPad, (short) 0);
      // release operation
      releaseOperation();
      short pubKeysToSignMac = KMByteBlob.instance(scratchPad, (short) 0, len);
      // Create DeviceInfo
      short deviceInfo = createDeviceInfo(scratchPad);
      // Generate Nonce for AES-GCM
      seProvider.newRandomNumber(scratchPad, (short) 0,
          KMKeymasterApplet.AES_GCM_NONCE_LENGTH);
      short nonce = KMByteBlob.instance(scratchPad, (short) 0,
          KMKeymasterApplet.AES_GCM_NONCE_LENGTH);
      // Initializes cipher instance.
      initAesGcmOperation(scratchPad, nonce);
      // Encode Enc_Structure as additional data for AES-GCM.
      processAesGcmUpdateAad(scratchPad);
      short partialPayloadLen = processSignedMac(scratchPad, pubKeysToSignMac, deviceInfo);
      short partialCipherText = KMByteBlob.instance(scratchPad, (short) 0, partialPayloadLen);
      short coseEncryptProtectedHeader = getCoseEncryptProtectedHeader(scratchPad);
      short coseEncryptUnProtectedHeader = getCoseEncryptUnprotectedHeader(scratchPad, nonce);
      len = KMKeymasterApplet.encodeToApduBuffer(deviceInfo, scratchPad,
              (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
      short encodedDeviceInfo =  KMByteBlob.instance(scratchPad, (short) 0, len);
      updateState(FINISH);
      short arr = KMArray.instance((short) 7);
      KMArray.cast(arr).add((short) 0, KMInteger.uint_16(KMError.OK));
      KMArray.cast(arr).add((short) 1, pubKeysToSignMac);
      KMArray.cast(arr).add((short) 2, encodedDeviceInfo);
      KMArray.cast(arr).add((short) 3, coseEncryptProtectedHeader);
      KMArray.cast(arr).add((short) 4, coseEncryptUnProtectedHeader);
      KMArray.cast(arr).add((short) 5, partialCipherText);
      KMArray.cast(arr).add((short) 6, KMInteger.uint_8(MORE_DATA));
      KMKeymasterApplet.sendOutgoing(apdu, arr);
    } catch (Exception e) {
      clearDataTable();
      releaseOperation();
      throw e;
    }
  }

  public void processGetResponse(APDU apdu) throws Exception {
    try {
      // The prior state should be FINISH.
      validateState((byte) (FINISH | GET_RESPONSE));
      byte[] scratchPad = apdu.getBuffer();
      short len = 0;
      short recipientStructure = KMArray.instance((short) 0);
      byte moreData = MORE_DATA;
      byte state = getCurrentOutputProcessingState();
      switch (state) {
        case START_PROCESSING:
        case PROCESSING_BCC_IN_PROGRESS:
          len = processBcc(scratchPad);
          updateState(GET_RESPONSE);
          break;
        case PROCESSING_BCC_COMPLETE:
        case PROCESSING_ACC_IN_PROGRESS:
          len = processAdditionalCertificateChain(scratchPad);
          updateState(GET_RESPONSE);
          break;
        case PROCESSING_ACC_COMPLETE:
          recipientStructure = processRecipientStructure(scratchPad);
          len = processFinalData(scratchPad);
          moreData = NO_DATA;
          releaseOperation();
          clearDataTable();
          break;
        default:
          KMException.throwIt(KMError.INVALID_STATE);
      }
      short data = KMByteBlob.instance(scratchPad, (short) 0, len);
      short arr = KMArray.instance((short) 4);
      KMArray.cast(arr).add((short) 0, KMInteger.uint_16(KMError.OK));
      KMArray.cast(arr).add((short) 1, data);
      KMArray.cast(arr).add((short) 2, recipientStructure);
      // represents there is more output to retrieve
      KMArray.cast(arr).add((short) 3, KMInteger.uint_8(moreData));
      KMKeymasterApplet.sendOutgoing(apdu, arr);
    } catch (Exception e) {
      clearDataTable();
      releaseOperation();
      throw e;
    }
  }

  public void process(short ins, APDU apdu) throws Exception  {
    switch (ins) {
      case KMKeymasterApplet.INS_GET_RKP_HARDWARE_INFO:
        processGetRkpHwInfoCmd(apdu);
        break;
      case KMKeymasterApplet.INS_GENERATE_RKP_KEY_CMD:
        processGenerateRkpKey(apdu);
        break;
      case KMKeymasterApplet.INS_BEGIN_SEND_DATA_CMD:
        processBeginSendData(apdu);
        break;
      case KMKeymasterApplet.INS_UPDATE_KEY_CMD:
        processUpdateKey(apdu);
        break;
      case KMKeymasterApplet.INS_UPDATE_EEK_CHAIN_CMD:
        processUpdateEekChain(apdu);
        break;
      case KMKeymasterApplet.INS_UPDATE_CHALLENGE_CMD:
        processUpdateChallenge(apdu);
        break;
      case KMKeymasterApplet.INS_FINISH_SEND_DATA_CMD:
        processFinishSendData(apdu);
        break;
      case KMKeymasterApplet.INS_GET_RESPONSE_CMD:
        processGetResponse(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  private boolean isAdditionalCertificateChainPresent() {
    return (storeDataInst.getAdditionalCertChainLength() == 0 ? false : true);
  }

  private short processFinalData(byte[] scratchPad) {
    // Call finish on AES GCM Cipher
    byte[] empty = {};
    short len =
        ((KMOperation) operation[0]).finish(empty, (short) 0, (short) 0, scratchPad, (short) 0);
    return len;
  }

  private byte getCurrentOutputProcessingState() {
    short index = getEntry(RESPONSE_PROCESSING_STATE);
    if (index == 0) {
      return START_PROCESSING;
    }
    return data[index];
  }

  private void updateOutputProcessingState(byte state) {
    short dataEntryIndex = getEntry(RESPONSE_PROCESSING_STATE);
    data[dataEntryIndex] = state;
  }

  /**
   * Validates the CoseMac message and extracts the CoseKey from it.
   *
   * @param coseMacPtr CoseMac instance to be validated.
   * @param scratchPad Scratch buffer used to store temp results.
   * @return CoseKey instance.
   */
  private short validateAndExtractPublicKey(short coseMacPtr, byte[] scratchPad) {
    boolean testMode = (TRUE == data[getEntry(TEST_MODE)]) ? true : false;
    // Exp for KMCoseHeaders
    short coseHeadersExp = KMCoseHeaders.exp();
    // Exp for coseky
    short coseKeyExp = KMCoseKey.exp();
    
    // validate protected Headers
    short ptr = KMArray.cast(coseMacPtr).get(KMCose.COSE_MAC0_PROTECTED_PARAMS_OFFSET);
    ptr = decoder.decode(coseHeadersExp, KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(), KMByteBlob.cast(ptr).length());

    if (!KMCoseHeaders.cast(ptr).isDataValid(KMCose.COSE_ALG_HMAC_256, KMType.INVALID_VALUE)) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }

    // Validate payload.
    ptr = KMArray.cast(coseMacPtr).get(KMCose.COSE_MAC0_PAYLOAD_OFFSET);
    ptr = decoder.decode(coseKeyExp, KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(), KMByteBlob.cast(ptr).length());

    if (!KMCoseKey.cast(ptr).isDataValid(KMCose.COSE_KEY_TYPE_EC2, KMType.INVALID_VALUE,
        KMCose.COSE_ALG_ES256, KMType.INVALID_VALUE, KMCose.COSE_ECCURVE_256)) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }

    boolean isTestKey = KMCoseKey.cast(ptr).isTestKey();
    if (isTestKey && !testMode) {
      KMException.throwIt(KMError.STATUS_TEST_KEY_IN_PRODUCTION_REQUEST);
    } else if (!isTestKey && testMode) {
      KMException.throwIt(KMError.STATUS_PRODUCTION_KEY_IN_TEST_REQUEST);
    }

    // Compute CoseMac Structure and compare the macs.
    short macStructure =
        KMCose.constructCoseMacStructure(KMArray.cast(coseMacPtr).get(
            KMCose.COSE_MAC0_PROTECTED_PARAMS_OFFSET),
            KMByteBlob.instance((short) 0),
            KMArray.cast(coseMacPtr).get(KMCose.COSE_MAC0_PAYLOAD_OFFSET));
    short encodedLen = KMKeymasterApplet.encodeToApduBuffer(macStructure, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);

    short hmacLen = rkpHmacSign(testMode, scratchPad, (short) 0, encodedLen, scratchPad, encodedLen);

    if (hmacLen != KMByteBlob.cast(
        KMArray.cast(coseMacPtr).get(KMCose.COSE_MAC0_TAG_OFFSET)).length()) {
      KMException.throwIt(KMError.STATUS_INVALID_MAC);
    }

    if (0 != Util.arrayCompare(scratchPad, encodedLen,
        KMByteBlob.cast(KMArray.cast(coseMacPtr).get(KMCose.COSE_MAC0_TAG_OFFSET)).getBuffer(),
        KMByteBlob.cast(KMArray.cast(coseMacPtr).get(KMCose.COSE_MAC0_TAG_OFFSET)).getStartOff(),
        hmacLen)) {
      KMException.throwIt(KMError.STATUS_INVALID_MAC);
    }
    return ptr;
  }



  /**
   * This function validates the EEK Chain and extracts the leaf public key, which is used to
   * generate shared secret using ECDH.
   *
   * @param eekArr EEK cert chain array pointer.
   * @param scratchPad Scratch buffer used to store temp results.
   * @return CoseKey instance.
   */
  private short validateAndExtractEekPub(short eekArr, byte[] scratchPad) {
    short leafPubKey = 0;
    try {
      leafPubKey =
          KMKeymasterApplet.validateCertChain(
              (TRUE == data[getEntry(TEST_MODE)]) ? false : true, // validate EEK root
              KMCose.COSE_ALG_ES256,
              KMCose.COSE_ALG_ECDH_ES_HKDF_256,
              eekArr,
              scratchPad,
              authorizedEekRoots
          );
    } catch (KMException e) {
      KMException.throwIt(KMError.STATUS_INVALID_EEK);
    }
    return leafPubKey;
  }

  private void validateKeysToSignCount() {
    short index = getEntry(KEYS_TO_SIGN_COUNT);
    short keysToSignCount = 0;
    if (index != 0) {
      keysToSignCount = Util.getShort(data, index);
    }
    if (Util.getShort(data, getEntry(TOTAL_KEYS_TO_SIGN)) <= keysToSignCount) {
      // Mismatch in the number of keys sent.
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void validateState(byte expectedState) {
    short dataEntryIndex = getEntry(GENERATE_CSR_PHASE);
    if (0 == (data[dataEntryIndex] & expectedState)) {
      KMException.throwIt(KMError.INVALID_STATE);
    }
  }

  private void updateState(byte state) {
    short dataEntryIndex = getEntry(GENERATE_CSR_PHASE);
    if (dataEntryIndex == 0) {
      KMException.throwIt(KMError.INVALID_STATE);
    }
    data[dataEntryIndex] = state;
  }


  /**
   * This function constructs a Mac Structure, encode it and signs the encoded buffer with the
   * ephemeral mac key.
   */
  private void constructPartialPubKeysToSignMac(byte[] scratchPad, short arrayLength,
      short encodedCoseKeysLen) {
    short ptr;
    short len;
    short headerPtr = KMCose.constructHeaders(
        KMInteger.uint_8(KMCose.COSE_ALG_HMAC_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    len = KMKeymasterApplet.encodeToApduBuffer(headerPtr, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    short protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, len);
    // create MAC_Structure
    ptr =
        KMCose.constructCoseMacStructure(protectedHeader,
            KMByteBlob.instance((short) 0), KMType.INVALID_VALUE);
    // Encode the Mac_structure and do HMAC_Sign to produce the tag for COSE_MAC0
    len = KMKeymasterApplet.encodeToApduBuffer(ptr, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    // Construct partial payload - Bstr Header + Array Header
    // The maximum combined length of bstr header and array header length is 6 bytes.
    // The lengths will never exceed Max SHORT value.
    short arrPtr = KMArray.instance(arrayLength);
    for (short i = 0; i < arrayLength; i++) {
      KMArray.cast(arrPtr).add(i, KMType.INVALID_VALUE);
    }
    arrayLength = encoder.getEncodedLength(arrPtr);
    short bufIndex = repository.alloc((short) 6);
    short partialPayloadLen =
        encoder.encodeByteBlobHeader((short) (arrayLength + encodedCoseKeysLen),
            repository.getHeap(),
            bufIndex, (short) 3);

    partialPayloadLen +=
        encoder.encode(arrPtr, repository.getHeap(), (short) (bufIndex + partialPayloadLen), repository.getHeapReclaimIndex());
    Util.arrayCopyNonAtomic(repository.getHeap(), bufIndex, scratchPad, len, partialPayloadLen);
    ((KMOperation) operation[0]).update(scratchPad, (short) 0, (short) (len + partialPayloadLen));
  }

  private short createSignedMac(KMDeviceUniqueKeyPair deviceUniqueKeyPair, byte[] scratchPad,
      short deviceMapPtr, short pubKeysToSign) {
    // Challenge
    short dataEntryIndex = getEntry(CHALLENGE);
    short challengePtr = KMByteBlob.instance(data, dataEntryIndex, getEntryLength(CHALLENGE));
    // Ephemeral mac key
    dataEntryIndex = getEntry(EPHEMERAL_MAC_KEY);
    short ephmeralMacKey =
        KMByteBlob.instance(data, dataEntryIndex, getEntryLength(EPHEMERAL_MAC_KEY));

    /* Prepare AAD */
    short aad = KMArray.instance((short) 3);
    KMArray.cast(aad).add((short) 0, challengePtr);
    KMArray.cast(aad).add((short) 1, deviceMapPtr);
    KMArray.cast(aad).add((short) 2, pubKeysToSign);
    aad = KMKeymasterApplet.encodeToApduBuffer(aad, scratchPad,
        (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    aad = KMByteBlob.instance(scratchPad, (short) 0, aad);

    /* construct protected header */
    short protectedHeaders = KMCose.constructHeaders(
        KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    protectedHeaders = KMKeymasterApplet.encodeToApduBuffer(protectedHeaders, scratchPad,
        (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    protectedHeaders = KMByteBlob.instance(scratchPad, (short) 0, protectedHeaders);

    /* construct cose sign structure */
    short signStructure =
        KMCose.constructCoseSignStructure(protectedHeaders, aad, ephmeralMacKey);
    signStructure = KMKeymasterApplet.encodeToApduBuffer(signStructure, scratchPad,
        (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    short len =
        seProvider.ecSign256(
            deviceUniqueKeyPair,
            scratchPad,
            (short) 0,
            signStructure,
            scratchPad,
            signStructure
        );
    len = KMAsn1Parser.instance().
            decodeEcdsa256Signature(KMByteBlob.instance(scratchPad, signStructure, len), scratchPad, signStructure);
    signStructure = KMByteBlob.instance(scratchPad, signStructure, len);

    /* Construct unprotected headers */
    short unprotectedHeader = KMArray.instance((short) 0);
    unprotectedHeader = KMCoseHeaders.instance(unprotectedHeader);

    /* construct Cose_Sign1 */
    return KMCose.constructCoseSign1(protectedHeaders, unprotectedHeader,
        ephmeralMacKey, signStructure);
  }


  private KMDeviceUniqueKeyPair createDeviceUniqueKeyPair(boolean testMode, byte[] scratchPad) {
    KMDeviceUniqueKeyPair deviceUniqueKeyPair;
    short[] lengths = {0, 0};
    if (testMode) {
      seProvider.createAsymmetricKey(
          KMType.EC,
          scratchPad,
          (short) 0,
          (short) 128,
          scratchPad,
          (short) 128,
          (short) 128,
          lengths);
      deviceUniqueKeyPair =
    		storeDataInst.createRkpTestDeviceUniqueKeyPair(scratchPad, (short) 128, lengths[1],
              scratchPad, (short) 0, lengths[0]);
    } else {
      deviceUniqueKeyPair = storeDataInst.getRkpDeviceUniqueKeyPair(false);
    }
    return deviceUniqueKeyPair;
  }

  /**
   * DeviceInfo is a CBOR Map structure described by the following CDDL.
   * <p>
   * DeviceInfo = {
   * ? "brand" : tstr,
   * ? "manufacturer" : tstr,
   * ? "product" : tstr,
   * ? "model" : tstr,
   * ? "board" : tstr,
   * ? "vb_state" : "green" / "yellow" / "orange",    // Taken from the AVB values
   * ? "bootloader_state" : "locked" / "unlocked",    // Taken from the AVB values
   * ? "vbmeta_digest": bstr,                         // Taken from the AVB values
   * ? "os_version" : tstr,                    // Same as android.os.Build.VERSION.release
   * ? "system_patch_level" : uint,                   // YYYYMMDD
   * ? "boot_patch_level" : uint,                     //YYYYMMDD
   * ? "vendor_patch_level" : uint,                   // YYYYMMDD
   * "version" : 1, // TheCDDL schema version
   * "security_level" : "tee" / "strongbox"
   * "att_id_state": "locked" / "open"
   * }
   */
  private short createDeviceInfo(byte[] scratchpad) {
    // Device Info Key Value pairs.
    short[] deviceIds = {
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE,
    };
    short[] out = {0/* index */, 0 /* length */};
    updateItem(deviceIds, out, BRAND, getAttestationId(KMType.ATTESTATION_ID_BRAND, scratchpad));
    updateItem(deviceIds, out, MANUFACTURER,
        getAttestationId(KMType.ATTESTATION_ID_MANUFACTURER, scratchpad));
    updateItem(deviceIds, out, PRODUCT,
        getAttestationId(KMType.ATTESTATION_ID_PRODUCT, scratchpad));
    updateItem(deviceIds, out, MODEL, getAttestationId(KMType.ATTESTATION_ID_MODEL, scratchpad));
    updateItem(deviceIds, out, VB_STATE, getVbState());
    updateItem(deviceIds, out, BOOTLOADER_STATE, getBootloaderState());
    updateItem(deviceIds, out, VB_META_DIGEST, getVerifiedBootHash(scratchpad));
    updateItem(deviceIds, out, OS_VERSION, getBootParams(OS_VERSION_ID, scratchpad));
    updateItem(deviceIds, out, SYSTEM_PATCH_LEVEL,
        getBootParams(SYSTEM_PATCH_LEVEL_ID, scratchpad));
    updateItem(deviceIds, out, BOOT_PATCH_LEVEL, getBootParams(BOOT_PATCH_LEVEL_ID, scratchpad));
    updateItem(deviceIds, out, VENDOR_PATCH_LEVEL,
        getBootParams(VENDOR_PATCH_LEVEL_ID, scratchpad));
    updateItem(deviceIds, out, DEVICE_INFO_VERSION, KMInteger.uint_8(DI_SCHEMA_VERSION));
    updateItem(deviceIds, out, SECURITY_LEVEL,
        KMTextString.instance(DI_SECURITY_LEVEL, (short) 0, (short) DI_SECURITY_LEVEL.length));
    byte[] attestIdState = storeDataInst.isProvisionLocked() ? ATTEST_ID_LOCKED : ATTEST_ID_OPEN;
    updateItem(deviceIds, out, ATTEST_ID_STATE,
            KMTextString.instance(attestIdState, (short) 0, (short) attestIdState.length));
    // Create device info map.
    short map = KMMap.instance(out[1]);
    short mapIndex = 0;
    short index = 0;
    while (index < (short) deviceIds.length) {
      if (deviceIds[index] != KMType.INVALID_VALUE) {
        KMMap.cast(map).add(mapIndex++, deviceIds[index], deviceIds[(short) (index + 1)]);
      }
      index += 2;
    }
    KMMap.cast(map).canonicalize();
    return map;
  }

  // Below 6 methods are helper methods to create device info structure.
  //----------------------------------------------------------------------------

  /**
   * Update the item inside the device info structure.
   *
   * @param deviceIds Device Info structure to be updated.
   * @param meta Out parameter meta information. Offset 0 is index and Offset 1 is length.
   * @param item Key info to be updated.
   * @param value value to be updated.
   */
  private void updateItem(short[] deviceIds, short[] meta, byte[] item, short value) {
    if (KMType.INVALID_VALUE != value) {
      deviceIds[meta[0]++] =
          KMTextString.instance(item, (short) 0, (short) item.length);
      deviceIds[meta[0]++] = value;
      meta[1]++;
    }
  }

  private short getAttestationId(short attestId, byte[] scratchpad) {
    short attIdTagLen = storeDataInst.getAttestationId(attestId, scratchpad, (short) 0);
    if (attIdTagLen != 0) {
      return KMTextString.instance(scratchpad, (short) 0, attIdTagLen);
    }
    return KMType.INVALID_VALUE;
  }

  private short getVerifiedBootHash(byte[] scratchPad) {
    short len = storeDataInst.getVerifiedBootHash(scratchPad, (short) 0);
    if (len != 0) {
      return KMByteBlob.instance(scratchPad, (short) 0, len);
    }
    return KMType.INVALID_VALUE;
  }

  private short getBootloaderState() {
    short bootloaderState;
    if (storeDataInst.isDeviceBootLocked()) {
      bootloaderState = KMTextString.instance(LOCKED, (short) 0, (short) LOCKED.length);
    } else {
      bootloaderState = KMTextString.instance(UNLOCKED, (short) 0, (short) UNLOCKED.length);
    }
    return bootloaderState;
  }

  private short getVbState() {
    short state = storeDataInst.getBootState();
    short vbState = KMType.INVALID_VALUE;
    if (state == KMType.VERIFIED_BOOT) {
      vbState = KMTextString.instance(VB_STATE_GREEN, (short) 0, (short) VB_STATE_GREEN.length);
    } else if (state == KMType.SELF_SIGNED_BOOT) {
      vbState = KMTextString.instance(VB_STATE_YELLOW, (short) 0, (short) VB_STATE_YELLOW.length);
    } else if (state == KMType.UNVERIFIED_BOOT) {
      vbState = KMTextString.instance(VB_STATE_ORANGE, (short) 0, (short) VB_STATE_ORANGE.length);
    } else if (state == KMType.FAILED_BOOT) {
      vbState = KMTextString.instance(VB_STATE_RED, (short) 0, (short) VB_STATE_RED.length);
    }
    return vbState;
  }

  private short converIntegerToTextString(short intPtr, byte[] scratchPad) {
    // Prepare Hex Values
    short index = 1;
    scratchPad[0] = 0x30; // Ascii 0
    while(index < 10) {
      scratchPad[index] = (byte) (scratchPad[(short) (index - 1)] + 1);
      index++;
    }
    scratchPad[index++] = 0x41; // Ascii 'A'
    while(index < 16) {
      scratchPad[index] = (byte) (scratchPad[(short) (index - 1)] + 1);
      index++;
    }
    
    
    short intLen = KMInteger.cast(intPtr).length();
    short intOffset = KMInteger.cast(intPtr).getStartOff();
    byte[] buf = repository.getHeap();
    short tsPtr = KMTextString.instance((short) (intLen * 2));
    short tsStartOff = KMTextString.cast(tsPtr).getStartOff();
    index = 0;
    byte nibble;
    while (index < intLen) {
      nibble = (byte) ((byte) (buf[intOffset] >> 4) & (byte) 0x0F);
      buf[tsStartOff] = scratchPad[nibble];
      nibble = (byte) (buf[intOffset] & 0x0F);
      buf[(short) (tsStartOff + 1)] = scratchPad[nibble];
      index++;
      intOffset++;
      tsStartOff += 2;
    }
    return tsPtr;
  }

  private short getBootParams(byte bootParam, byte[] scratchPad) {
    short value = KMType.INVALID_VALUE;
    switch (bootParam) {
      case OS_VERSION_ID:
        value = storeDataInst.getOsVersion();
        break;
      case SYSTEM_PATCH_LEVEL_ID:
        value = storeDataInst.getOsPatch();
        break;
      case BOOT_PATCH_LEVEL_ID:
        short len = storeDataInst.getBootPatchLevel(scratchPad, (short) 0);
        value = KMByteBlob.instance(scratchPad, (short) 0, len);
        break;
      case VENDOR_PATCH_LEVEL_ID:
        value = storeDataInst.getVendorPatchLevel();
        break;
      default:
        KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Convert Integer to Text String for OS_VERSION.
    if (bootParam == OS_VERSION_ID) {
      value = converIntegerToTextString(value, scratchPad);
    }
    return value;
  }
  //----------------------------------------------------------------------------

  //----------------------------------------------------------------------------
  // ECDH HKDF
  private short ecdhHkdfDeriveKey(byte[] privKeyA, short privKeyAOff, short privKeyALen,
      byte[] pubKeyA,
      short pubKeyAOff, short pubKeyALen, byte[] pubKeyB, short pubKeyBOff,
      short pubKeyBLen, byte[] scratchPad) {
    short key =
        seProvider.ecdhKeyAgreement(privKeyA, privKeyAOff, privKeyALen, pubKeyB, pubKeyBOff,
            pubKeyBLen, scratchPad, (short) 0);
    key = KMByteBlob.instance(scratchPad, (short) 0, key);

    // ignore 0x04 for ephemerical public key as kdfContext should not include 0x04.
    pubKeyAOff += 1;
    pubKeyALen -= 1;
    pubKeyBOff += 1;
    pubKeyBLen -= 1;
    short kdfContext =
        KMCose.constructKdfContext(pubKeyA, pubKeyAOff, pubKeyALen, pubKeyB, pubKeyBOff, pubKeyBLen,
            true);
    kdfContext = KMKeymasterApplet
        .encodeToApduBuffer(kdfContext, scratchPad, (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    kdfContext = KMByteBlob.instance(scratchPad, (short) 0, kdfContext);

    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 32, (byte) 0);
    seProvider.hkdf(
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
    Util.arrayCopy(scratchPad, (short) 32, scratchPad, (short) 0, (short) 32);
    return (short) 32;
  }

  //----------------------------------------------------------------------------
  // This function returns the instance of private key and It stores the public key in the
  // data table for later usage.
  private short generateEphemeralEcKey(byte[] scratchPad) {
    // Generate ephemeral ec key.
    short[] lengths = {0/* Private key Length*/, 0 /* Public key length*/};
    seProvider.createAsymmetricKey(
        KMType.EC,
        scratchPad,
        (short) 0,
        (short) 128,
        scratchPad,
        (short) 128,
        (short) 128,
        lengths);
    // Copy the ephemeral private key from scratch pad
    short ptr = KMByteBlob.instance(lengths[0]);
    Util.arrayCopyNonAtomic(
        scratchPad,
        (short) 0,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        lengths[0]);
    //Store  ephemeral public key in data table for later usage.
    short dataEntryIndex = createEntry(EPHEMERAL_PUB_KEY, lengths[1]);
    Util.arrayCopyNonAtomic(scratchPad, (short) 128, data, dataEntryIndex, lengths[1]);
    return ptr;
  }

  private void initHmacOperation() {
    short dataEntryIndex = getEntry(EPHEMERAL_MAC_KEY);
    operation[0] =
        seProvider.getRkpOperation(
            KMType.SIGN,
            KMType.HMAC,
            KMType.SHA2_256,
            KMType.PADDING_NONE,
            (byte) 0,
            data,
            dataEntryIndex,
            getEntryLength(EPHEMERAL_MAC_KEY),
            null,
            (short) 0,
            (short) 0,
            (short) 0
        );
    if (operation[0] == null) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
  }

  private void initAesGcmOperation(byte[] scratchPad, short nonce) {
    // Generate Ephemeral mac key
    short privKey = generateEphemeralEcKey(scratchPad);
    short pubKeyIndex = getEntry(EPHEMERAL_PUB_KEY);
    // Generate session key
    short eekIndex = getEntry(EEK_KEY);
    // Generate session key
    short sessionKeyLen =
        ecdhHkdfDeriveKey(
            KMByteBlob.cast(privKey).getBuffer(), /* Ephemeral Private Key */
            KMByteBlob.cast(privKey).getStartOff(),
            KMByteBlob.cast(privKey).length(),
            data,                /* Ephemeral Public key */
            pubKeyIndex,
            getEntryLength(EPHEMERAL_PUB_KEY),
            data,               /* EEK Public key */
            eekIndex,
            getEntryLength(EEK_KEY),
            scratchPad         /* scratchpad */
        );
    // Initialize the Cipher object.
    operation[0] =
        seProvider.getRkpOperation(
            KMType.ENCRYPT,
            KMType.AES,
            (byte) 0,
            KMType.PADDING_NONE,
            KMType.GCM,
            scratchPad, /* key */
            (short) 0,
            sessionKeyLen,
            KMByteBlob.cast(nonce).getBuffer(), /* nonce */
            KMByteBlob.cast(nonce).getStartOff(),
            KMByteBlob.cast(nonce).length(),
            (short) (KMKeymasterApplet.AES_GCM_AUTH_TAG_LENGTH * 8)
        );
    if (operation[0] == null) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
  }

  private short processRecipientStructure(byte[] scratchPad) {
    short protectedHeaderRecipient = KMCose.constructHeaders(
        KMNInteger.uint_8(KMCose.COSE_ALG_ECDH_ES_HKDF_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    protectedHeaderRecipient = KMKeymasterApplet
        .encodeToApduBuffer(protectedHeaderRecipient, scratchPad, (short) 0,
            KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    protectedHeaderRecipient = KMByteBlob.instance(scratchPad, (short) 0, protectedHeaderRecipient);

    /* Construct unprotected headers */
    short pubKeyIndex = getEntry(EPHEMERAL_PUB_KEY);
    // prepare cosekey
    short coseKey =
        KMCose.constructCoseKey(
            KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
            KMType.INVALID_VALUE,
            KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
            KMType.INVALID_VALUE,
            KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
            data,
            pubKeyIndex,
            getEntryLength(EPHEMERAL_PUB_KEY),
            KMType.INVALID_VALUE,
            false
        );
    short keyIdentifierPtr = KMByteBlob
        .instance(data, getEntry(EEK_KEY_ID), getEntryLength(EEK_KEY_ID));
    short unprotectedHeaderRecipient =
        KMCose.constructHeaders(KMType.INVALID_VALUE, keyIdentifierPtr, KMType.INVALID_VALUE,
            coseKey);

    // Construct recipients structure.
    return KMCose.constructRecipientsStructure(protectedHeaderRecipient, unprotectedHeaderRecipient,
        KMSimpleValue.instance(KMSimpleValue.NULL));
  }

  private short getAdditionalCertChainProcessedLength() {
    short dataEntryIndex = getEntry(ACC_PROCESSED_LENGTH);
    if (dataEntryIndex == 0) {
      dataEntryIndex = createEntry(ACC_PROCESSED_LENGTH, SHORT_SIZE);
      Util.setShort(data, dataEntryIndex, (short) 0);
      return (short) 0;
    }
    return Util.getShort(data, dataEntryIndex);
  }

  private void updateAdditionalCertChainProcessedLength(short processedLen) {
    short dataEntryIndex = getEntry(ACC_PROCESSED_LENGTH);
    Util.setShort(data, dataEntryIndex, processedLen);
  }

  private short processAdditionalCertificateChain(byte[] scratchPad) {
    byte[] persistedData = storeDataInst.getAdditionalCertChain();
    short totalAccLen = Util.getShort(persistedData, (short) 0);
    if (totalAccLen == 0) {
      // No Additional certificate chain present.
      return 0;
    }
    short processedLen = getAdditionalCertChainProcessedLength();
    short lengthToSend = (short) (totalAccLen - processedLen);
    if (lengthToSend > MAX_SEND_DATA) {
      lengthToSend = MAX_SEND_DATA;
    }
    short cipherTextLen =
        ((KMOperation) operation[0]).update(persistedData, (short) (2 + processedLen), lengthToSend,
            scratchPad, (short) 0);
    processedLen += lengthToSend;
    updateAdditionalCertChainProcessedLength(processedLen);
    // Update the output processing state.
    updateOutputProcessingState(
        (processedLen == totalAccLen) ? PROCESSING_ACC_COMPLETE : PROCESSING_ACC_IN_PROGRESS);
    return cipherTextLen;
  }

  // BCC for STRONGBOX has chain length of 2. So it can be returned in a single go.
  private short processBcc(byte[] scratchPad) {
    // Construct BCC
    boolean testMode = (TRUE == data[getEntry(TEST_MODE)]) ? true : false;
    short len;
    if (testMode) {
      short bcc = KMKeymasterApplet.generateBcc(true, scratchPad);
      len = KMKeymasterApplet
          .encodeToApduBuffer(bcc, scratchPad, (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    } else {
      byte[] bcc = storeDataInst.getBootCertificateChain();
      len = Util.getShort(bcc, (short) 0);
      Util.arrayCopyNonAtomic(bcc, (short) 2, scratchPad, (short) 0, len);
    }
    short cipherTextLen = ((KMOperation) operation[0])
        .update(scratchPad, (short) 0, len, scratchPad, len);
    // move cipher text on scratch pad from starting position.
    Util.arrayCopyNonAtomic(scratchPad, len, scratchPad, (short) 0, cipherTextLen);
    createEntry(RESPONSE_PROCESSING_STATE, BYTE_SIZE);
    // If there is no additional certificate chain present then put the state to
    // PROCESSING_ACC_COMPLETE.
    updateOutputProcessingState(
        isAdditionalCertificateChainPresent() ? PROCESSING_BCC_COMPLETE : PROCESSING_ACC_COMPLETE);
    return cipherTextLen;
  }

  // AAD is the CoseEncrypt structure
  private void processAesGcmUpdateAad(byte[] scratchPad) {
    short protectedHeader = KMCose.constructHeaders(
        KMInteger.uint_8(KMCose.COSE_ALG_AES_GCM_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    protectedHeader = KMKeymasterApplet.encodeToApduBuffer(protectedHeader, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, protectedHeader);
    short coseEncryptStr =
        KMCose.constructCoseEncryptStructure(protectedHeader, KMByteBlob.instance((short) 0));
    coseEncryptStr = KMKeymasterApplet.encodeToApduBuffer(coseEncryptStr, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    ((KMOperation) operation[0]).updateAAD(scratchPad, (short) 0, coseEncryptStr);
  }

  private short processSignedMac(byte[] scratchPad, short pubKeysToSignMac, short deviceInfo) {
    // Construct SignedMac
    KMDeviceUniqueKeyPair deviceUniqueKeyPair =
        createDeviceUniqueKeyPair((TRUE == data[getEntry(TEST_MODE)]) ? true : false, scratchPad);
    // Create signedMac
    short signedMac = createSignedMac(deviceUniqueKeyPair, scratchPad, deviceInfo, pubKeysToSignMac);
    //Prepare partial data for encryption.
    short arrLength = (short) (isAdditionalCertificateChainPresent() ? 3 : 2);
    short arr = KMArray.instance(arrLength);
    KMArray.cast(arr).add((short) 0, signedMac);
    KMArray.cast(arr).add((short) 1, KMType.INVALID_VALUE);
    if (arrLength == 3) {
      KMArray.cast(arr).add((short) 2, KMType.INVALID_VALUE);
    }
    short len = KMKeymasterApplet
        .encodeToApduBuffer(arr, scratchPad, (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    short cipherTextLen = ((KMOperation) operation[0])
        .update(scratchPad, (short) 0, len, scratchPad, len);
    Util.arrayCopyNonAtomic(
        scratchPad,
        len,
        scratchPad,
        (short) 0,
        cipherTextLen
    );
    return cipherTextLen;
  }

  private short getCoseEncryptProtectedHeader(byte[] scratchPad) {
    // CoseEncrypt protected headers.
    short protectedHeader = KMCose.constructHeaders(
        KMInteger.uint_8(KMCose.COSE_ALG_AES_GCM_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    protectedHeader = KMKeymasterApplet.encodeToApduBuffer(protectedHeader, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    return KMByteBlob.instance(scratchPad, (short) 0, protectedHeader);
  }

  private short getCoseEncryptUnprotectedHeader(byte[] scratchPad, short nonce) {
    /* CoseEncrypt unprotected headers */
    return KMCose
        .constructHeaders(KMType.INVALID_VALUE, KMType.INVALID_VALUE, nonce, KMType.INVALID_VALUE);
  }

  private short constructCoseMacForRkpKey(boolean testMode, byte[] scratchPad, short pubKey) {
    // prepare cosekey
    short coseKey =
        KMCose.constructCoseKey(
            KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
            KMType.INVALID_VALUE,
            KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
            KMType.INVALID_VALUE,
            KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
            KMByteBlob.cast(pubKey).getBuffer(),
            KMByteBlob.cast(pubKey).getStartOff(),
            KMByteBlob.cast(pubKey).length(),
            KMType.INVALID_VALUE,
            testMode);
    // Encode the cose key and make it as payload.
    short len = KMKeymasterApplet
        .encodeToApduBuffer(coseKey, scratchPad, (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    short payload = KMByteBlob.instance(scratchPad, (short) 0, len);
    // Prepare protected header, which is required to construct the COSE_MAC0
    short headerPtr = KMCose.constructHeaders(
        KMInteger.uint_8(KMCose.COSE_ALG_HMAC_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    len = KMKeymasterApplet
        .encodeToApduBuffer(headerPtr, scratchPad, (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    short protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, len);
    // create MAC_Structure
    short macStructure =
        KMCose.constructCoseMacStructure(protectedHeader, KMByteBlob.instance((short) 0), payload);
    // Encode the Mac_structure and do HMAC_Sign to produce the tag for COSE_MAC0
    len = KMKeymasterApplet.encodeToApduBuffer(macStructure, scratchPad, (short) 0,
        KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    // HMAC Sign.
    short hmacLen = rkpHmacSign(testMode, scratchPad, (short) 0, len, scratchPad, len);
    // Create COSE_MAC0 object
    short coseMac0 =
        KMCose
            .constructCoseMac0(protectedHeader, KMCoseHeaders.instance(KMArray.instance((short) 0)),
                payload,
                KMByteBlob.instance(scratchPad, len, hmacLen));
    len = KMKeymasterApplet
        .encodeToApduBuffer(coseMac0, scratchPad, (short) 0, KMKeymasterApplet.MAX_COSE_BUF_SIZE);
    return KMByteBlob.instance(scratchPad, (short) 0, len);
  }

  private short getEcAttestKeyParameters() {
    short tagIndex = 0;
    short arrPtr = KMArray.instance((short) 6);
    // Key size - 256
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 256));
    // Digest - SHA256
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    // Purpose - Attest
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ATTEST_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);

    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    // Algorithm - EC
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    // Curve - P256
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ECCURVE, KMType.P_256));
    // No Authentication is required to use this key.
    KMArray.cast(arrPtr).add(tagIndex, KMBoolTag.instance(KMType.NO_AUTH_REQUIRED));
    return KMKeyParameters.instance(arrPtr);
  }
  
  private boolean isSignedByte(byte b) {
    return ((b & 0x0080) != 0);
  }

  private short writeIntegerHeader(short valueLen, byte[] data, short offset) {
    // write length
    data[offset] = (byte) valueLen;
    // write INTEGER tag
    offset--;
    data[offset] = 0x02;
    return offset;
  }

  private short writeSequenceHeader(short valueLen, byte[] data, short offset) {
    // write length
    data[offset] = (byte) valueLen;
    // write INTEGER tag
    offset--;
    data[offset] = 0x30;
    return offset;
  }

  private short writeSignatureData(byte[] input, short inputOff, short inputlen, byte[] output, short offset) {
    Util.arrayCopyNonAtomic(input, inputOff, output, offset, inputlen);
    if (isSignedByte(input[inputOff])) {
      offset--;
      output[offset] = (byte) 0;
    }
    return offset;
  }

  public short encodeES256CoseSignSignature(byte[] input, short offset, short len, byte[] scratchPad, short scratchPadOff) {
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
  
  private short rkpHmacSign(boolean testMode, byte[] data, short dataStart, short dataLength, byte[] signature,
	      short signatureStart) {
	short result;  
    if(testMode) {
	  short macKey = KMByteBlob.instance(MAC_KEY_SIZE);
	  Util.arrayFillNonAtomic(KMByteBlob.cast(macKey).getBuffer(),
	        KMByteBlob.cast(macKey).getStartOff(), MAC_KEY_SIZE, (byte) 0);
	  result = seProvider.hmacSign(KMByteBlob.cast(macKey).getBuffer(), KMByteBlob.cast(macKey).getStartOff(), MAC_KEY_SIZE, data, dataStart, dataLength, signature, signatureStart);	    
	} else {
	  result = seProvider.hmacSign(storeDataInst.getRkpMacKey(), data, dataStart, dataLength, signature, signatureStart);
	}
    return result;
  }
  
}
