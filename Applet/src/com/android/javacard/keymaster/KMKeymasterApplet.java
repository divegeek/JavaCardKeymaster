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

package com.android.javacard.keymaster;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.apdu.ExtendedLength;

/**
 * KMKeymasterApplet implements the javacard applet. It creates repository and other install time
 * objects. It also implements the keymaster state machine and handles javacard applet life cycle
 * events.
 */
public class KMKeymasterApplet extends Applet implements AppletEvent, ExtendedLength {

  // Constants.
  public static final byte[] F4 = {0x01, 0x00, 0x01};
  public static final byte AES_BLOCK_SIZE = 16;
  public static final byte DES_BLOCK_SIZE = 8;
  public static final short MAX_LENGTH = 10000;
  public static final short MASTER_KEY_SIZE = 128;
  public static final short WRAPPING_KEY_SIZE = 32;
  public static final short MAX_OPERATIONS_COUNT = 4;
  public static final short VERIFIED_BOOT_KEY_SIZE = 32;
  public static final short VERIFIED_BOOT_HASH_SIZE = 32;
  public static final short BOOT_PATCH_LVL_SIZE = 4;

  protected static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
  protected static final short KM_HAL_VERSION = (short) 0x5000;
  private static final short MAX_AUTH_DATA_SIZE = (short) 512;
  private static final short DERIVE_KEY_INPUT_SIZE = (short) 256;

  // Subject is a fixed field with only CN= Android Keystore Key - same for all the keys
  private static final byte[] defaultSubject = {
      0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e,
      0x64,
      0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B,
      0x65,
      0x79
  };

  private static final byte[] dec319999Ms ={(byte)0, (byte)0, (byte)0xE6, (byte)0x77,
      (byte)0xD2, (byte)0x1F, (byte)0xD8, (byte)0x18};

  private static final byte[] dec319999 = {
      0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
      0x39, 0x35, 0x39, 0x5a,
  };

  private static final byte[] jan01970 = {
      0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x5a,
  };

  // "Keymaster HMAC Verification" - used for HMAC key verification.
  public static final byte[] sharingCheck = {
      0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x48, 0x4D, 0x41, 0x43, 0x20,
      0x56,
      0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E
  };

  // "KeymasterSharedMac"
  public static final byte[] ckdfLable = {
      0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64,
      0x4D,
      0x61, 0x63
  };

  // "Auth Verification"
  public static final byte[] authVerification = {
      0x41, 0x75, 0x74, 0x68, 0x20, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
      0x6F,
      0x6E
  };



  // Top 32 commands are reserved for provisioning.
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
  private static final byte INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23;
  private static final byte INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24;
  private static final byte INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25;
  private static final byte INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26;
  private static final byte KEYMINT_CMD_APDU_END = KEYMINT_CMD_APDU_START + 27;

  private static final byte INS_END_KM_CMD = 0x7F;

  // Data Dictionary items
  public static final byte DATA_ARRAY_SIZE = 40;
  public static final byte TMP_VARIABLE_ARRAY_SIZE = 5;

  public static final byte KEY_PARAMETERS = 0;
  public static final byte KEY_CHARACTERISTICS = 1;
  public static final byte HIDDEN_PARAMETERS = 2;
  public static final byte HW_PARAMETERS = 3;
  public static final byte SW_PARAMETERS = 4;
  public static final byte AUTH_DATA = 5;
  public static final byte AUTH_TAG = 6;
  public static final byte NONCE = 7;
  public static final byte KEY_BLOB = 8;
  public static final byte AUTH_DATA_LENGTH = 9;
  public static final byte SECRET = 10;
  public static final byte ROT = 11;
  public static final byte DERIVED_KEY = 12;
  public static final byte RSA_PUB_EXPONENT = 13;
  public static final byte APP_ID = 14;
  public static final byte APP_DATA = 15;
  public static final byte PUB_KEY = 16;
  public static final byte IMPORTED_KEY_BLOB = 17;
  public static final byte ORIGIN = 18;
  public static final byte NOT_USED = 19;
  public static final byte MASKING_KEY = 20;
  public static final byte HMAC_SHARING_PARAMS = 21;
  public static final byte OP_HANDLE = 22;
  public static final byte IV = 23;
  public static final byte INPUT_DATA = 24;
  public static final byte OUTPUT_DATA = 25;
  public static final byte HW_TOKEN = 26;
  public static final byte VERIFICATION_TOKEN = 27;
  public static final byte SIGNATURE = 28;
  public static final byte ATTEST_KEY_BLOB = 29;
  public static final byte ATTEST_KEY_PARAMS = 30;
  public static final byte ATTEST_KEY_ISSUER = 31;
  public static final byte CERTIFICATE = 32;
  public static final byte PLAIN_SECRET = 33;
  public static final byte TEE_PARAMETERS = 34;
  public static final byte SB_PARAMETERS = 35;
  // Constant

  // AddRngEntropy
  protected static final short MAX_SEED_SIZE = 2048;

  // Keyblob constants
  public static final byte KEY_BLOB_SECRET = 0;
  public static final byte KEY_BLOB_NONCE = 1;
  public static final byte KEY_BLOB_AUTH_TAG = 2;
  public static final byte KEY_BLOB_PARAMS = 3;
  public static final byte KEY_BLOB_PUB_KEY = 4;
  // AES GCM constants
  private static final byte AES_GCM_AUTH_TAG_LENGTH = 16;
  private static final byte AES_GCM_NONCE_LENGTH = 12;
  // ComputeHMAC constants
  private static final short HMAC_SHARED_PARAM_MAX_SIZE = 64;
  protected static final short MAX_CERT_SIZE = 2048;

  protected static KMEncoder encoder;
  protected static KMDecoder decoder;
  protected static KMRepository repository;
  protected static KMSEProvider seProvider;
  protected static KMOperationState[] opTable;

  protected static short[] tmpVariables;
  protected static short[] data;
  protected static byte[] wrappingKey;

  /**
   * Registers this applet.
   */
  protected KMKeymasterApplet(KMSEProvider seImpl) {
    seProvider = seImpl;
    boolean isUpgrading = seProvider.isUpgrading();
    if (!isUpgrading) {
      seProvider.createMasterKey(MASTER_KEY_SIZE);
    }
    repository = new KMRepository(isUpgrading);
    encoder = new KMEncoder();
    decoder = new KMDecoder();
    data = JCSystem.makeTransientShortArray(DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_DESELECT);
    tmpVariables =
        JCSystem.makeTransientShortArray(TMP_VARIABLE_ARRAY_SIZE, JCSystem.CLEAR_ON_DESELECT);
    wrappingKey = JCSystem.makeTransientByteArray((short)(WRAPPING_KEY_SIZE+1), JCSystem.CLEAR_ON_RESET);
    resetWrappingKey();
    opTable = new KMOperationState[MAX_OPERATIONS_COUNT];
    short index = 0;
    while(index < MAX_OPERATIONS_COUNT){
      opTable[index] = new KMOperationState();
      index++;
    }
    KMType.initialize();

    // initialize default values
    initHmacNonceAndSeed();
    initSystemBootParams((short)0,(short)0,(short)0,(short)0);
  }

  protected void initHmacNonceAndSeed(){
    short nonce = repository.alloc((short)32);
    seProvider.newRandomNumber(repository.getHeap(), nonce, KMRepository.HMAC_SEED_NONCE_SIZE);
    repository.initHmacNonce(repository.getHeap(), nonce, KMRepository.HMAC_SEED_NONCE_SIZE);
  }

  private void releaseAllOperations(){
    short index = 0;
    while(index < MAX_OPERATIONS_COUNT) {
      opTable[index].reset();
      index++;
    }
  }

  private KMOperationState reserveOperation(short algorithm, short opHandle){
    short index = 0;
    while(index < MAX_OPERATIONS_COUNT) {
      if (opTable[index].getAlgorithm() == KMType.INVALID_VALUE) {
        opTable[index].setAlgorithm(algorithm);
        opTable[index].setHandle(KMInteger.cast(opHandle).getBuffer(),
            KMInteger.cast(opHandle).getStartOff(),
            KMInteger.cast(opHandle).length());
        return opTable[index];
      }
      index++;
    }
    return null;
  }

  private KMOperationState findOperation(short handle){
    return findOperation(KMInteger.cast(handle).getBuffer(),
        KMInteger.cast(handle).getStartOff(),
        KMInteger.cast(handle).length());
  }

  private KMOperationState findOperation(byte[] opHandle, short start, short len){
    short index = 0;
    while(index < MAX_OPERATIONS_COUNT) {
      if(opTable[index].compare(opHandle, start, len) == 0){
        if(opTable[index].getAlgorithm() != KMType.INVALID_VALUE) {
          return opTable[index];
        }
      }
      index++;
    }
    return null;
  }

  private void releaseOperation(KMOperationState op){
    op.reset();
  }
  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
    repository.onSelect();
    return true;
  }

  /**
   * De-selects this applet.
   */
  @Override
  public void deselect() {
    repository.onDeselect();
  }

  /**
   * Uninstalls the applet after cleaning the repository.
   */
  @Override
  public void uninstall() {
    repository.onUninstall();
  }

  private short mapISOErrorToKMError(short reason) {
    switch (reason) {
      case ISO7816.SW_CLA_NOT_SUPPORTED:
        return KMError.UNSUPPORTED_CLA;
      case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
        return KMError.SW_CONDITIONS_NOT_SATISFIED;
      case ISO7816.SW_COMMAND_NOT_ALLOWED:
        return KMError.CMD_NOT_ALLOWED;
      case ISO7816.SW_DATA_INVALID:
        return KMError.INVALID_DATA;
      case ISO7816.SW_INCORRECT_P1P2:
        return KMError.INVALID_P1P2;
      case ISO7816.SW_INS_NOT_SUPPORTED:
        return KMError.UNSUPPORTED_INSTRUCTION;
      case ISO7816.SW_WRONG_LENGTH:
        return KMError.SW_WRONG_LENGTH;
      case ISO7816.SW_UNKNOWN:
      default:
//        return KMError.UNKNOWN_ERROR;
        return KMError.INVALID_NONCE;
    }
  }

  private short mapCryptoErrorToKMError(short reason) {
    switch (reason) {
      case CryptoException.ILLEGAL_USE:
        return KMError.CRYPTO_ILLEGAL_USE;
      case CryptoException.ILLEGAL_VALUE:
        return KMError.CRYPTO_ILLEGAL_VALUE;
      case CryptoException.INVALID_INIT:
        return KMError.CRYPTO_INVALID_INIT;
      case CryptoException.NO_SUCH_ALGORITHM:
        return KMError.CRYPTO_NO_SUCH_ALGORITHM;
      case CryptoException.UNINITIALIZED_KEY:
        return KMError.CRYPTO_UNINITIALIZED_KEY;
      default:
 //       return KMError.UNKNOWN_ERROR;
        return KMError.INVALID_NONCE;
    }
  }

  protected short validateApduHeader(APDU apdu) {
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
    // Validate APDU Header.
    if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    // Validate P1P2.
    if (P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    byte apduIns = apduBuffer[ISO7816.OFFSET_INS];
    // Validate whether INS can be supported
    if (!(apduIns > KEYMINT_CMD_APDU_START && apduIns < KEYMINT_CMD_APDU_END)) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    return apduIns;
  }

  /**
   * Processes an incoming APDU and handles it using command objects.
   * @param apdu the incoming APDU
   */
  @Override
  public void process(APDU apdu) {
    try {
      repository.onProcess();
      // If this is select applet apdu which is selecting this applet then return
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      // Validate APDU Header.
      short apduIns = validateApduHeader(apdu);
        switch (apduIns) {
          case INS_INIT_STRONGBOX_CMD:
            processInitStrongBoxCmd(apdu);
            sendError(apdu, KMError.OK);
            return;
          case INS_GENERATE_KEY_CMD:
            processGenerateKey(apdu);
            break;
          case INS_IMPORT_KEY_CMD:
            processImportKeyCmd(apdu);
            break;
          case INS_BEGIN_IMPORT_WRAPPED_KEY_CMD:
            processBeginImportWrappedKeyCmd(apdu);
            break;
          case INS_FINISH_IMPORT_WRAPPED_KEY_CMD:
            processFinishImportWrappedKeyCmd(apdu);
            break;
          case INS_EXPORT_KEY_CMD:
            processExportKeyCmd(apdu);
            break;
          case INS_UPGRADE_KEY_CMD:
            processUpgradeKeyCmd(apdu);
            break;
          case INS_DELETE_KEY_CMD:
            processDeleteKeyCmd(apdu);
            break;
          case INS_DELETE_ALL_KEYS_CMD:
            processDeleteAllKeysCmd(apdu);
            break;
          case INS_ADD_RNG_ENTROPY_CMD:
            processAddRngEntropyCmd(apdu);
            break;
          case INS_COMPUTE_SHARED_HMAC_CMD:
            processComputeSharedHmacCmd(apdu);
            break;
          case INS_DESTROY_ATT_IDS_CMD:
            processDestroyAttIdsCmd(apdu);
            break;
          case INS_VERIFY_AUTHORIZATION_CMD:
            processVerifyAuthorizationCmd(apdu);
            break;
          case INS_GET_HMAC_SHARING_PARAM_CMD:
            processGetHmacSharingParamCmd(apdu);
            break;
          case INS_GET_KEY_CHARACTERISTICS_CMD:
            processGetKeyCharacteristicsCmd(apdu);
            break;
          case INS_GET_HW_INFO_CMD:
            processGetHwInfoCmd(apdu);
            break;
          case INS_BEGIN_OPERATION_CMD:
            processBeginOperationCmd(apdu);
            break;
          case INS_UPDATE_OPERATION_CMD:
            processUpdateOperationCmd(apdu);
            break;
          case INS_FINISH_OPERATION_CMD:
            processFinishOperationCmd(apdu);
            break;
          case INS_ABORT_OPERATION_CMD:
            processAbortOperationCmd(apdu);
            break;
          case INS_DEVICE_LOCKED_CMD:
            processDeviceLockedCmd(apdu);
            break;
          case INS_EARLY_BOOT_ENDED_CMD:
            processEarlyBootEndedCmd(apdu);
            break;
          case INS_UPDATE_AAD_OPERATION_CMD:
            processUpdateAadOperationCmd(apdu);
            break;
          default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    } catch (KMException exception) {
      freeOperations();
      resetWrappingKey();
      sendError(apdu, KMException.reason());
    } catch (ISOException exp) {
  //    sendError(apdu, mapISOErrorToKMError(exp.getReason()));
      freeOperations();
      resetWrappingKey();
      sendError(apdu, mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      freeOperations();
      resetWrappingKey();
      sendError(apdu, mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
//      sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
      freeOperations();
      resetWrappingKey();
      sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      resetData();
      repository.clean();
    }
  }

  private void generateUniqueOperationHandle(byte[] buf, short offset, short len) {
    do {
      seProvider.newRandomNumber(buf, offset, len);
    } while (null != findOperation(buf, offset, len));
  }

  private void freeOperations() {
    if (data[OP_HANDLE] != KMType.INVALID_VALUE) {
      KMOperationState op = findOperation(data[OP_HANDLE]);
      if (op != null) {
        releaseOperation(op);
      }
    }
  }

  private void processEarlyBootEndedCmd(APDU apdu) {
    KMException.throwIt(KMError.UNIMPLEMENTED);
  }

  private short deviceLockedCmd(APDU apdu){
    short cmd = KMArray.instance((short) 2);
    // passwordOnly
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());
    // verification token
    KMArray.cast(cmd).add((short) 1, KMVerificationToken.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processDeviceLockedCmd(APDU apdu) {
    short cmd = deviceLockedCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    short passwordOnly = KMArray.cast(cmd).get((short) 0);
    short verToken = KMArray.cast(cmd).get((short) 1);
    passwordOnly = KMInteger.cast(passwordOnly).getByte();
    validateVerificationToken(verToken, scratchPad);
    short verTime = KMVerificationToken.cast(verToken).getTimestamp();
    short lastDeviceLockedTime = repository.getDeviceTimeStamp();
    if (KMInteger.compare(verTime, lastDeviceLockedTime) > 0) {
      Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
      KMInteger.cast(verTime).getValue(scratchPad, (short) 0, (short) 8);
      repository.setDeviceLock(true);
      repository.setDeviceLockPasswordOnly(passwordOnly == 0x01);
      repository.setDeviceLockTimestamp(scratchPad, (short) 0, (short) 8);
    }
    sendError(apdu, KMError.OK);
  }

  private void resetWrappingKey(){
    if(!isValidWrappingKey()) return;
    Util.arrayFillNonAtomic(wrappingKey,(short) 1, WRAPPING_KEY_SIZE, (byte) 0);
    wrappingKey[0] = -1;
  }

  private boolean isValidWrappingKey(){
    return wrappingKey[0] != -1;
  }

  private void setWrappingKey(short key){
    if(KMByteBlob.cast(key).length() != WRAPPING_KEY_SIZE){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    wrappingKey[0] = 0;
    Util.arrayCopyNonAtomic(KMByteBlob.cast(key).getBuffer(),
        KMByteBlob.cast(key).getStartOff(),wrappingKey,(short)1,WRAPPING_KEY_SIZE);
  }

  private short getWrappingKey(){
    return KMByteBlob.instance(wrappingKey,(short)1,WRAPPING_KEY_SIZE);
  }

  private void resetData() {
    short index = 0;
    while (index < data.length) {
      data[index] = KMType.INVALID_VALUE;
      index++;
    }
    index = 0;
    while (index < tmpVariables.length) {
      tmpVariables[index] = KMType.INVALID_VALUE;
      index++;
    }
  }

  /**
   * Sends a response, may be extended response, as requested by the command.
   */
  public static void sendOutgoing(APDU apdu, short resp) {
    //TODO handle the extended buffer stuff. We can reuse this.
    short bufferStartOffset = repository.allocAvailableMemory();
    byte[] buffer = repository.getHeap();
    // TODO we can change the following to incremental send.
    short bufferLength = encoder.encode(resp, buffer, bufferStartOffset);
    if (((short) (bufferLength + bufferStartOffset)) > ((short) repository
        .getHeap().length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Send data
    apdu.setOutgoing();
    apdu.setOutgoingLength(bufferLength);
    apdu.sendBytesLong(buffer, bufferStartOffset, bufferLength);
  }

  /**
   * Receives data, which can be extended data, as requested by the command instance.
   */
  public static short receiveIncoming(APDU apdu, short reqExp) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    // TODO add logic to handle the extended length buffer. In this case the memory can be reused
    //  from extended buffer.
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = repository.allocReclaimableMemory(bufferLength);
    short index = bufferStartOffset;
    byte[] buffer = repository.getHeap();
    while (recvLen > 0 && ((short) (index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    short req = decoder.decode(reqExp,buffer, bufferStartOffset, bufferLength);
    repository.reclaimMemory(bufferLength);
    return req;
  }

  private void processGetHwInfoCmd(APDU apdu) {
    // No arguments expected
    final byte version = 1;
    final byte[] JavacardKeymintDevice = {
        0x4a,0x61,0x76,0x61,0x63,0x61,0x72,0x64,
        0x4b,0x65,0x79,0x6d,0x69,0x6e,0x74,
        0x44,0x65,0x76,0x69,0x63,0x65,
    };
    final byte[] Google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
    // Make the response
    short respPtr = KMArray.instance((short) 6);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMInteger.uint_16(KMError.OK));
    resp.add((short) 1, KMInteger.uint_8(version));
    resp.add((short) 2, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 3,
        KMByteBlob.instance(
            JavacardKeymintDevice, (short) 0, (short) JavacardKeymintDevice.length));
    resp.add((short) 4, KMByteBlob.instance(Google, (short) 0, (short) Google.length));
    resp.add((short)5, KMInteger.uint_8((byte)1));
    // send buffer to master
    sendOutgoing(apdu, respPtr);
  }

  private short addRngEntropyCmd(APDU apdu){
    short cmd = KMArray.instance((short) 1);
    // Rng entropy
    KMArray.cast(cmd).add((short) 0, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processAddRngEntropyCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    short cmd = addRngEntropyCmd(apdu);
    // Process
    KMByteBlob blob = KMByteBlob.cast(KMArray.cast(cmd).get((short) 0));
    // Maximum 2KiB of seed is allowed.
    if (blob.length() > MAX_SEED_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    seProvider.addRngEntropy(blob.getBuffer(), blob.getStartOff(), blob.length());
    sendError(apdu, KMError.OK);
  }

  private short getKeyCharacteristicsCmd(APDU apdu){
    short cmd = KMArray.instance((short) 3);
    KMArray.cast(cmd).add((short) 0, KMByteBlob.exp());
    KMArray.cast(cmd).add((short) 1, KMByteBlob.exp());
    KMArray.cast(cmd).add((short) 2, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processGetKeyCharacteristicsCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    short cmd = getKeyCharacteristicsCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_BLOB] = KMArray.cast(cmd).get((short) 0);
    data[APP_ID] = KMArray.cast(cmd).get((short) 1);
    data[APP_DATA] = KMArray.cast(cmd).get((short) 2);
    if (!KMByteBlob.cast(data[APP_ID]).isValid()) {
      data[APP_ID] = KMType.INVALID_VALUE;
    }
    if (!KMByteBlob.cast(data[APP_DATA]).isValid()) {
      data[APP_DATA] = KMType.INVALID_VALUE;
    }
    // Parse Key Blob
    parseEncryptedKeyBlob(data[KEY_BLOB],data[APP_ID], data[APP_DATA], scratchPad);
    // Check Version and Patch Level
    checkVersionAndPatchLevel(scratchPad);
    // make response.
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, data[KEY_CHARACTERISTICS]);
    sendOutgoing(apdu, resp);
  }

  private void processGetHmacSharingParamCmd(APDU apdu) {
    // No Arguments
    // Create HMAC Sharing Parameters
    short params = KMHmacSharingParameters.instance();
    short nonce = repository.getHmacNonce();
    short seed = KMByteBlob.instance((short) 0);
    KMHmacSharingParameters.cast(params).setNonce(nonce);
    KMHmacSharingParameters.cast(params).setSeed(seed);
    print(KMByteBlob.cast(nonce).getBuffer(), KMByteBlob.cast(nonce).getStartOff(),
        KMByteBlob.cast(nonce).length());
    // prepare the response
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, params);
    sendOutgoing(apdu, resp);
  }

  private void processDeleteAllKeysCmd(APDU apdu) {
    // No arguments
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private short deleteKeyCmd(APDU apdu){
    short cmd = KMArray.instance((short) 1);
    KMArray.cast(cmd).add((short) 0, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private short keyBlob(){
    short keyBlob = KMArray.instance((short) 5);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    short keyChar = KMKeyCharacteristics.exp();
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_PARAMS, keyChar);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    return keyBlob;
  }

  private void processDeleteKeyCmd(APDU apdu) {
    short cmd = deleteKeyCmd(apdu);
    data[KEY_BLOB] = KMArray.cast(cmd).get((short) 0);
    try {
      data[KEY_BLOB] = decoder.decodeArray(keyBlob(),
          KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
          KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
          KMByteBlob.cast(data[KEY_BLOB]).length());
    } catch (ISOException e) {
      // As per VTS, deleteKey should return KMError.OK but in case if
      // input is empty then VTS accepts UNIMPLEMENTED errorCode as well.
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    if (KMArray.cast(data[KEY_BLOB]).length() < 4) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private short computeSharedHmacCmd(APDU apdu){
    short params = KMHmacSharingParameters.exp();
    short paramsVec = KMArray.exp(params);
    short cmd = KMArray.instance((short) 1);
    KMArray.cast(cmd).add((short) 0, paramsVec);
    return receiveIncoming(apdu, cmd);
  }

  private void processComputeSharedHmacCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = computeSharedHmacCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[HMAC_SHARING_PARAMS] = KMArray.cast(cmd).get((short) 0);
    // Concatenate HMAC Params
    //tmpVariables[0]
    short paramsLen = KMArray.cast(data[HMAC_SHARING_PARAMS]).length(); // total number of params
    //tmpVariables[1]
    short concateBuffer = repository.alloc((short) (paramsLen * HMAC_SHARED_PARAM_MAX_SIZE));
    //tmpVariables[2]
    short paramIndex = 0; // index for params
    //tmpVariables[3]
    short bufferIndex = 0; // index for concatenation buffer
    // To check if nonce created by Strongbox is found. This value becomes 1 if both
    // seed and nonce created here are found in hmac sharing parameters received.
    //tmpVariables[7] = 0;
    short found = 0;
    //tmpVariables[9]
    short nonce = repository.getHmacNonce();
    print(KMByteBlob.cast(nonce).getBuffer(),
        KMByteBlob.cast(nonce).getStartOff(),
        KMByteBlob.cast(nonce).length());

    while (paramIndex < paramsLen) {
      // read HmacSharingParam
      //tmpVariables[4]
      short param = KMArray.cast(data[HMAC_SHARING_PARAMS]).get(paramIndex);
      // get seed - 32 bytes max
      //tmpVariables[5]
      short seed  = KMHmacSharingParameters.cast(param).getSeed();
      //tmpVariables[6]
      short seedLength = KMByteBlob.cast(seed).length();
      // if seed is present
      if (seedLength != 0) {
        // then copy that to concatenation buffer
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(seed).getBuffer(),
            KMByteBlob.cast(seed).getStartOff(),
            repository.getHeap(),
            (short) (concateBuffer + bufferIndex), // concat index
            seedLength);
        bufferIndex += seedLength; // increment the concat index
      } else if (found == 0) {
        found = 1; // Applet does not have any seed. Potentially
      }
      // if nonce is present get nonce - 32 bytes
      //tmpVariables[5]
      short paramNonce = KMHmacSharingParameters.cast(param).getNonce();
      short nonceLen = KMByteBlob.cast(paramNonce).length();
      // if nonce is less then 32 - it is an error
      if (nonceLen < 32) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      // copy nonce to concatenation buffer
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(paramNonce).getBuffer(),
          KMByteBlob.cast(paramNonce).getStartOff(),
          repository.getHeap(),
          (short) (concateBuffer + bufferIndex), // index
          nonceLen);

      // Check if the nonce generated here is present in the hmacSharingParameters array.
      // Otherwise throw INVALID_ARGUMENT error.
      if (found == 1) {
        print(repository.getHeap(),
            (short) (concateBuffer + bufferIndex),nonceLen);
        print(KMByteBlob.cast(nonce).getBuffer(),
            KMByteBlob.cast(nonce).getStartOff(),
            nonceLen);
        if (0
            == Util.arrayCompare(
            repository.getHeap(),
            (short) (concateBuffer + bufferIndex),
            KMByteBlob.cast(nonce).getBuffer(),
            KMByteBlob.cast(nonce).getStartOff(),
            nonceLen)) {
          found = 2; // hmac nonce for this keymaster found.
        } else {
          found = 0;
        }
      }
      bufferIndex += nonceLen; // increment by nonce length
      paramIndex++; // go to next hmac param in the vector
    }
    if (found != 2) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // generate the key and store it in scratch pad - 32 bytes
    //tmpVariables[6]
    short keyLen =
        seProvider.cmacKDF(
            seProvider.getPresharedKey(),
            ckdfLable,
            (short) 0,
            (short) ckdfLable.length,
            repository.getHeap(),
            concateBuffer,
            bufferIndex,
            scratchPad,
            (short) 0);
    // persist the computed hmac key.
    repository.initComputedHmac(scratchPad, (short) 0, keyLen);

    // Generate sharingKey verification signature and store that in scratch pad.
    //tmpVariables[5]
    short signLen =
        seProvider.hmacSign(
            scratchPad,
            (short) 0,
            keyLen,
            sharingCheck,
            (short) 0,
            (short) sharingCheck.length,
            scratchPad,
            keyLen);
    // verification signature blob - 32 bytes
    //tmpVariables[1]
    short signature = KMByteBlob.instance(scratchPad, keyLen, signLen);
    // prepare the response
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, signature);
    sendOutgoing(apdu, resp);
  }

  private short upgradeKeyCmd(APDU apdu){
    short cmd = KMArray.instance((short) 2);
    short keyParams = KMKeyParameters.exp();
    KMArray.cast(cmd).add((short) 0, KMByteBlob.exp()); // Key Blob
    KMArray.cast(cmd).add((short) 1, keyParams); // Key Params
    return receiveIncoming(apdu, cmd);
  }

  private void processUpgradeKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = upgradeKeyCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();

    data[KEY_BLOB] = KMArray.cast(cmd).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(cmd).get((short) 1);
    //tmpVariables[0]
    short appId    =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    if (appId != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(appId).getValue();
    }
    short appData =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (appData != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(appData).getValue();
    }
    // parse existing key blob
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    // validate characteristics to be upgraded.
    short osVersion =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_VERSION, data[HW_PARAMETERS]);
    osVersion = KMIntegerTag.cast(osVersion).getValue();
    short osPatchLvl =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    osPatchLvl = KMIntegerTag.cast(osPatchLvl).getValue();
    short provOsVersion = repository.getOsVersion();
    short provOsPatch = repository.getOsPatch();
    short zero = KMInteger.uint_8((byte) 0);
    short error = KMError.OK;
    if (osVersion != KMType.INVALID_VALUE) {
      // os version in key characteristics must be less the os version stored in javacard or the
      // stored version must be zero. Then only upgrade is allowed else it is invalid argument.
      if (KMInteger.compare(osVersion, provOsVersion) != -1
          && KMInteger.compare(provOsVersion, zero) != 0) {
        // Key Should not be upgraded, but error code should be OK, As per VTS.
        error = KMError.INVALID_ARGUMENT;
      }
    }
    if (osPatchLvl != KMType.INVALID_VALUE) {
      // The key characteristics should have had os patch level < os patch level stored in javacard
      // then only upgrade is allowed.
      if (KMInteger.compare(osPatchLvl, provOsPatch) != -1) {
        // Key Should not be upgraded, but error code should be OK, As per VTS.
        error = KMError.INVALID_ARGUMENT;
      }
    }

    //Compare vendor patch levels
    short vendorPatchLvl =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.VENDOR_PATCH_LEVEL, data[HW_PARAMETERS]);
    vendorPatchLvl = KMIntegerTag.cast(vendorPatchLvl).getValue();
    short provVendorPatch = repository.getVendorPatchLevel();
    if (vendorPatchLvl != KMType.INVALID_VALUE) {
      // The key characteristics should have had vendor patch level < vendor patch level stored in javacard
      // then only upgrade is allowed.
      if (KMInteger.compare(vendorPatchLvl, provVendorPatch) != -1) {
        // Key Should not be upgraded, but error code should be OK, As per VTS.
        error = KMError.INVALID_ARGUMENT;
      }
    }

    //Compare boot patch levels
    short bootPatch =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.BOOT_PATCH_LEVEL, data[HW_PARAMETERS]);
    bootPatch = KMIntegerTag.cast(bootPatch).getValue();
    short provBootPatch = getBootPatchLevel(scratchPad);
    if (bootPatch != KMType.INVALID_VALUE) {
      // The key characteristics should have had boot patch level < boot patch level stored in javacard
      // then only upgrade is allowed.
      if (KMInteger.compare(bootPatch, provBootPatch) != -1) {
        // Key Should not be upgraded, but error code should be OK, As per VTS.
        error = KMError.INVALID_ARGUMENT;
      }
    }

    if (error != KMError.INVALID_ARGUMENT) {
      // copy origin
      data[ORIGIN] = KMEnumTag.getValue(KMType.ORIGIN, data[HW_PARAMETERS]);
      makeKeyCharacteristics(scratchPad);
      // create new key blob with current os version etc.
      createEncryptedKeyBlob(scratchPad);
    } else {
      data[KEY_BLOB] = KMByteBlob.instance((short) 0);
    }
    // prepare the response
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, data[KEY_BLOB]);
    sendOutgoing(apdu, resp);
  }

  private void processExportKeyCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }
  private void processWrappingKeyBlob(short keyBlob, short wrapParams, byte[] scratchPad) {
    // Read App Id and App Data if any from un wrapping key params
    short appId =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, wrapParams);
    short appData =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, wrapParams);
    if (appId != KMTag.INVALID_VALUE) {
      appId = KMByteTag.cast(appId).getValue();
    }
    if (appData != KMTag.INVALID_VALUE) {
      appData = KMByteTag.cast(appData).getValue();
    }
    data[APP_ID] = appId;
    data[APP_DATA] = appData;
    data[KEY_PARAMETERS] = wrapParams;
    data[KEY_BLOB] = keyBlob;
    // parse the wrapping key blob
    parseEncryptedKeyBlob(keyBlob, appId, appData, scratchPad);
    validateWrappingKeyBlob();
  }

  private void validateWrappingKeyBlob(){
    // check whether the wrapping key is RSA with purpose KEY_WRAP, padding RSA_OAEP and Digest
    // SHA2_256.
    KMTag.assertPresence(data[SB_PARAMETERS],KMType.ENUM_TAG, KMType.ALGORITHM, KMError.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
    if (KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]) != KMType.RSA) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
    }
    if (!KMEnumArrayTag.contains(KMType.DIGEST, KMType.SHA2_256, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    if (!KMEnumArrayTag.contains(KMType.PADDING, KMType.RSA_OAEP, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    if (!KMEnumArrayTag.contains(KMType.PURPOSE, KMType.WRAP_KEY, data[HW_PARAMETERS])) {
      KMException.throwIt((KMError.INCOMPATIBLE_PURPOSE));
    }
  }

  private short decryptTransportKey(short privExp, short modulus, short transportKey, byte[] scratchPad){
    short length  =
        seProvider.rsaDecipherOAEP256(
            KMByteBlob.cast(privExp).getBuffer(),
            KMByteBlob.cast(privExp).getStartOff(),
            KMByteBlob.cast(privExp).length(),
            KMByteBlob.cast(modulus).getBuffer(),
            KMByteBlob.cast(modulus).getStartOff(),
            KMByteBlob.cast(modulus).length(),
            KMByteBlob.cast(transportKey).getBuffer(),
            KMByteBlob.cast(transportKey).getStartOff(),
            KMByteBlob.cast(transportKey).length(),
            scratchPad,
            (short) 0);
    return KMByteBlob.instance(scratchPad, (short) 0, length);

  }

  private void unmask(short data, short maskingKey){
    short dataLength = KMByteBlob.cast(data).length();
    short maskLength = KMByteBlob.cast(maskingKey).length();
    // Length of masking key and transport key must be same.
    if (maskLength != dataLength) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    short index = 0; // index
    // Xor every byte of masking and key and store the result in data[SECRET]
    while (index < maskLength) {
      short var1 =
          (short) (((short) KMByteBlob.cast(maskingKey).get(index)) & 0x00FF);
      short var2 =
          (short) (((short) KMByteBlob.cast(data).get(index)) & 0x00FF);
      KMByteBlob.cast(data).add(index, (byte) (var1 ^ var2));
      index++;
    }
  }
  private short beginImportWrappedKeyCmd(APDU apdu){
    short cmd = KMArray.instance((short) 4);
    short params = KMKeyParameters.expAny();
    KMArray.cast(cmd).add((short) 0, KMByteBlob.exp()); // Encrypted Transport Key
    KMArray.cast(cmd).add((short) 1, KMByteBlob.exp()); // Wrapping Key KeyBlob
    KMArray.cast(cmd).add((short) 2, KMByteBlob.exp()); // Masking Key
    params = KMKeyParameters.exp();
    KMArray.cast(cmd).add((short) 3, params); // Wrapping key blob Params
    return receiveIncoming(apdu, cmd);
  }

  private void processBeginImportWrappedKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = beginImportWrappedKeyCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    // Step -1 parse the wrapping key blob
    // read wrapping key blob
    short keyBlob = KMArray.cast(cmd).get((short) 1);
    // read un wrapping key params
    short wrappingKeyParameters = KMArray.cast(cmd).get((short) 3);
    processWrappingKeyBlob(keyBlob, wrappingKeyParameters, scratchPad);
    // Step 2 - decrypt the encrypted transport key - 32 bytes AES-GCM key
    short transportKey = decryptTransportKey(data[SECRET], data[PUB_KEY],
        KMArray.cast(cmd).get((short) 0), scratchPad);
    // Step 3 - XOR the decrypted AES-GCM key with with masking key
    unmask(transportKey, KMArray.cast(cmd).get((short) 2));
    if(isValidWrappingKey()){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    setWrappingKey(transportKey);
    sendError(apdu, KMError.OK);
  }
  private short aesGCMEncrypt(short aesSecret, short input, short nonce, short authData, short authTag,byte[] scratchPad){
    Util.arrayFillNonAtomic(scratchPad, (short) 0, KMByteBlob.cast(input).length(), (byte) 0);
    short len = seProvider.aesGCMEncrypt(
        KMByteBlob.cast(aesSecret).getBuffer(),
        KMByteBlob.cast(aesSecret).getStartOff(),
        KMByteBlob.cast(aesSecret).length(),
        KMByteBlob.cast(input).getBuffer(),
        KMByteBlob.cast(input).getStartOff(),
        KMByteBlob.cast(input).length(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(nonce).getBuffer(),
        KMByteBlob.cast(nonce).getStartOff(),
        KMByteBlob.cast(nonce).length(),
        KMByteBlob.cast(authData).getBuffer(),
        KMByteBlob.cast(authData).getStartOff(),
        KMByteBlob.cast(authData).length(),
        KMByteBlob.cast(authTag).getBuffer(),
        KMByteBlob.cast(authTag).getStartOff(),
        KMByteBlob.cast(authTag).length());
    return KMByteBlob.instance(scratchPad, (short) 0, len);
  }

  private short aesGCMDecrypt(short aesSecret, short input, short nonce, short authData, short authTag,byte[] scratchPad){
    Util.arrayFillNonAtomic(scratchPad, (short) 0, KMByteBlob.cast(input).length(), (byte) 0);
    if (!seProvider.aesGCMDecrypt(
        KMByteBlob.cast(aesSecret).getBuffer(),
        KMByteBlob.cast(aesSecret).getStartOff(),
        KMByteBlob.cast(aesSecret).length(),
        KMByteBlob.cast(input).getBuffer(),
        KMByteBlob.cast(input).getStartOff(),
        KMByteBlob.cast(input).length(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(nonce).getBuffer(),
        KMByteBlob.cast(nonce).getStartOff(),
        KMByteBlob.cast(nonce).length(),
        KMByteBlob.cast(authData).getBuffer(),
        KMByteBlob.cast(authData).getStartOff(),
        KMByteBlob.cast(authData).length(),
        KMByteBlob.cast(authTag).getBuffer(),
        KMByteBlob.cast(authTag).getStartOff(),
        KMByteBlob.cast(authTag).length())) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    return KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.cast(input).length());
  }

  private short finishImportWrappedKeyCmd(APDU apdu){
    short cmd = KMArray.instance((short) 8);
    short params = KMKeyParameters.expAny();
    KMArray.cast(cmd).add((short) 0, params); // Key Params of wrapped key
    KMArray.cast(cmd).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT)); // Key Format
    KMArray.cast(cmd).add((short) 2, KMByteBlob.exp()); // Wrapped Import Key Blob
    KMArray.cast(cmd).add((short) 3, KMByteBlob.exp()); // Auth Tag
    KMArray.cast(cmd).add((short) 4, KMByteBlob.exp()); // IV - Nonce
    KMArray.cast(cmd)
        .add((short) 5, KMByteBlob.exp()); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.cast(cmd).add((short) 6, KMInteger.exp()); // Password Sid
    KMArray.cast(cmd).add((short) 7, KMInteger.exp()); // Biometric Sid
    return receiveIncoming(apdu, cmd);
  }

  //TODO remove cmd later on
  private void processFinishImportWrappedKeyCmd(APDU apdu){
    short cmd = finishImportWrappedKeyCmd(apdu);
    short keyParameters = KMArray.cast(cmd).get((short) 0);
    short keyFmt = KMArray.cast(cmd).get((short) 1);
    keyFmt = KMEnum.cast(keyFmt).getVal();
    validateImportKey(keyParameters, keyFmt);
    byte[] scratchPad = apdu.getBuffer();
    // Step 4 - AES-GCM decrypt the wrapped key
    data[INPUT_DATA] = KMArray.cast(cmd).get((short) 2);
    data[AUTH_TAG] = KMArray.cast(cmd).get((short) 3);
    data[NONCE] = KMArray.cast(cmd).get((short) 4);
    data[AUTH_DATA] = KMArray.cast(cmd).get((short) 5);

    if(!isValidWrappingKey()){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    data[IMPORTED_KEY_BLOB] = aesGCMDecrypt(getWrappingKey(),data[INPUT_DATA],data[NONCE],data[AUTH_DATA], data[AUTH_TAG],scratchPad);
    resetWrappingKey();
    // Step 5 - Import decrypted key
    data[ORIGIN] = KMType.SECURELY_IMPORTED;
    data[KEY_PARAMETERS] = keyParameters;
    // create key blob array
    importKey(apdu, keyFmt, scratchPad);
  }

  /**
   * 1) If attestation key is present and attestation challenge is absent then it is an error.
   * 2) If attestation key is absent and attestation challenge is present then it is an error as
   * factory provisioned attestation key is not supported.
   * 3) If both are present and issuer is absent or attest key purpose is not ATTEST_KEY then it is an error.
   * 4) If the generated/imported keys are RSA or EC then validity period must be specified.
   * Device Unique Attestation is not supported.
   */
  private KMAttestationCert makeCert(byte[] scratchPad) {
    byte mode = KMType.FAKE_CERT;
    boolean rsaCert = true;
    short attestationKey = KMType.INVALID_VALUE;
    boolean rsaAttest = true;
    // No attestation required for symmetric keys
    short alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if(KMEnumTag.cast(alg).getValue() != KMType.RSA &&
        KMEnumTag.cast(alg).getValue() != KMType.EC){
        return null;
    }
    // Device unique attestation not supported
    short deviceUniqueAttest = KMKeyParameters.findTag(KMType.BOOL_TAG,
        KMType.DEVICE_UNIQUE_ATTESTATION, data[KEY_PARAMETERS]);
    if(deviceUniqueAttest != KMType.INVALID_VALUE){
      KMException.throwIt(KMError.CANNOT_ATTEST_IDS);
    }
    if(KMEnumTag.cast(alg).getValue() == KMType.EC) {
      rsaCert = false;
      rsaAttest = false;
    }
    KMAttestationCert cert = seProvider.getAttestationCert(rsaCert);
    // Read attestation challenge if present
    short attChallenge =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ATTESTATION_CHALLENGE, data[KEY_PARAMETERS]);
    if(attChallenge != KMType.INVALID_VALUE){
      attChallenge = KMByteTag.cast(attChallenge).getValue();
    }
    short subject = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.CERTIFICATE_SUBJECT_NAME, data[KEY_PARAMETERS]);
    // If no subject name is specified then use the default subject name.
    if(subject == KMType.INVALID_VALUE || KMByteTag.cast(subject).length() == 0){
      subject = KMByteBlob.instance(defaultSubject, (short) 0, (short) defaultSubject.length);
    }else{
      subject = KMByteTag.cast(subject).getValue();
    }
    // If attestation key is given by the caller
    if(data[ATTEST_KEY_BLOB] != KMType.INVALID_VALUE &&
        KMByteBlob.cast(data[ATTEST_KEY_BLOB]).length() > 0) {
      // If no attestation challenge present then it is an error
      if (attChallenge == KMType.INVALID_VALUE || KMByteBlob.cast(attChallenge).length() <= 0) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      mode = KMType.ATTESTATION_CERT;
      attestationKey = data[ATTEST_KEY_BLOB];
      alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, data[ATTEST_KEY_PARAMS]);
      if(KMEnumTag.cast(alg).getValue() == KMType.EC){
        rsaAttest = false;
      }
      // If issuer is not present then it is an error
      if (KMByteBlob.cast(data[ATTEST_KEY_ISSUER]).length() <= 0) {
        KMException.throwIt(KMError.MISSING_ISSUER_SUBJECT_NAME);
      }
      // TODO KeyMint should parse issuer subject name to validate that it is valid der encoded
      //  string.
      //  Currently not done as X509 parsing not yet supported.

      short attKeyPurpose =
          KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, data[ATTEST_KEY_PARAMS]);
      // If the attest key's purpose is not "attest key" then error.
      if (!KMEnumArrayTag.cast(attKeyPurpose).contains(KMType.ATTEST_KEY)) {
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    }else if (attChallenge != KMType.INVALID_VALUE && KMByteBlob.cast(attChallenge).length() > 0) {
      // If the challenge is present and attest key is absent then it is an error.
      // Note: The keymint applet does not support factory provisioned attestation keys.
      KMException.throwIt(KMError.ATTESTATION_KEYS_NOT_PROVISIONED);
    }else {
      // Both attestation key and challenge are are absent.
      short purpose = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, data[KEY_PARAMETERS]);
      if(purpose != KMType.INVALID_VALUE && KMEnumArrayTag.cast(purpose).contains(KMType.SIGN)) {
        // If the generated/imported key can sign then mode is self signed
        mode = KMType.SELF_SIGNED_CERT;
        attestationKey = data[SECRET];
        data[ATTEST_KEY_ISSUER] = subject;
      }else{
        // else a fake cert i.e. certificated without signature must be generated
        mode = KMType.FAKE_CERT;
        attestationKey = KMType.INVALID_VALUE;
        data[ATTEST_KEY_ISSUER] = subject;
      }
    }
    cert.attestKey(attestationKey, rsaAttest,mode);
    cert.attestationChallenge(attChallenge);
    cert.issuer(data[ATTEST_KEY_ISSUER]);
    cert.subjectName(subject);

    // Validity period must be specified
    short notBefore = KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CERTIFICATE_NOT_BEFORE, data[KEY_PARAMETERS]);
    if(notBefore == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.MISSING_NOT_BEFORE);
    }
    notBefore = KMIntegerTag.cast(notBefore).getValue();
    short notAfter = KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CERTIFICATE_NOT_AFTER, data[KEY_PARAMETERS]);
    if(notAfter == KMType.INVALID_VALUE ){
      KMException.throwIt(KMError.MISSING_NOT_AFTER);
    }
    notAfter = KMIntegerTag.cast(notAfter).getValue();
    // VTS sends notBefore == Epoch.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
    short epoch = KMInteger.instance(scratchPad, (short)0, (short)8);
    short end = KMInteger.instance(dec319999Ms, (short)0, (short)dec319999Ms.length);
    if(KMInteger.compare(notBefore, epoch) == 0){
      cert.notBefore(KMByteBlob.instance(jan01970, (short)0, (short)jan01970.length),
          true, scratchPad);
    }else {
      cert.notBefore(notBefore, false, scratchPad);
    }
    // VTS sends notAfter == Dec 31st 9999
    if(KMInteger.compare(notAfter, end) == 0){
      cert.notAfter(KMByteBlob.instance(dec319999, (short)0, (short)dec319999.length),
          true, scratchPad);
    }else {
      cert.notAfter(notAfter, false, scratchPad);
    }
    // Serial number
    short serialNum =
        KMKeyParameters.findTag(KMType.BIGNUM_TAG, KMType.CERTIFICATE_SERIAL_NUM, data[KEY_PARAMETERS]);
    if (serialNum != KMType.INVALID_VALUE) {
      serialNum = KMBignumTag.cast(serialNum).getValue();
    }else{
      serialNum= KMByteBlob.instance((short)1);
      KMByteBlob.cast(serialNum).add((short)0, (byte)1);
    }
    cert.serialNumber(serialNum);

    //Extension
    if(mode == KMType.ATTESTATION_CERT){
      // Save attestation application id - must be present.
      short attAppId =
          KMKeyParameters.findTag( KMType.BYTES_TAG, KMType.ATTESTATION_APPLICATION_ID, data[KEY_PARAMETERS]);
      if (attAppId == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
      }
      cert.extensionTag(attAppId, false);
      // unique id byte blob - uses application id and temporal month count of creation time.
      setUniqueId(cert, scratchPad);
      // Add Attestation Ids if present
      addAttestationIds(cert, scratchPad);
      // Add Tags
      addTags(data[HW_PARAMETERS], true, cert);
      addTags(data[SW_PARAMETERS], false, cert);
      // Add Device Boot locked status
      cert.deviceLocked(seProvider.isDeviceBootLocked());
      // VB data
      cert.verifiedBootHash(getVerifiedBootHash(scratchPad));
      cert.verifiedBootKey(getBootKey(scratchPad));
      cert.verifiedBootState((byte)seProvider.getBootState());
    }

    // Public key
    cert.publicKey(data[PUB_KEY]);
    return cert;
  }

  protected short getBootKey(byte[] scratchPad){
    Util.arrayFillNonAtomic(scratchPad, (short)0, VERIFIED_BOOT_KEY_SIZE, (byte)0);
    short len = seProvider.getVerifiedBootHash(scratchPad,(short)0);
    if(len != VERIFIED_BOOT_KEY_SIZE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMByteBlob.instance(scratchPad,(short)0, VERIFIED_BOOT_KEY_SIZE);
  }
 
  protected short getVerifiedBootHash(byte[] scratchPad){
    Util.arrayFillNonAtomic(scratchPad, (short)0, VERIFIED_BOOT_HASH_SIZE, (byte)0);
    short len = seProvider.getVerifiedBootHash(scratchPad,(short)0);
    if(len != VERIFIED_BOOT_HASH_SIZE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMByteBlob.instance(scratchPad,(short)0, VERIFIED_BOOT_HASH_SIZE);
  }
  // --------------------------------
  private static void addAttestationIds(KMAttestationCert cert, byte[] scratchPad) {
    final short[] attTags =
        new short[]{
            KMType.ATTESTATION_ID_BRAND,
            KMType.ATTESTATION_ID_DEVICE,
            KMType.ATTESTATION_ID_IMEI,
            KMType.ATTESTATION_ID_MANUFACTURER,
            KMType.ATTESTATION_ID_MEID,
            KMType.ATTESTATION_ID_MODEL,
            KMType.ATTESTATION_ID_PRODUCT,
            KMType.ATTESTATION_ID_SERIAL
        };
    byte index = 0;
    //short attIdTag;
    while (index < (short) attTags.length) {
      //attIdTag = repository.getAttId(mapToAttId(attTags[index]));
      if(KMKeyParameters.findTag(KMType.BYTES_TAG,attTags[index],data[KEY_PARAMETERS]) == KMType.INVALID_VALUE){
        continue;
      }
      short attIdTagLen = seProvider.getAttestationId(attTags[index],scratchPad, (short)0);
      if (attIdTagLen != 0) {
        short blob = KMByteBlob.instance(scratchPad, (short)0, attIdTagLen);
        //attIdTag = KMByteTag.instance(attTags[index], blob);
        //cert.extensionTag(attIdTag, true);
        cert.extensionTag(KMByteTag.instance(attTags[index], blob), true);
      }
      index++;
    }
  }

  private static void addTags(short params, boolean hwEnforced, KMAttestationCert cert) {
    short index = 0;
    short arr = KMKeyParameters.cast(params).getVals();
    short len = KMArray.cast(arr).length();
    short tag;
    while (index < len) {
      tag = KMArray.cast(arr).get(index);
      cert.extensionTag(tag, hwEnforced);
      index++;
    }
  }

  private static void setUniqueId(KMAttestationCert cert, byte[] scratchPad) {
    if(!KMTag.isPresent(data[KEY_PARAMETERS],KMType.BOOL_TAG, KMType.INCLUDE_UNIQUE_ID)){
      return;
    }
    // temporal count T
    short time = KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CREATION_DATETIME, data[KEY_PARAMETERS]);
    if(time == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.INVALID_TAG);
    }
    time = KMIntegerTag.cast(time).getValue();

    // Application Id C
    short appId = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ATTESTATION_APPLICATION_ID, data[KEY_PARAMETERS]);
    if (appId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    appId = KMByteTag.cast(appId).getValue();

    // Reset After Rotation R - it will be part of HW Enforced key
    // characteristics
    byte resetAfterRotation = 0;
    if(KMTag.isPresent(data[KEY_PARAMETERS], KMType.BOOL_TAG, KMType.RESET_SINCE_ID_ROTATION)){
      resetAfterRotation = 0x01;
    }

    cert.makeUniqueId(scratchPad, (short) 0, KMInteger.cast(time).getBuffer(),
        KMInteger.cast(time).getStartOff(), KMInteger.cast(time).length(),
        KMByteBlob.cast(appId).getBuffer(), KMByteBlob.cast(appId).getStartOff(), KMByteBlob.cast(appId).length(), resetAfterRotation,
        seProvider.getMasterKey());
  }

  private void processDestroyAttIdsCmd(APDU apdu) {
    seProvider.deleteAttestationIds();
    sendError(apdu, KMError.OK);
  }

  private void processVerifyAuthorizationCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private short abortOperationCmd(APDU apdu){
    short cmd = KMArray.instance((short) 1);
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processAbortOperationCmd(APDU apdu) {
    short cmd = abortOperationCmd(apdu);
    data[OP_HANDLE] = KMArray.cast(cmd).get((short) 0);
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      sendError(apdu,KMError.INVALID_OPERATION_HANDLE);
    }else {
      releaseOperation(op);
      sendError(apdu, KMError.OK);
    }
  }

  private short finishOperationCmd(APDU apdu){
    short cmd = KMArray.instance((short) 5);
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());//op handle
    KMArray.cast(cmd).add((short) 1, KMByteBlob.exp());// input data
    KMArray.cast(cmd).add((short) 2, KMByteBlob.exp()); // signature
    short authToken = KMHardwareAuthToken.exp();
    KMArray.cast(cmd).add((short) 3, authToken); // auth token
    short verToken = KMVerificationToken.exp();
    KMArray.cast(cmd).add((short) 4, verToken); // time stamp token
    return receiveIncoming(apdu, cmd);
  }

  private void processFinishOperationCmd(APDU apdu) {
    short cmd = finishOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[OP_HANDLE] = KMArray.cast(cmd).get((short) 0);
    data[INPUT_DATA] = KMArray.cast(cmd).get((short) 1);
    data[SIGNATURE] = KMArray.cast(cmd).get((short) 2);
    data[HW_TOKEN] = KMArray.cast(cmd).get((short) 3);
    data[VERIFICATION_TOKEN] = KMArray.cast(cmd).get((short) 4);
    // Check Operation Handle
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // Authorize the finish operation
    authorizeUpdateFinishOperation(op, scratchPad);
    switch (op.getPurpose()) {
      case KMType.SIGN:
      case KMType.VERIFY:
        finishSigningVerifyingOperation(op, scratchPad);
        break;
      case KMType.ENCRYPT:
        finishEncryptOperation(op, scratchPad);
        break;
      case KMType.DECRYPT:
        finishDecryptOperation(op, scratchPad);
        break;
    }
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    // Remove the operation handle
    releaseOperation(op);

    // make response
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, data[OUTPUT_DATA]);
    sendOutgoing(apdu, resp);
  }

  private void finishEncryptOperation(KMOperationState op, byte[] scratchPad) {
    if(op.getAlgorithm() != KMType.AES && op.getAlgorithm() != KMType.DES){
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    finishAesDesOperation(op);
  }

  private void finishDecryptOperation(KMOperationState op, byte[] scratchPad) {
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        // Fill the scratch pad with zero
        Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
        if (op.getPadding() == KMType.PADDING_NONE && len != 256) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        }
        len =
            op.getOperation().finish(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(), KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                len, scratchPad, (short) 0);

        data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short) 0, len);
        break;
      case KMType.AES:
      case KMType.DES:
        if(op.getBlockMode() == KMType.GCM && (len < (short) (op.getMacLength() / 8))){
          // Check if there is at least MAC Length bytes of input data
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        }
        finishAesDesOperation(op);
        break;
    }
  }

  private void finishAesDesOperation(KMOperationState op){
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    short blockSize = AES_BLOCK_SIZE;
    if (op.getAlgorithm() == KMType.DES) {
      blockSize= DES_BLOCK_SIZE;
    }

    // If no padding then data length must be block aligned
    if(op.getPadding() == KMType.PADDING_NONE && op.getPurpose() == KMType.ENCRYPT
        && (op.getBlockMode() == KMType.ECB || op.getBlockMode() == KMType.CBC)
        && ((short) (len % blockSize) != 0)){
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    if(op.getPurpose() == KMType.DECRYPT && len > 0
        && (op.getBlockMode() == KMType.ECB || op.getBlockMode() == KMType.CBC)
        && ((short) (len % blockSize) != 0)){
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    if (op.getBlockMode() == KMType.GCM) {
      if(op.isAesGcmUpdateAllowed()){
        op.setAesGcmUpdateComplete();
      }
      //Get output size as it can be more then input size in case of GCM
      len = op.getOperation().getAESGCMOutputSize(len, (short) (op.getMacLength() / 8));
    }
    // If padding i.e. pkcs7 then add padding to right
    // Output data can at most one block size more the input data in case of pkcs7 encryption
    // In case of gcm we will allocate extra memory of the size equal to blocksize.
    short outData  = KMByteBlob.instance((short) (len + blockSize));
    len =
        op.getOperation()
            .finish(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                KMByteBlob.cast(data[INPUT_DATA]).length(),
                KMByteBlob.cast(outData).getBuffer(),
                KMByteBlob.cast(outData).getStartOff());
    KMByteBlob.cast(outData).setLength(len);
    data[OUTPUT_DATA] = outData;
  }

  private void finishSigningVerifyingOperation(KMOperationState op, byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        // If there is no padding we can treat signing as a RSA decryption operation.
        try {
          if (op.getPurpose() == KMType.SIGN) {
            // len of signature will be 256 bytes - but it can be less then 256 bytes
            short len = op.getOperation().sign(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(), scratchPad,
                    (short) 0);
            // Maximum output size of signature is 256 bytes. - the signature will always be positive
            data[OUTPUT_DATA] = KMByteBlob.instance((short) 256);
            Util.arrayCopyNonAtomic(
                    scratchPad,
                    (short) 0,
                    KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
                    (short) (KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff() + 256 - len),
                    len);
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException e) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        break;
      case KMType.EC:
        short len = KMByteBlob.cast(data[INPUT_DATA]).length();
        // If DIGEST NONE then truncate the input data to 32 bytes.
        if (op.getDigest() == KMType.DIGEST_NONE && len > 32) {
          len = 32;
        }
        if (op.getPurpose() == KMType.SIGN) {
          // len of signature will be 512 bits i.e. 64 bytes
          len =
              op.getOperation()
                  .sign(
                      KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                      KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                      len,
                      scratchPad,
                      (short) 0);
          data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short) 0, len);
        } else {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.HMAC:
        // As per Keymaster HAL documentation, the length of the Hmac output can
        // be decided by using TAG_MAC_LENGTH in Keyparameters. But there is no
        // such provision to control the length of the Hmac output using JavaCard
        // crypto APIs and the current implementation always returns 32 bytes
        // length of Hmac output. So to provide support to TAG_MAC_LENGTH
        // feature, we truncate the output signature to TAG_MAC_LENGTH and return
        // the truncated signature back to the caller. At the time of verfication
        // we again compute the signature of the plain text input, truncate it to
        // TAG_MAC_LENGTH and compare it with the input signature for
        // verification. So this is the reason we are using KMType.SIGN directly
        // instead of using op.getPurpose().
        op.getOperation()
            .sign(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                KMByteBlob.cast(data[INPUT_DATA]).length(),
                scratchPad,
                (short) 0);
        if(op.getPurpose() == KMType.SIGN) {
          // Copy only signature of mac length size.
          data[OUTPUT_DATA] =
              KMByteBlob.instance(scratchPad, (short) 0, (short) (op.getMacLength() / 8));
        }else if (op.getPurpose() == KMType.VERIFY) {
          if (0
              != Util.arrayCompare(
              scratchPad, (short)0,
              KMByteBlob.cast(data[SIGNATURE]).getBuffer(),
              KMByteBlob.cast(data[SIGNATURE]).getStartOff(),
              KMByteBlob.cast(data[SIGNATURE]).length())) {
            KMException.throwIt(KMError.VERIFICATION_FAILED);
          }
          data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
        }
        break;
      default: // This is should never happen
        KMException.throwIt(KMError.OPERATION_CANCELLED);
        break;
    }
  }

  private void authorizeUpdateFinishOperation(KMOperationState op, byte[] scratchPad) {
    // If one time user Authentication is required
    if (op.isSecureUserIdReqd() && !op.isAuthTimeoutValidated()) {
      validateVerificationToken(op, data[VERIFICATION_TOKEN], scratchPad);
      short authTime = op.getAuthTime();
      short verTime = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getTimestamp();
      if (verTime == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
      if (KMInteger.compare(authTime, verTime) < 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      op.setAuthTimeoutValidated(true);
    } else if (op.isAuthPerOperationReqd()) { // If Auth per operation is required
      short challenge = KMHardwareAuthToken.cast(data[HW_TOKEN]).getChallenge();
      if (KMInteger.compare(data[OP_HANDLE], challenge) != 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      authenticateUser();
    }
  }

  private void authorizeDeviceUnlock(short hwToken) {
    // If device is locked and key characteristics requires unlocked device then check whether
    // HW auth token has correct timestamp.
    short ptr =
        KMKeyParameters.findTag(
            KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED, data[HW_PARAMETERS]);

    if (ptr != KMType.INVALID_VALUE && repository.getDeviceLock()) {
      if (hwToken == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
      // Check if the current auth time stamp is greater then device locked time stamp
      short ts = repository.getDeviceTimeStamp();
      if (KMInteger.compare(ptr, ts) <= 0) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      // Now check if the device unlock requires password only authentication and whether
      // auth token is generated through password authentication or not.
      if (repository.getDeviceLockPasswordOnly()) {
        ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
        ptr = KMEnum.cast(ptr).getVal();
        if (((byte) ptr & KMType.PASSWORD) == 0) {
          KMException.throwIt(KMError.DEVICE_LOCKED);
        }
      }
      // Unlock the device
      // repository.deviceLockedFlag = false;
      repository.setDeviceLock(false);
      repository.clearDeviceLockTimeStamp();
    }
  }

  private void validateVerificationToken(KMOperationState op, short verToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian and Java is big endian
    short ptr = KMVerificationToken.cast(verToken).getMac();
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    validateVerificationToken(verToken, scratchPad);
    // validate operation handle.
    ptr = KMVerificationToken.cast(verToken).getChallenge();
    if (op.getHandle() != KMInteger.cast(ptr).getShort()) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private void validateVerificationToken(short verToken, byte[] scratchPad) {
    short ptr = KMVerificationToken.cast(verToken).getMac();
    short len;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    // concatenation length will be 37 + length of verified parameters list  - which is typically
    // empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopy(
        authVerification, (short) 0, scratchPad, (short) 0, (short) authVerification.length);
    len = (short) authVerification.length;
    // concatenate challenge - 8 bytes
    ptr = KMVerificationToken.cast(verToken).getChallenge();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.cast(verToken).getTimestamp();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // hmac the data
    ptr = KMVerificationToken.cast(verToken).getMac();
    short key = repository.getComputedHmacKey();
    boolean verified =
        seProvider.hmacVerify(
            KMByteBlob.cast(key).getBuffer(),
            KMByteBlob.cast(key).getStartOff(),
            KMByteBlob.cast(key).length(),
            scratchPad,
            (short) 0,
            len,
            KMByteBlob.cast(ptr).getBuffer(),
            KMByteBlob.cast(ptr).getStartOff(),
            KMByteBlob.cast(ptr).length());

    if (!verified) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private short updateOperationCmd(APDU apdu){
    short cmd = KMArray.instance((short) 4);
    // Arguments
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());
    KMArray.cast(cmd).add((short) 1, KMByteBlob.exp());
    short authToken = KMHardwareAuthToken.exp();
    KMArray.cast(cmd).add((short) 2, authToken);
    short verToken = KMVerificationToken.exp();
    KMArray.cast(cmd).add((short) 3, verToken);
    return receiveIncoming(apdu, cmd);
  }

  private void processUpdateOperationCmd(APDU apdu) {
    short cmd = updateOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[OP_HANDLE] = KMArray.cast(cmd).get((short) 0);
    data[INPUT_DATA] = KMArray.cast(cmd).get((short) 1);
    data[HW_TOKEN] = KMArray.cast(cmd).get((short) 2);
    data[VERIFICATION_TOKEN] = KMArray.cast(cmd).get((short) 3);

    // Input data must be present even if it is zero length.
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    // Check Operation Handle and get op state
    // Check Operation Handle
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // authorize the update operation
    authorizeUpdateFinishOperation(op, scratchPad);

    if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY) {
       short len = KMByteBlob.cast(data[INPUT_DATA]).length();
      // update the data.
      op.getOperation()
          .update(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length());
      data[OUTPUT_DATA] = KMType.INVALID_VALUE;
    } else if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
      // Update for encrypt/decrypt using RSA will not be supported because to do this op state
      //  will have to buffer the data - so reject the update if it is rsa algorithm.
      if (op.getAlgorithm() == KMType.RSA) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      short len  = KMByteBlob.cast(data[INPUT_DATA]).length();
      short additionalExpOutLen = 0;
      if (op.getAlgorithm() == KMType.AES) {
        if (op.getBlockMode() == KMType.GCM) {
          if(op.isAesGcmUpdateAllowed()){
            op.setAesGcmUpdateComplete();
          }
          // if input data present then it should be block aligned.
          if (len > 0) {
            if (len % AES_BLOCK_SIZE != 0) {
              KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
            }
          }
          additionalExpOutLen = 16;
        } else {
          // input data must be block aligned.
          // 128 bit block size - HAL must send block aligned data
          if (len % AES_BLOCK_SIZE != 0 || len  <= 0) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
        }
      } else if (op.getAlgorithm() == KMType.DES) {
        // 64 bit block size - HAL must send block aligned data
        if (len % DES_BLOCK_SIZE != 0) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        }
      }
      // Allocate output buffer as input data is already block aligned
      data[OUTPUT_DATA] = KMByteBlob.instance((short) (len + additionalExpOutLen));
      // Otherwise just update the data.
      // HAL consumes all the input and maintains a buffered data inside it. So the
      // applet sends the inputConsumed length as same as the input length.
      try {
        len =
            op.getOperation()
                .update(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
      } catch (CryptoException e) {
        KMException.throwIt(KMError.INVALID_TAG);
      }

      // Adjust the Output data if it is not equal to input data.
      // This happens in case of JCardSim provider.
      if (len != KMByteBlob.cast(data[OUTPUT_DATA]).length()) {
        data[INPUT_DATA] = data[OUTPUT_DATA];
        data[OUTPUT_DATA] = KMByteBlob.instance(len);
        Util.arrayCopy(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff(),
            len);
      }
    }

    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    // Persist if there are any updates.
    //op.persist();
    // make response
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, data[OUTPUT_DATA]);
    sendOutgoing(apdu, resp);
  }

  private short updateAadOperationCmd(APDU apdu){
    short cmd = KMArray.instance((short) 4);
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());
    KMArray.cast(cmd).add((short) 1, KMByteBlob.exp());
    short authToken = KMHardwareAuthToken.exp();
    KMArray.cast(cmd).add((short) 2, authToken);
    short verToken = KMVerificationToken.exp();
    KMArray.cast(cmd).add((short) 3, verToken);
    return receiveIncoming(apdu, cmd);
  }

  private void processUpdateAadOperationCmd(APDU apdu) {
    short cmd = updateAadOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[OP_HANDLE] = KMArray.cast(cmd).get((short) 0);
    data[INPUT_DATA] = KMArray.cast(cmd).get((short) 1);
    data[HW_TOKEN] = KMArray.cast(cmd).get((short) 2);
    data[VERIFICATION_TOKEN] = KMArray.cast(cmd).get((short) 3);

    // Input data must be present even if it is zero length.
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Check Operation Handle and get op state
    // Check Operation Handle
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    if(op.getAlgorithm() != KMType.AES ){
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    if(op.getBlockMode() != KMType.GCM ){
      KMException.throwIt(KMError.INCOMPATIBLE_BLOCK_MODE);
    }
    if(!op.isAesGcmUpdateAllowed() ){
      KMException.throwIt(KMError.INVALID_TAG);
    }
    if(op.getPurpose() != KMType.ENCRYPT && op.getPurpose() != KMType.DECRYPT){
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
    // authorize the update operation
    authorizeUpdateFinishOperation(op, scratchPad);
    try {
      op.getOperation()
          .updateAAD(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length());
    }catch(CryptoException exp){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // make response
    short resp = KMArray.instance((short) 1);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    sendOutgoing(apdu, resp);
  }

  private short beginOperationCmd(APDU apdu){
    short cmd = KMArray.instance((short) 4);
    // Arguments
    short params = KMKeyParameters.expAny();
    KMArray.cast(cmd).add((short) 0, KMEnum.instance(KMType.PURPOSE));
    KMArray.cast(cmd).add((short) 1, KMByteBlob.exp());
    KMArray.cast(cmd).add((short) 2, params);
    short authToken  = KMHardwareAuthToken.exp();
    KMArray.cast(cmd).add((short) 3, authToken);
    return receiveIncoming(apdu, cmd);
  }

  private void processBeginOperationCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = beginOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    short purpose = KMArray.cast(cmd).get((short) 0);
    data[KEY_BLOB] = KMArray.cast(cmd).get((short) 1);
    data[KEY_PARAMETERS] = KMArray.cast(cmd).get((short) 2);
    data[HW_TOKEN] = KMArray.cast(cmd).get((short) 3);
    purpose = KMEnum.cast(purpose).getVal();
    // Check for app id and app data.
    data[APP_ID] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    data[APP_DATA] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(data[APP_ID]).getValue();
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(data[APP_DATA]).getValue();
    }
    // Parse the encrypted blob and decrypt it.
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    KMTag.assertAbsence(data[SB_PARAMETERS],KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, KMError.EARLY_BOOT_ENDED);
    KMTag.assertPresence(data[SB_PARAMETERS],KMType.ENUM_TAG,KMType.ALGORITHM,KMError.UNSUPPORTED_ALGORITHM);
    short algorithm = KMEnumTag.getValue(KMType.ALGORITHM,data[SB_PARAMETERS]);
    // If Blob usage tag is present in key characteristics then it should be standalone.
    if(KMTag.isPresent(data[SB_PARAMETERS],KMType.ENUM_TAG, KMType.BLOB_USAGE_REQ)){
      if(KMEnumTag.getValue(KMType.BLOB_USAGE_REQ, data[SB_PARAMETERS]) != KMType.STANDALONE){
        KMException.throwIt(KMError.UNSUPPORTED_TAG);
      }
    }

    // Generate a random number for operation handle
    short buf = KMByteBlob.instance(KMOperationState.OPERATION_HANDLE_SIZE);
    generateUniqueOperationHandle(
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    /* opHandle is a KMInteger and is encoded as KMInteger when it is returned back. */
    short opHandle = KMInteger.instance(
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    KMOperationState op = reserveOperation(algorithm,opHandle);
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    data[OP_HANDLE] = op.getHandle();
    op.setPurpose((byte) purpose);
    op.setKeySize(KMByteBlob.cast(data[SECRET]).length());
    authorizeAndBeginOperation(op, scratchPad);
    switch (op.getPurpose()) {
      case KMType.SIGN:
      case KMType.VERIFY:
        beginSignVerifyOperation(op);
        break;
      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        beginCipherOperation(op);
        break;
      default:
        KMException.throwIt(KMError.UNIMPLEMENTED);
        break;
    }
    short iv = KMType.INVALID_VALUE;
    // If the data[IV] is required to be returned.
    // As per VTS, for the decryption operation don't send the iv back.
    if (data[IV] != KMType.INVALID_VALUE
        && op.getPurpose() != KMType.DECRYPT
        && op.getBlockMode() != KMType.ECB) {
      iv = KMArray.instance((short) 1);
      if (op.getAlgorithm() == KMType.DES && op.getBlockMode() == KMType.CBC) {
        // For AES/DES we are generate an random iv of length 16 bytes.
        // While sending the iv back for DES/CBC mode of opeation only send
        // 8 bytes back.
        short ivBlob = KMByteBlob.instance((short) 8);
        Util.arrayCopy(
            KMByteBlob.cast(data[IV]).getBuffer(),
            KMByteBlob.cast(data[IV]).getStartOff(),
            KMByteBlob.cast(ivBlob).getBuffer(),
            KMByteBlob.cast(ivBlob).getStartOff(),
            (short) 8);
        data[IV] = ivBlob;
      }
      KMArray.cast(iv).add((short) 0, KMByteTag.instance(KMType.NONCE, data[IV]));
    } else {
      iv = KMArray.instance((short) 0);
    }

    short params = KMKeyParameters.instance(iv);
    short resp  = KMArray.instance((short) 4);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, params);
    KMArray.cast(resp).add((short) 2, data[OP_HANDLE]);
    KMArray.cast(resp).add((short) 3, KMInteger.uint_8(op.getBufferingMode()));
    sendOutgoing(apdu, resp);
  }

  private void authorizeAlgorithm(KMOperationState op) {
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    if (alg == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    op.setAlgorithm((byte) alg);
  }

  private void authorizePurpose(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.AES:
      case KMType.DES:
        if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.EC:
      case KMType.HMAC:
        if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      default:
        break;
    }
    if (!KMEnumArrayTag.contains(KMType.PURPOSE, op.getPurpose(), data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
  }

  private void authorizeDigest(KMOperationState op) {
    short digests =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[HW_PARAMETERS]);
    op.setDigest(KMType.DIGEST_NONE);
    short param =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(param).length() != 1) {
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
      }
      param = KMEnumArrayTag.cast(param).get((short) 0);
      if (!KMEnumArrayTag.cast(digests).contains(param)) {
        KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
      }
      op.setDigest((byte) param);
    }else if(KMEnumArrayTag.contains(KMType.PADDING, KMType.RSA_PKCS1_1_5_SIGN, data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    short paramPadding =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[KEY_PARAMETERS]);
    if (paramPadding != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(paramPadding).length() != 1) {
        //TODO vts fails because it expects UNSUPPORTED_PADDING_MODE
        KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
      }
      paramPadding = KMEnumArrayTag.cast(paramPadding).get((short) 0);
    }
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        if ((paramPadding == KMType.RSA_OAEP || paramPadding == KMType.RSA_PSS)
            && param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
        }
        break;
      case KMType.EC:
      case KMType.HMAC:
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
        }
        break;
      default:
        break;
    }
  }

  private void authorizePadding(KMOperationState op) {
    short paddings =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[HW_PARAMETERS]);
    op.setPadding(KMType.PADDING_NONE);
    short param =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[KEY_PARAMETERS]);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(param).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      param = KMEnumArrayTag.cast(param).get((short) 0);
      if (!KMEnumArrayTag.cast(paddings).contains(param)) {
        KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
      }
    }
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }
        if ((op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY)
            && param != KMType.PADDING_NONE
            && param != KMType.RSA_PSS
            && param != KMType.RSA_PKCS1_1_5_SIGN) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }
        if ((op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT)
            && param != KMType.PADDING_NONE
            && param != KMType.RSA_OAEP
            && param != KMType.RSA_PKCS1_1_5_ENCRYPT) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }

        if (param == KMType.PADDING_NONE && op.getDigest() != KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        if ((param == KMType.RSA_OAEP || param == KMType.RSA_PSS)
            && op.getDigest() == KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        //TODO d to verify whether javacard support MGF1 = SHA1 or is it equal to the OAEP scheme
        // digest. There is no way to define any other digest.
        if(param == KMType.RSA_OAEP){
          short mgfDigest = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG,
              KMType.RSA_OAEP_MGF_DIGEST, data[KEY_PARAMETERS]);
          if(mgfDigest != KMType.INVALID_VALUE) {
            if(KMEnumArrayTag.cast(mgfDigest).length() != 1) {
              KMException.throwIt(KMError.INVALID_ARGUMENT);
            }
            mgfDigest = KMEnumArrayTag.cast(mgfDigest).get((short) 0);
            if (mgfDigest == KMType.DIGEST_NONE) {
              KMException.throwIt(KMError.UNSUPPORTED_MGF_DIGEST);
            }
            if (!KMEnumArrayTag
                .contains(KMType.RSA_OAEP_MGF_DIGEST, mgfDigest, data[HW_PARAMETERS])) {
              KMException.throwIt(KMError.INCOMPATIBLE_MGF_DIGEST);
            }
            if (mgfDigest != KMType.SHA1 && mgfDigest != KMType.SHA2_256) {
              KMException.throwIt(KMError.UNSUPPORTED_MGF_DIGEST);
            }
          }
        }
        op.setPadding((byte) param);
        break;
      case KMType.DES:
      case KMType.AES:
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }
        op.setPadding((byte) param);
        break;
      default:
        break;
    }
  }

  private void authorizeBlockModeAndMacLength(KMOperationState op) {
    short param =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, data[KEY_PARAMETERS]);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(param).length() != 1) {
        KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
      }
      param = KMEnumArrayTag.cast(param).get((short) 0);
    }
    if (KMType.AES == op.getAlgorithm() || KMType.DES == op.getAlgorithm()) {
      if (!KMEnumArrayTag.contains(KMType.BLOCK_MODE, param, data[HW_PARAMETERS])) {
        KMException.throwIt(KMError.INCOMPATIBLE_BLOCK_MODE);
      }
    }
    short macLen =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MAC_LENGTH, data[KEY_PARAMETERS]);
    switch (op.getAlgorithm()) {
      case KMType.AES:
        //Validate the block mode.
        switch (param) {
          case KMType.ECB:
          case KMType.CBC:
          case KMType.CTR:
          case KMType.GCM:
            break;
          default:
            KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
        }
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        if (param == KMType.GCM) {
          if (op.getPadding() != KMType.PADDING_NONE || op.getPadding() == KMType.PKCS7) {
            KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
          }
          if (macLen == KMType.INVALID_VALUE) {
            KMException.throwIt(KMError.MISSING_MAC_LENGTH);
          }
          if (macLen % 8 != 0
              || macLen > 128
              || macLen
              < KMIntegerTag.getShortValue(
              KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
            KMException.throwIt(KMError.INVALID_MAC_LENGTH);
          }
          op.setMacLength(macLen);
        }
        if (param == KMType.CTR) {
          if (op.getPadding() != KMType.PADDING_NONE || op.getPadding() == KMType.PKCS7) {
            KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
          }
        }
          break;
      case KMType.DES:
        //Validate the block mode.
        switch (param) {
          case KMType.ECB:
          case KMType.CBC:
            break;
          default:
            KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
        }
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        break;
      case KMType.HMAC:
        if (macLen == KMType.INVALID_VALUE) {
          if (op.getPurpose() == KMType.SIGN) {
            KMException.throwIt(KMError.MISSING_MAC_LENGTH);
          }
        } else {
          // MAC length may not be specified for verify.
          if (op.getPurpose() == KMType.VERIFY) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }
          if (macLen
              < KMIntegerTag.getShortValue(
              KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
            KMException.throwIt(KMError.INVALID_MAC_LENGTH);
          } else if (macLen
              > KMIntegerTag.getShortValue(
              KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
            KMException.throwIt(KMError.UNSUPPORTED_MAC_LENGTH);
          }
          op.setMacLength(macLen);
        }
        break;
      default:
        break;
    }
    op.setBlockMode((byte) param);
  }

  private void authorizeAndBeginOperation(KMOperationState op, byte[] scratchPad) {
    authorizePurpose(op);
    authorizeDigest(op);
    authorizePadding(op);
    authorizeBlockModeAndMacLength(op);
    if (!validateHwToken(data[HW_TOKEN], scratchPad)) {
      data[HW_TOKEN] = KMType.INVALID_VALUE;
    }
    authorizeUserSecureIdAuthTimeout(op);
    authorizeDeviceUnlock(data[HW_TOKEN]);
    // Authorize Caller Nonce - if caller nonce absent in key char and nonce present in
    // key params then fail if it is not a Decrypt operation
    data[IV] = KMType.INVALID_VALUE;

    if (!KMTag.isPresent(data[HW_PARAMETERS], KMType.BOOL_TAG, KMType.CALLER_NONCE )
        && KMTag.isPresent(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.NONCE )
        && op.getPurpose() != KMType.DECRYPT) {
      KMException.throwIt(KMError.CALLER_NONCE_PROHIBITED);
    }

    short nonce = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.NONCE, data[KEY_PARAMETERS]);
    // If Nonce is present then check whether the size of nonce is correct.
    if (nonce != KMType.INVALID_VALUE) {
      data[IV] = KMByteTag.cast(nonce).getValue();
      // For CBC mode - iv must be 8 bytes
      if (op.getBlockMode() == KMType.CBC
          && op.getAlgorithm() == KMType.DES
          && KMByteBlob.cast(data[IV]).length() != 8) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }

      // For GCM mode - IV must be 12 bytes
      if (KMByteBlob.cast(data[IV]).length() != 12 && op.getBlockMode() == KMType.GCM) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }

      // For AES CBC and CTR modes IV must be 16 bytes
      if ((op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.CTR)
          && op.getAlgorithm() == KMType.AES
          && KMByteBlob.cast(data[IV]).length() != 16) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }
    } else if (op.getAlgorithm() == KMType.AES || op.getAlgorithm() == KMType.DES) {

      // For symmetric decryption iv is required
      if (op.getPurpose() == KMType.DECRYPT
          && (op.getBlockMode() == KMType.CBC
          || op.getBlockMode() == KMType.GCM
          || op.getBlockMode() == KMType.CTR)) {
        KMException.throwIt(KMError.MISSING_NONCE);
      } else if (op.getBlockMode() == KMType.ECB) {
        // For ECB we create zero length nonce
        data[IV] = KMByteBlob.instance((short) 0);
      } else if (op.getPurpose() == KMType.ENCRYPT) {

        // For encrypt mode if nonce is absent then create random nonce of correct length
        byte ivLen = 16;
        if (op.getBlockMode() == KMType.GCM) {
          ivLen = 12;
        } else if (op.getAlgorithm() == KMType.DES) {
          ivLen = 8;
        }
        data[IV] = KMByteBlob.instance(ivLen);
        seProvider.newRandomNumber(
            KMByteBlob.cast(data[IV]).getBuffer(),
            KMByteBlob.cast(data[IV]).getStartOff(),
            KMByteBlob.cast(data[IV]).length());
      }
    }
  }

  private void beginCipherOperation(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        try {
          if (op.getPurpose() == KMType.DECRYPT) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    (byte)op.getAlgorithm(),
                    (byte)op.getPadding(),
                    (byte)op.getDigest(),
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                    KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                    KMByteBlob.cast(data[PUB_KEY]).length()));
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.AES:
      case KMType.DES:
        if (op.getBlockMode() == KMType.GCM) {
          op.setAesGcmUpdateStart();
        }
        try {
          op.setOperation(
              seProvider.initSymmetricOperation(
                  (byte) op.getPurpose(),
                  (byte)op.getAlgorithm(),
                  (byte)op.getDigest(),
                  (byte)op.getPadding(),
                  (byte)op.getBlockMode(),
                  KMByteBlob.cast(data[SECRET]).getBuffer(),
                  KMByteBlob.cast(data[SECRET]).getStartOff(),
                  KMByteBlob.cast(data[SECRET]).length(),
                  KMByteBlob.cast(data[IV]).getBuffer(),
                  KMByteBlob.cast(data[IV]).getStartOff(),
                  KMByteBlob.cast(data[IV]).length(),
                  op.getMacLength()));
        } catch (CryptoException exception) {
          if (exception.getReason() == CryptoException.ILLEGAL_VALUE) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          } else if (exception.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
            KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
          }
        }
    }
  }

  private void beginSignVerifyOperation(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        try {
          if (op.getPurpose() == KMType.SIGN) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    (byte)op.getAlgorithm(),
                    (byte)op.getPadding(),
                    (byte)op.getDigest(),
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                    KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                    KMByteBlob.cast(data[PUB_KEY]).length()));
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.EC:
        try {
          if (op.getPurpose() == KMType.SIGN) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    (byte)op.getAlgorithm(),
                    (byte)op.getPadding(),
                    (byte)op.getDigest(),
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    null,
                    (short) 0,
                    (short) 0));
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException exp) {
          // Javacard does not support NO digest based signing.
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.HMAC:
        // As per Keymaster HAL documentation, the length of the Hmac output can
        // be decided by using TAG_MAC_LENGTH in Keyparameters. But there is no
        // such provision to control the length of the Hmac output using JavaCard
        // crypto APIs and the current implementation always returns 32 bytes
        // length of Hmac output. So to provide support to TAG_MAC_LENGTH
        // feature, we truncate the output signature to TAG_MAC_LENGTH and return
        // the truncated signature back to the caller. At the time of verfication
        // we again compute the signature of the plain text input, truncate it to
        // TAG_MAC_LENGTH and compare it with the input signature for
        // verification. So this is the reason we are using KMType.SIGN directly
        // instead of using op.getPurpose().
        try {
          op.setOperation(
              seProvider.initSymmetricOperation(
                  (byte) KMType.SIGN,
                  (byte)op.getAlgorithm(),
                  (byte)op.getDigest(),
                  (byte)op.getPadding(),
                  (byte)op.getBlockMode(),
                  KMByteBlob.cast(data[SECRET]).getBuffer(),
                  KMByteBlob.cast(data[SECRET]).getStartOff(),
                  KMByteBlob.cast(data[SECRET]).length(),
                  null,
                  (short) 0,
                  (short) 0,
                  (short) 0));
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
  }

  private void authorizeUserSecureIdAuthTimeout(KMOperationState op) {
    short authTime;
    // Authorize User Secure Id and Auth timeout
    if (KMTag.isPresent(data[HW_PARAMETERS], KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID)) {
      authTime =
          KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, data[HW_PARAMETERS]);
      if (authTime != KMType.INVALID_VALUE) {
        // check if hw token is empty - mac should not be empty.
        if (data[HW_TOKEN] == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_MAC_LENGTH);
        }
        authTime = KMIntegerTag.cast(authTime).getValue();
        // authenticate user
        authenticateUser();
        // set the one time auth
        op.setOneTimeAuthReqd(true);
        // set the authentication time stamp in operation state
        authTime = addIntegers(authTime, KMHardwareAuthToken.cast(data[HW_TOKEN]).getTimestamp());
        op.setAuthTime(
            KMInteger.cast(authTime).getBuffer(), KMInteger.cast(authTime).getStartOff());
        // auth time validation will happen in update or finish
        op.setAuthTimeoutValidated(false);
      } else {
        // auth per operation required
        op.setOneTimeAuthReqd(false);
        op.setAuthPerOperationReqd(true);
      }
    }
  }

  private void authenticateUser() {
    short id = KMHardwareAuthToken.cast(data[HW_TOKEN]).getUserId();
    if (KMInteger.cast(id).isZero()) {
      id = KMHardwareAuthToken.cast(data[HW_TOKEN]).getAuthenticatorId();
      if (KMInteger.cast(id).isZero()) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
    }
    // check user secure id
    if (!KMIntegerArrayTag.contains(KMType.USER_SECURE_ID, id, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
    // check auth type
    short authType    = KMEnumTag.getValue(KMType.USER_AUTH_TYPE, data[HW_PARAMETERS]);
    short authenticatorType = KMHardwareAuthToken.cast(data[HW_TOKEN]).getHwAuthenticatorType();
    authenticatorType = KMEnum.cast(authenticatorType).getVal();
    if (((byte) authenticatorType & (byte) authType) == 0) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
  }

  private boolean validateHwToken(short hwToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian
    short ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    short len;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return false;
    }
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
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
    ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    short key = repository.getComputedHmacKey();
    return seProvider.hmacVerify(
        KMByteBlob.cast(key).getBuffer(),
        KMByteBlob.cast(key).getStartOff(),
        KMByteBlob.cast(key).length(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
  }

  private short importKeyCmd(APDU apdu){
    short cmd = KMArray.instance((short) 6);
    // Arguments
    short params = KMKeyParameters.expAny();
    KMArray.cast(cmd).add((short) 0, params);
    KMArray.cast(cmd).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT));
    KMArray.cast(cmd).add((short) 2, KMByteBlob.exp());
    KMArray.cast(cmd).add((short) 3, KMByteBlob.exp()); //attest key
    KMArray.cast(cmd).add((short) 4, params); //attest key params
    KMArray.cast(cmd).add((short) 5, KMByteBlob.exp()); //issuer
    return receiveIncoming(apdu, cmd);
  }
  private void processImportKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = importKeyCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_PARAMETERS] = KMArray.cast(cmd).get((short) 0);
    short keyFmt = KMArray.cast(cmd).get((short) 1);
    data[IMPORTED_KEY_BLOB] = KMArray.cast(cmd).get((short) 2);
    data[ATTEST_KEY_BLOB] = KMArray.cast(cmd).get((short) 3);
    data[ATTEST_KEY_PARAMS] = KMArray.cast(cmd).get((short) 4);
    data[ATTEST_KEY_ISSUER] = KMArray.cast(cmd).get((short) 5);
    keyFmt = KMEnum.cast(keyFmt).getVal();

    data[CERTIFICATE] = KMArray.instance((short)0); //by default the cert is empty.
    data[ORIGIN] = KMType.IMPORTED;
    importKey(apdu, keyFmt, scratchPad);
  }

  private void validateImportKey(short params, short keyFmt){
    // Rollback protection not supported
    KMTag.assertAbsence(params, KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE, KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    // vts disallows importing EARLY_BOOT keys
    KMTag.assertAbsence(params, KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, KMError.EARLY_BOOT_ENDED);
    // Importing Bootloader only keys not supported.
    KMTag.assertAbsence(params, KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, KMError.INVALID_KEY_BLOB);
    // Algorithm must be present
    KMTag.assertPresence(params, KMType.ENUM_TAG, KMType.ALGORITHM, KMError.INVALID_ARGUMENT);
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, params);
    // key format must be raw if aes, des or hmac and pkcs8 for rsa and ec.
    if((alg == KMType.AES || alg == KMType.DES || alg == KMType.HMAC) && keyFmt != KMType.RAW ){
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    if((alg == KMType.RSA || alg == KMType.EC) && keyFmt != KMType.PKCS8){
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
  }

  private void importKey(APDU apdu, short keyFmt, byte[] scratchPad) {
    validateImportKey(data[KEY_PARAMETERS], keyFmt);
    // Check algorithm and dispatch to appropriate handler.
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    switch (alg) {
      case KMType.RSA:
        importRSAKey(scratchPad);
        break;
      case KMType.AES:
        importAESKey(scratchPad);
        break;
      case KMType.DES:
        importTDESKey(scratchPad);
        break;
      case KMType.HMAC:
        importHmacKey(scratchPad);
        break;
      case KMType.EC:
        importECKeys(scratchPad);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
    makeKeyCharacteristics(scratchPad);
    generateAttestation(scratchPad);
    createEncryptedKeyBlob(scratchPad);
    // prepare the response
    short resp = KMArray.instance((short) 4);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, data[KEY_BLOB]);
    KMArray.cast(resp).add((short) 2, data[KEY_CHARACTERISTICS]);
    KMArray.cast(resp).add((short) 3, data[CERTIFICATE]);
    sendOutgoing(apdu, resp);
  }

  private void importECKeys(byte[] scratchPad) {
    // Decode key material
    KMPKCS8Decoder pkcs8 = KMPKCS8Decoder.instance();
    short keyBlob = pkcs8.decodeEc(data[IMPORTED_KEY_BLOB]);
    data[PUB_KEY] = KMArray.cast(keyBlob).get((short) 0);
    data[SECRET] = KMArray.cast(keyBlob).get((short) 1);
    // initialize 256 bit p256 key for given private key and public key.
    short index = 0;
    // check whether the key size tag is present in key parameters.
    short keySize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keySize != KMType.INVALID_VALUE) {
      // As per NIST.SP.800-186 page 9,  secret for 256 curve should be between
      // 256-383
      if (((256 <= (short) (KMByteBlob.cast(data[SECRET]).length() * 8))
          && (383 >= (short) (KMByteBlob.cast(data[SECRET]).length() * 8)))
          ^ keySize == 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (keySize != 256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    } else {
      // add the key size to scratchPad
      keySize = KMInteger.uint_16((short) 256);
      keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keySize);
      Util.setShort(scratchPad, index, keySize);
      index += 2;
    }
    // check the curve if present in key parameters.
    short curve = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (curve != KMType.INVALID_VALUE) {
      // As per NIST.SP.800-186 page 9,  secret length for 256 curve should be between
      // 256-383
      if (((256 <= (short) (KMByteBlob.cast(data[SECRET]).length() * 8))
          && (383 >= (short) (KMByteBlob.cast(data[SECRET]).length() * 8)))
          ^ curve == KMType.P_256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (curve != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
      }
    } else {
      // add the curve to scratchPad
      curve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
      Util.setShort(scratchPad, index, curve);
      index += 2;
    }

    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.EC,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length());

    // add scratch pad to key parameters
    updateKeyParameters(scratchPad, index);
    // validate updated key parameters.
    validateECKeys();
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void importHmacKey(byte[] scratchPad) {
    // Get Key
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    // create HMAC key of up to 512 bit
    short index = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (!(keysize >= 64 && keysize <= 512 && keysize % 8 == 0)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      keysize = KMInteger.uint_16((short) (KMByteBlob.cast(data[SECRET]).length() * 8));
      short keySizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keySizeTag);
      index += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.HMAC,
        keysize,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate HMAC Key parameters
    validateHmacKey();
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importTDESKey(byte[] scratchPad) {
    // Decode Key Material
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    short index  = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (keysize != 168) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    } else {
      // add the key size to scratchPad
      keysize = KMInteger.uint_16((short) 168);
      short keysizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keysizeTag);
      index += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.DES,
        keysize,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());
    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate TDES Key parameters
    validateTDESKey();
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importAESKey(byte[] scratchPad) {
    // Get Key
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    // create 128 or 256 bit AES key
    short index = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (keysize != 128 && keysize != 256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    } else {
      // add the key size to scratchPad
      keysize = KMInteger.uint_16(KMByteBlob.cast(data[SECRET]).length());
      short keysizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keysizeTag);
      index += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.AES,
        keysize,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate AES Key parameters
    validateAESKey();
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importRSAKey(byte[] scratchPad) {
    // Decode key material
    KMPKCS8Decoder pkcs8 = KMPKCS8Decoder.instance();
    short keyblob = pkcs8.decodeRsa(data[IMPORTED_KEY_BLOB]);
    data[PUB_KEY] = KMArray.cast(keyblob).get((short) 0);
    short pubKeyExp = KMArray.cast(keyblob).get((short)1);
    data[SECRET] = KMArray.cast(keyblob).get((short) 2);
    if(F4.length != KMByteBlob.cast(pubKeyExp).length()){
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    if(Util.arrayCompare(F4, (short)0, KMByteBlob.cast(pubKeyExp).getBuffer(),
        KMByteBlob.cast(pubKeyExp).getStartOff(), (short)F4.length) != 0){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    short index = 0; // index in scratchPad for update parameters.
    // validate public exponent if present in key params - it must be 0x010001
    short len =
        KMIntegerTag.getValue(
            scratchPad,
            (short) 10, // using offset 10 as first 10 bytes reserved for update params
            KMType.ULONG_TAG,
            KMType.RSA_PUBLIC_EXPONENT,
            data[KEY_PARAMETERS]);
    if (len  != KMTag.INVALID_VALUE) {
      if (len != 4
          || Util.getShort(scratchPad, (short) 10) != 0x01
          || Util.getShort(scratchPad, (short) 12) != 0x01) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add public exponent to scratchPad
      Util.setShort(scratchPad, (short) 10, (short) 0x01);
      Util.setShort(scratchPad, (short) 12, (short) 0x01);
      pubKeyExp = KMInteger.uint_32(scratchPad, (short) 10);
      pubKeyExp =
          KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, pubKeyExp);
      Util.setShort(scratchPad, index, pubKeyExp);
      index += 2;
    }

    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (keysize != 2048
          || keysize != (short) (KMByteBlob.cast(data[SECRET]).length() * 8)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      keysize = KMInteger.uint_16((short) 2048);
      keysize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keysize);
      index += 2;
    }

    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.RSA,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate RSA Key parameters
    validateRSAKey(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void updateKeyParameters(byte[] newParams, short len) {
    if (len == 0) {
      return; // nothing to update
    }
    // Create Update Param array and copy current params
    short params = KMKeyParameters.cast(data[KEY_PARAMETERS]).getVals();
    len = (short) (KMArray.cast(params).length() + (short) (len / 2));
    short updatedParams = KMArray.instance(len); // update params

    len = KMArray.cast(params).length();
    short index  = 0;

    // copy the existing key parameters to updated array
    while (index < len) {
      short tag = KMArray.cast(params).get(index);
      KMArray.cast(updatedParams).add(index, tag);
      index++;
    }

    // copy new parameters to updated array
    len = KMArray.cast(updatedParams).length();
    short newParamIndex = 0; // index in ptrArr
    while (index < len) {
      short tag = Util.getShort(newParams, newParamIndex);
      KMArray.cast(updatedParams).add(index, tag);
      index++;
      newParamIndex += 2;
    }
    // replace with updated key parameters.
    data[KEY_PARAMETERS] = KMKeyParameters.instance(updatedParams);
  }

  private short initStrongBoxCmd(APDU apdu){
    short cmd = KMArray.instance((short) 3);
    KMArray.cast(cmd).add((short) 0, KMInteger.exp()); //OS version
    KMArray.cast(cmd).add((short) 1, KMInteger.exp()); //OS patch level
    KMArray.cast(cmd).add((short) 2, KMInteger.exp()); //Vendor patch level
    return receiveIncoming(apdu, cmd);
  }

  // This command is executed to set the boot parameters.
  // releaseAllOperations has to be called on every boot, so
  // it is called from inside initStrongBoxCmd. Later in future if
  // initStrongBoxCmd is removed, then make sure that releaseAllOperations
  // is moved to a place where it is called on every boot.
  private void processInitStrongBoxCmd(APDU apdu) {
    short cmd = initStrongBoxCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();

    short osVersion = KMArray.cast(cmd).get((short) 0);
    short osPatchLevel = KMArray.cast(cmd).get((short) 1);
    short vendorPatchLevel = KMArray.cast(cmd).get((short) 2);
    setOsVersion(osVersion);
    setOsPatchLevel(osPatchLevel);
    setVendorPatchLevel(vendorPatchLevel);
  }

  public void reboot(){
      // Clear the Computed SharedHmac and Hmac nonce from persistent memory.
      repository.clearComputedHmac();
      repository.clearHmacNonce();
      //Clear all the operation state.
      releaseAllOperations();
      // Hmac is cleared, so generate a new Hmac nonce.
      initHmacNonceAndSeed();
  }

  protected void initSystemBootParams(short osVersion,
      short osPatchLevel, short vendorPatchLevel, short bootPatchLevel){
      osVersion = KMInteger.uint_16(osVersion);
      osPatchLevel = KMInteger.uint_16(osPatchLevel);
      vendorPatchLevel = KMInteger.uint_16((short) vendorPatchLevel);
      setOsVersion(osVersion);
      setOsPatchLevel(osPatchLevel);
      setVendorPatchLevel(vendorPatchLevel);
  }

  protected void setOsVersion(short version){
    repository.setOsVersion(
        KMInteger.cast(version).getBuffer(),
        KMInteger.cast(version).getStartOff(),
        KMInteger.cast(version).length());
  }

  protected void setVendorPatchLevel(short patch){
    repository.setOsPatch(
        KMInteger.cast(patch).getBuffer(),
        KMInteger.cast(patch).getStartOff(),
        KMInteger.cast(patch).length());
  }

  protected void setOsPatchLevel(short patch){
    repository.setVendorPatchLevel(
        KMInteger.cast(patch).getBuffer(),
        KMInteger.cast(patch).getStartOff(),
        KMInteger.cast(patch).length());
  }

  private short generateKeyCmd(APDU apdu){
    short params = KMKeyParameters.expAny();
    short blob = KMByteBlob.exp();
    // Array of expected arguments
    short cmd = KMArray.instance((short) 4);
    KMArray.cast(cmd).add((short) 0, params); //key params
    KMArray.cast(cmd).add((short) 1, blob); //attest key
    KMArray.cast(cmd).add((short) 2, params); //attest key params
    KMArray.cast(cmd).add((short) 3, blob); //issuer
    return receiveIncoming(apdu, cmd);
  }

  private void processGenerateKey(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = generateKeyCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_PARAMETERS] = KMArray.cast(cmd).get((short) 0);
    data[ATTEST_KEY_BLOB] = KMArray.cast(cmd).get((short) 1);
    data[ATTEST_KEY_PARAMS] = KMArray.cast(cmd).get((short) 2);
    data[ATTEST_KEY_ISSUER] = KMArray.cast(cmd).get((short) 3);
    data[CERTIFICATE] = KMArray.instance((short)0); //by default the cert is empty.
    // ROLLBACK_RESISTANCE not supported.
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.BOOL_TAG,KMType.ROLLBACK_RESISTANCE, KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    // BOOTLOADER_ONLY keys not supported.
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, KMError.INVALID_KEY_BLOB);
    // Algorithm must be present
    KMTag.assertPresence(data[KEY_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM, KMError.INVALID_ARGUMENT);
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    // Check algorithm and dispatch to appropriate handler.
    switch (alg) {
      case KMType.RSA:
        generateRSAKey(scratchPad);
        break;
      case KMType.AES:
        generateAESKey(scratchPad);
        break;
      case KMType.DES:
        generateTDESKey(scratchPad);
        break;
      case KMType.HMAC:
        generateHmacKey(scratchPad);
        break;
      case KMType.EC:
        generateECKeys(scratchPad);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
    // create key blob and associated attestation.
    data[ORIGIN] = KMType.GENERATED;
    makeKeyCharacteristics(scratchPad);
    generateAttestation(scratchPad);
    createEncryptedKeyBlob(scratchPad);
    // prepare the response
    short resp = KMArray.instance((short) 4);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, data[KEY_BLOB]);
    KMArray.cast(resp).add((short) 2, data[KEY_CHARACTERISTICS]);
    KMArray.cast(resp).add((short) 3, data[CERTIFICATE]);
    sendOutgoing(apdu, resp);
  }

  private static void print(byte[] buf, short start, short length){
    StringBuilder sb = new StringBuilder(length * 2);
    for(short i = start; i < (start+length); i ++){
      sb.append(String.format("%02x", buf[i]));
    }
    System.out.println( sb.toString());
  }

  private  void generateAttestation(byte[] scratchPad){
    KMAttestationCert cert = makeCert(scratchPad);
    if(cert == null) {// No certificate
      data[CERTIFICATE] = KMArray.instance((short)0);
      return;
    }
    // Allocate memory
    short certData = KMByteBlob.instance(MAX_CERT_SIZE);
    cert.buffer(KMByteBlob.cast(certData).getBuffer(),
          KMByteBlob.cast(certData).getStartOff(),
          KMByteBlob.cast(certData).length());
    // Build the certificate - this will sign the cert
    cert.build();
    // Adjust the start and length of the certificate in the blob
    KMByteBlob.cast(certData).setStartOff(cert.getCertStart());
    KMByteBlob.cast(certData).setLength(cert.getCertLength());

    print(KMByteBlob.cast(certData).getBuffer(),
        KMByteBlob.cast(certData).getStartOff(),
        KMByteBlob.cast(certData).length());
    // Initialize the certificate as array of blob
    data[CERTIFICATE] = KMArray.instance((short)1);
    KMArray.cast(data[CERTIFICATE]).add((short)0, certData);
  }

  /**
   * 1) If attestation key is present and attestation challenge is absent then it is an error.
   * 2) If attestation key is absent and attestation challenge is present then it is an error as
   * factory provisioned attestation key is not supported.
   * 3) If both are present and issuer is absent or attest key purpose is not ATTEST_KEY then it is an error.
   * 4) If the generated/imported keys are RSA or EC then validity period must be specified.
   * Device Unique Attestation is not supported.
   */

  private static void validateRSAKey(byte[] scratchPad) {
    // Read key size
    if(!KMTag.isValidKeySize(data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    if(!KMTag.isValidPublicExponent(data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  // Generate key handlers
  private static void generateRSAKey(byte[] scratchPad) {
    // Validate RSA Key
    validateRSAKey(scratchPad);
    // Now generate 2048 bit RSA keypair for the given exponent
    short[] lengths = tmpVariables;
    data[PUB_KEY] = KMByteBlob.instance((short) 256);
    data[SECRET] = KMByteBlob.instance((short) 256);
    seProvider.createAsymmetricKey(
        KMType.RSA,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length(),
        lengths);

    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateAESKey() {
    // Read key size
    if(!KMTag.isValidKeySize(data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read Block mode - array of byte values
    if(KMTag.isPresent(data[KEY_PARAMETERS],KMType.ENUM_ARRAY_TAG,KMType.BLOCK_MODE)){
      short blockModes =
          KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, data[KEY_PARAMETERS]);
      // If it is a GCM mode
      if (KMEnumArrayTag.cast(blockModes).contains(KMType.GCM)){
        // Min mac length must be present
        KMTag.assertPresence(data[KEY_PARAMETERS],KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMError.MISSING_MIN_MAC_LENGTH);
        short macLength =
            KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
        macLength = KMIntegerTag.cast(macLength).getValue();
        // Validate the MIN_MAC_LENGTH for AES - should be multiple of 8, less then 128 bits
        // and greater the 96 bits
        if (KMInteger.cast(macLength).getSignificantShort() != 0
            || KMInteger.cast(macLength).getShort() > 128
            || KMInteger.cast(macLength).getShort() < 96
            || (KMInteger.cast(macLength).getShort() % 8) != 0) {
          KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
        }
      }
    }
  }

  private static void generateAESKey(byte[] scratchPad) {
    validateAESKey();
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    short len  =
        seProvider.createSymmetricKey(KMType.AES, keysize, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static void validateECKeys() {
    // Read key size
    short eccurve = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if(!KMTag.isValidKeySize(data[KEY_PARAMETERS])){
      if (eccurve == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      } else if (eccurve != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
  }

  private static void generateECKeys(byte[] scratchPad) {
    validateECKeys();
    short[] lengths = tmpVariables;
    seProvider.createAsymmetricKey(KMType.EC, scratchPad, (short) 0, (short) 128, scratchPad, (short) 128,
        (short) 128, lengths);
    data[PUB_KEY] = KMByteBlob.instance(scratchPad, (short) 128, lengths[1]);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, lengths[0]);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateTDESKey() {
    if(!KMTag.isValidKeySize(data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read Minimum Mac length - it must not be present
    KMTag.assertAbsence(data[KEY_PARAMETERS],KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,KMError.INVALID_TAG);
  }

  private static void generateTDESKey(byte[] scratchPad) {
    validateTDESKey();
    short len = seProvider.createSymmetricKey(KMType.DES, (short) 168, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static void validateHmacKey() {
    // If params does not contain any digest throw unsupported digest error.
    KMTag.assertPresence(data[KEY_PARAMETERS],KMType.ENUM_ARRAY_TAG,KMType.DIGEST,KMError.UNSUPPORTED_DIGEST);

    // check whether digest sizes are greater then or equal to min mac length.
    // Only SHA256 digest must be supported.
    if (KMEnumArrayTag.contains(KMType.DIGEST, KMType.DIGEST_NONE, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // Read Minimum Mac length
    KMTag.assertPresence(data[KEY_PARAMETERS],KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMError.MISSING_MAC_LENGTH);
    short minMacLength =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);

    if (((short) (minMacLength % 8) != 0)
        || minMacLength < (short) 64
        || minMacLength > (short) 256) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read Keysize
    if(!KMTag.isValidKeySize(data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private static void generateHmacKey(byte[] scratchPad) {
    validateHmacKey();
    short keysize = KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    // generate HMAC Key
    short len = seProvider.createSymmetricKey(KMType.HMAC, keysize, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void checkVersionAndPatchLevel(byte[] scratchPad) {
    short len =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_VERSION, data[HW_PARAMETERS]);
    if (len != KMType.INVALID_VALUE) {
      short provOsVersion = repository.getOsVersion();
      short status =
          KMInteger.unsignedByteArrayCompare(
              KMInteger.cast(provOsVersion).getBuffer(),
              KMInteger.cast(provOsVersion).getStartOff(),
              scratchPad,
              (short) 0,
              len);
      if (status == -1) {
        // If the key characteristics has os version > current os version
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else if (status == 1) {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
    len =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    if (len != KMType.INVALID_VALUE) {
      short osPatch = repository.getOsPatch();
      short status =
          KMInteger.unsignedByteArrayCompare(
              KMInteger.cast(osPatch).getBuffer(),
              KMInteger.cast(osPatch).getStartOff(),
              scratchPad,
              (short) 0,
              len);
      if (status == -1) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else if (status == 1) {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
  }
  protected short getBootPatchLevel(byte[] scratchPad){
    Util.arrayFillNonAtomic(scratchPad,(short)0, BOOT_PATCH_LVL_SIZE, (byte)0);
    short len = seProvider.getBootPatchLevel(scratchPad,(short)0);
    if(len != BOOT_PATCH_LVL_SIZE){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMInteger.uint_32(scratchPad, (short)0);
  }

  private void makeKeyCharacteristics(byte[] scratchPad) {
    short osVersion = repository.getOsVersion();
    short osPatch = repository.getOsPatch();
    short vendorPatch = repository.getVendorPatchLevel();
    short bootPatch = getBootPatchLevel(scratchPad);
    data[SB_PARAMETERS] = KMKeyParameters.makeSbEnforced(
        data[KEY_PARAMETERS], (byte) data[ORIGIN], osVersion, osPatch, vendorPatch, bootPatch, scratchPad);
    data[TEE_PARAMETERS] = KMKeyParameters.makeTeeEnforced(data[KEY_PARAMETERS],scratchPad);
    data[SW_PARAMETERS] = KMKeyParameters.makeKeystoreEnforced(data[KEY_PARAMETERS],scratchPad);
    data[HW_PARAMETERS] = KMKeyParameters.makeHwEnforced(data[SB_PARAMETERS], data[TEE_PARAMETERS]);
    data[KEY_CHARACTERISTICS] = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setStrongboxEnforced(data[SB_PARAMETERS]);
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setKeystoreEnforced(data[SW_PARAMETERS]);
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setTeeEnforced(data[TEE_PARAMETERS]);
  }

  private void createEncryptedKeyBlob(byte[] scratchPad) {
    // make root of trust blob
    data[ROT] = readROT(scratchPad);
    if (data[ROT] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // make hidden key params list
    data[HIDDEN_PARAMETERS] =
        KMKeyParameters.makeHidden(data[KEY_PARAMETERS], data[ROT], scratchPad);
    // make authorization data
    makeAuthData(scratchPad);
    // encrypt the secret and cryptographically attach that to authorization data
    encryptSecret(scratchPad);
    // create key blob array
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_SECRET, data[SECRET]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_AUTH_TAG, data[AUTH_TAG]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_NONCE, data[NONCE]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PARAMS, data[KEY_CHARACTERISTICS]);
    // allocate reclaimable memory.
    short buffer = repository.alloc((short) 1024);
    short keyBlob = encoder.encode(data[KEY_BLOB], repository.getHeap(), buffer);
    data[KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), buffer, keyBlob);
  }

  private void parseEncryptedKeyBlob(short keyBlob, short appId, short appData, byte[] scratchPad) {
    short rot = readROT(scratchPad);
    if (rot == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    try {
      short parsedBlob = decoder.decodeArray(keyBlob(),
              KMByteBlob.cast(keyBlob).getBuffer(),
              KMByteBlob.cast(keyBlob).getStartOff(),
              KMByteBlob.cast(keyBlob).length());
      if (KMArray.cast(parsedBlob).length() < 4) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      // initialize data
      data[SECRET] = KMArray.cast(parsedBlob).get(KEY_BLOB_SECRET);
      data[NONCE]= KMArray.cast(parsedBlob).get(KEY_BLOB_NONCE);
      data[AUTH_TAG] = KMArray.cast(parsedBlob).get(KEY_BLOB_AUTH_TAG);
      data[KEY_CHARACTERISTICS] = KMArray.cast(parsedBlob).get(KEY_BLOB_PARAMS);
      data[PUB_KEY] = KMType.INVALID_VALUE;
      if (KMArray.cast(parsedBlob).length() == 5) {
        data[PUB_KEY] = KMArray.cast(parsedBlob).get(KEY_BLOB_PUB_KEY);
      }
      data[TEE_PARAMETERS] = KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getTeeEnforced();
      data[SB_PARAMETERS] = KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getStrongboxEnforced();
      data[HW_PARAMETERS] = KMKeyParameters.makeHwEnforced(data[SB_PARAMETERS], data[TEE_PARAMETERS]);
      data[HIDDEN_PARAMETERS] = KMKeyParameters.makeHidden(appId, appData, rot, scratchPad);
      data[KEY_BLOB] = parsedBlob;
      // make auth data
      makeAuthData(scratchPad);
      // Decrypt Secret and verify auth tag
      decryptSecret(scratchPad);
    } catch (Exception e) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
  }

  // Read RoT
  public short readROT(byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256,(byte)0);
    short len = seProvider.getBootKey(scratchPad, (short)0);
    len += seProvider.getVerifiedBootHash(scratchPad, (short)len);
    short bootState = seProvider.getBootState();
    Util.setShort(scratchPad, (short)0,bootState);
    len +=2;
    if(seProvider.isDeviceBootLocked()){
      scratchPad[len] = (byte)1;
    }else{
      scratchPad[len] = (byte)0;
    }
    len++;
    return KMByteBlob.instance(scratchPad,(short)0,len);
  }

  private void decryptSecret(byte[] scratchPad) {
    // derive master key - stored in derivedKey
    short len = deriveKey(scratchPad);
        if (!seProvider.aesGCMDecrypt(
            KMByteBlob.cast(data[DERIVED_KEY]).getBuffer(),
            KMByteBlob.cast(data[DERIVED_KEY]).getStartOff(),
            KMByteBlob.cast(data[DERIVED_KEY]).length(),
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        scratchPad, (short) 0,
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length(),
        repository.getHeap(), data[AUTH_DATA], data[AUTH_DATA_LENGTH],
        KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
        KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
        KMByteBlob.cast(data[AUTH_TAG]).length())) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Copy the decrypted secret
    data[SECRET] =
        KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.cast(data[SECRET]).length());
  }

  private void encryptSecret(byte[] scratchPad) {
    // make nonce
    data[NONCE] = KMByteBlob.instance((short) AES_GCM_NONCE_LENGTH);
    data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(data[NONCE]).length());
    seProvider.newRandomNumber(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length());
    // derive master key - stored in derivedKey
    short len = deriveKey(scratchPad);
        len = seProvider.aesGCMEncrypt(
            KMByteBlob.cast(data[DERIVED_KEY]).getBuffer(),
            KMByteBlob.cast(data[DERIVED_KEY]).getStartOff(),
            KMByteBlob.cast(data[DERIVED_KEY]).length(),
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            scratchPad,
            (short) 0,
            KMByteBlob.cast(data[NONCE]).getBuffer(),
            KMByteBlob.cast(data[NONCE]).getStartOff(),
            KMByteBlob.cast(data[NONCE]).length(),
            repository.getHeap(),
            data[AUTH_DATA],
            data[AUTH_DATA_LENGTH],
            KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
            KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
            KMByteBlob.cast(data[AUTH_TAG]).length());

    if (len > 0 && len != KMByteBlob.cast(data[SECRET]).length()) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    data[SECRET] = KMByteBlob.instance(scratchPad, (short)0, len);
  }

  private static void makeAuthData(byte[] scratchPad) {
    short len =
        addPtrToAAD(KMKeyParameters.cast(data[HW_PARAMETERS]).getVals(), scratchPad, (short) 0);
    len +=
        addPtrToAAD(
            KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals(), scratchPad, len);
    short authData;
    if (KMArray.cast(data[KEY_BLOB]).length() == 5) {
      authData = KMArray.instance((short) (len + 1));
    } else {
      authData = KMArray.instance(len);
    }
    // convert scratch pad to KMArray
    short index = 0;
    short objPtr;
    while (index < len) {
      objPtr = Util.getShort(scratchPad, (short) (index * 2));
      KMArray.cast(authData).add(index, objPtr);
      index++;
    }
    //TODO change the code below - implicitly adds the pub key.
    if (KMArray.cast(data[KEY_BLOB]).length() == 5) {
      KMArray.cast(authData).add(index, data[PUB_KEY]);
    }
    data[AUTH_DATA] = repository.alloc(MAX_AUTH_DATA_SIZE);
    len = encoder.encode(authData, repository.getHeap(), data[AUTH_DATA]);
    data[AUTH_DATA_LENGTH] = len;
  }

  private static short addPtrToAAD(short dataArrPtr, byte[] aadBuf, short offset) {
    short index = (short) (offset * 2);
    short tagInd = 0;
    short tagPtr;
    short arrLen = KMArray.cast(dataArrPtr).length();
    while (tagInd < arrLen) {
      tagPtr = KMArray.cast(dataArrPtr).get(tagInd);
      Util.setShort(aadBuf, index, tagPtr);
      index += 2;
      tagInd++;
    }
    return tagInd;
  }

  private static short deriveKey(byte[] scratchPad) {
    short hiddenParams = KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals();
    short derivationData = repository.alloc(DERIVE_KEY_INPUT_SIZE);
    // generate derivation material from hidden parameters
    short len = encoder.encode(hiddenParams, repository.getHeap(), derivationData);
    if (DERIVE_KEY_INPUT_SIZE > len) {
      short start = (short)(derivationData+len);
      len = (short)(DERIVE_KEY_INPUT_SIZE - len);
      // Copy KeyCharacteristics in the remaining space of DERIVE_KEY_INPUT_SIZE
      // if the data[AUTH_DATA] length is less then DERIVE_KEY_INPUT_SIZE - len
      // then add complete key characteristics.
      if(data[AUTH_DATA_LENGTH] < len){
        len = data[AUTH_DATA_LENGTH];
      }
      Util.arrayCopyNonAtomic(repository.getHeap(), data[AUTH_DATA],
          repository.getHeap(), start, len);
    }
    // KeyDerivation:
    // 1. Do HMAC Sign, with below input parameters.
    //    Key - 128 bit master key
    //    Input data - HIDDEN_PARAMETERS + KeyCharacateristics
    //               - Truncate beyond 256 bytes.
    // 2. HMAC Sign generates an output of 32 bytes length.
    //    Consume only first 16 bytes as derived key.
    // Hmac sign.
    short signLen  = seProvider.hmacKDF(
        seProvider.getMasterKey(),
        repository.getHeap(),
        derivationData,
        DERIVE_KEY_INPUT_SIZE,
        scratchPad,
        (short) 0);
    if (signLen < 16) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    signLen = 16;
    // store the derived secret in data dictionary
    data[DERIVED_KEY] = KMByteBlob.instance(scratchPad, (short)0, signLen);
    //TODO do we need to return this len?
    return signLen;
  }

  protected static void sendError(APDU apdu, short err) {
    short resp = KMArray.instance((short)1);
    err = KMError.translate(err);
    short error = KMInteger.uint_16(err);
    KMArray.cast(resp).add((short)0, error);
    sendOutgoing(apdu, resp);
  }

  private short addIntegers(short num1, short num2) {
    short buf = repository.alloc((short) 24);
    byte[] scratchPad = repository.getHeap();
    Util.arrayFillNonAtomic(scratchPad, buf, (short) 24, (byte) 0);
    Util.arrayCopyNonAtomic(
        KMInteger.cast(num1).getBuffer(),
        KMInteger.cast(num1).getStartOff(),
        scratchPad,
        (short) (buf + 8 - KMInteger.cast(num1).length()),
        KMInteger.cast(num1).length());
    Util.arrayCopyNonAtomic(
        KMInteger.cast(num2).getBuffer(),
        KMInteger.cast(num2).getStartOff(),
        scratchPad,
        (short) (buf + 16 - KMInteger.cast(num2).length()),
        KMInteger.cast(num2).length());
    add(scratchPad, buf, (short) (buf + 8), (short) (buf + 16));
    return KMInteger.uint_64(scratchPad, (short) (buf + 16));
  }

  private void add(byte[] buf, short op1, short op2, short result) {
    byte index = 7;
    byte carry = 0;
    short tmp;
    while (index >= 0) {
      tmp = (short) (buf[(short) (op1 + index)] + buf[(short) (op2 + index)] + carry);
      carry = 0;
      if (tmp > 255) {
        carry = 1; // max unsigned byte value is 255
      }
      buf[(short) (result + index)] = (byte) (tmp & (byte) 0xFF);
      index--;
    }
  }

  public void powerReset() {
    //TODO handle power reset signal.
  }
}
