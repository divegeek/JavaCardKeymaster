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
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacardx.apdu.ExtendedLength;

/**
 * KMKeymasterApplet implements the javacard applet. It creates repository and other install time
 * objects. It also implements the keymaster state machine and handles javacard applet life cycle
 * events.
 */
// TODO Currently implementing ExtendedLength for ease of testing
//  - remove this in future.
public class KMKeymasterApplet extends Applet implements AppletEvent, ExtendedLength {
  // Constants.
  public static final byte AES_BLOCK_SIZE = 16;
  public static final short MAX_LENGTH = (short) 0x1000;
  private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
  private static final short KM_HAL_VERSION = (short) 0x4000;
  private static final short MAX_AUTH_DATA_SIZE = (short) 128;
  private static final short MAX_IO_LENGTH = 0x400;
  // Possible states of the applet.
  private static final byte ILLEGAL_STATE = 0x00;
  private static final byte INSTALL_STATE = 0x01;
  private static final byte FIRST_SELECT_STATE = 0x02;
  private static final byte ACTIVE_STATE = 0x03;
  private static final byte INACTIVE_STATE = 0x04;
  private static final byte UNINSTALLED_STATE = 0x05;
  // Commands
  private static final byte INS_GENERATE_KEY_CMD = 0x10;
  private static final byte INS_IMPORT_KEY_CMD = 0x11;
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = 0x12;
  private static final byte INS_EXPORT_KEY_CMD = 0x13;
  private static final byte INS_ATTEST_KEY_CMD = 0x14;
  private static final byte INS_UPGRADE_KEY_CMD = 0x15;
  private static final byte INS_DELETE_KEY_CMD = 0x16;
  private static final byte INS_DELETE_ALL_KEYS_CMD = 0x17;
  private static final byte INS_ADD_RNG_ENTROPY_CMD = 0x18;
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = 0x19;
  private static final byte INS_DESTROY_ATT_IDS_CMD = 0x1A;
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = 0x1B;
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = 0x1C;
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = 0x1D;
  private static final byte INS_GET_HW_INFO_CMD = 0x1E;
  private static final byte INS_BEGIN_OPERATION_CMD = 0x1F;
  private static final byte INS_UPDATE_OPERATION_CMD = 0x20;
  private static final byte INS_FINISH_OPERATION_CMD = 0x21;
  private static final byte INS_ABORT_OPERATION_CMD = 0x22;
  private static final byte INS_PROVISION_CMD = 0x23;
  private static final byte INS_SET_BOOT_PARAMS_CMD = 0x24;
  // Data Dictionary items
  public static final byte DATA_ARRAY_SIZE = 25;
  public static final byte TMP_VARIABLE_ARRAY_SIZE = 20;
  public static final byte UPDATE_PARAM_ARRAY_SIZE = 40;
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
  // AddRngEntropy
  private static final short MAX_SEED_SIZE = 2048;
  // Keyblob constants
  public static final byte KEY_BLOB_SECRET = 0;
  public static final byte KEY_BLOB_NONCE = 1;
  public static final byte KEY_BLOB_AUTH_TAG = 2;
  public static final byte KEY_BLOB_KEYCHAR = 3;
  public static final byte KEY_BLOB_PUB_KEY = 4;
  // AES GCM constants
  private static final byte AES_GCM_AUTH_TAG_LENGTH = 12;
  private static final byte AES_GCM_NONCE_LENGTH = 12;
  // Keymaster Applet attributes
  private static byte keymasterState = ILLEGAL_STATE;
  private static KMEncoder encoder;
  private static KMDecoder decoder;
  private static KMRepository repository;
  private static KMCryptoProvider cryptoProvider;
  private static byte[] buffer;
  private static short bufferLength;
  private static short bufferStartOffset;
  private static boolean provisionDone;
  private static boolean setBootParamsDone;
  private static short[] tmpVariables;
  private static short[] data;

  /** Registers this applet. */
  protected KMKeymasterApplet() {
    // TODO change this to make this compile time variation.
    cryptoProvider = new KMSimulator();
    keymasterState = KMKeymasterApplet.INSTALL_STATE;
    data = JCSystem.makeTransientShortArray((short) DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    tmpVariables = JCSystem.makeTransientShortArray((short) TMP_VARIABLE_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    repository = new KMRepository(cryptoProvider.getTrueRandomNumber((short) 256));
    KMType.initialize();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
    register();
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KMKeymasterApplet();
  }

  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
    repository.onSelect();
    if (keymasterState == KMKeymasterApplet.INSTALL_STATE) {
      keymasterState = KMKeymasterApplet.FIRST_SELECT_STATE;
    } else if (keymasterState == KMKeymasterApplet.INACTIVE_STATE) {
      keymasterState = KMKeymasterApplet.ACTIVE_STATE;
    } else {
      return false;
    }
    return true;
  }

  /** De-selects this applet. */
  @Override
  public void deselect() {
    repository.onDeselect();
    if (keymasterState == KMKeymasterApplet.ACTIVE_STATE) {
      keymasterState = KMKeymasterApplet.INACTIVE_STATE;
    }
  }

  /** Uninstalls the applet after cleaning the repository. */
  @Override
  public void uninstall() {
    repository.onUninstall();
    if (keymasterState != KMKeymasterApplet.UNINSTALLED_STATE) {
      keymasterState = KMKeymasterApplet.UNINSTALLED_STATE;
    }
  }

  /**
   * Processes an incoming APDU and handles it using command objects.
   *
   * @param apdu the incoming APDU
   */
  @Override
  public void process(APDU apdu) {
    repository.onProcess();
    // Verify whether applet is in correct state.
    if ((keymasterState != KMKeymasterApplet.ACTIVE_STATE)
        && (keymasterState != KMKeymasterApplet.FIRST_SELECT_STATE)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // If this is select applet apdu which is selecting this applet then return
    if (apdu.isISOInterindustryCLA()) {
      if (selectingApplet()) {
        return;
      }
    }
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
    byte apduIns = apduBuffer[ISO7816.OFFSET_INS];
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
    buffer = repository.getHeap();
    bufferStartOffset = repository.alloc(MAX_IO_LENGTH);
    // Validate APDU Header.
    if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    } else if (P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Validate whether INS can be supported
    if (!(apduIns >= INS_GENERATE_KEY_CMD && apduIns <= INS_SET_BOOT_PARAMS_CMD)) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    // Validate if INS is provision command if applet is in FIRST_SELECT_STATE.
    if (keymasterState == KMKeymasterApplet.FIRST_SELECT_STATE) {
      if ((apduIns != INS_PROVISION_CMD) && (apduIns != INS_SET_BOOT_PARAMS_CMD)) {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
      if (apduIns == INS_PROVISION_CMD && provisionDone) {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
      if (apduIns == INS_SET_BOOT_PARAMS_CMD && setBootParamsDone) {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
    }
    // Process the apdu
    try {
      // Handle the command
      switch (apduIns) {
        case INS_GENERATE_KEY_CMD:
          processGenerateKey(apdu);
          break;
        case INS_IMPORT_KEY_CMD:
          processImportKeyCmd(apdu);
          break;
        case INS_IMPORT_WRAPPED_KEY_CMD:
          processImportWrappedKeyCmd(apdu);
          break;
        case INS_EXPORT_KEY_CMD:
          processExportKeyCmd(apdu);
          break;
        case INS_ATTEST_KEY_CMD:
          processAttestKeyCmd(apdu);
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
          processVerifyAuthenticationCmd(apdu);
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
        case INS_PROVISION_CMD:
          processProvisionCmd(apdu);
          break;
        case INS_SET_BOOT_PARAMS_CMD:
          processSetBootParamsCmd(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } catch (KMException exception) {
      sendError(apdu, exception.reason);
      exception.clear();
    } finally {
      repository.clean();
    }
  }

  /** Sends a response, may be extended response, as requested by the command. */
  public static void sendOutgoing(APDU apdu) {
    if (bufferLength > MAX_IO_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Send data
    apdu.setOutgoing();
    // short currentBlockSize = apdu.getOutBlockSize();
    apdu.setOutgoingLength(bufferLength);
    apdu.sendBytesLong(buffer, bufferStartOffset, bufferLength);
  }

  /** Receives data, which can be extended data, as requested by the command instance. */
  public static void receiveIncoming(APDU apdu) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    bufferLength = apdu.getIncomingLength();
    short index = bufferStartOffset;
    // Receive data
    if (bufferLength > MAX_IO_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    while (recvLen > 0 && ((short) (index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
  }

  private void processProvisionCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormat = KMEnum.instance(KMType.KEY_FORMAT);
    short keyBlob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormat);
    KMArray.cast(argsProto).add((short) 2, keyBlob);
    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // key params should have os patch, os version and verified root of trust

    // TODO execute the function
    // Change the state to ACTIVE
    if (keymasterState == KMKeymasterApplet.FIRST_SELECT_STATE) {
      provisionDone = true;
      if (setBootParamsDone) {
        keymasterState = KMKeymasterApplet.ACTIVE_STATE;
      }
    }
  }

  private void processGetHwInfoCmd(APDU apdu) {
    // No arguments expected
    final byte[] JavacardKeymasterDevice = {
      0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74,
      0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
    };
    final byte[] Google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

    // Make the response
    short respPtr = KMArray.instance((short) 3);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 1,
        KMByteBlob.instance(
            JavacardKeymasterDevice, (short) 0, (short) JavacardKeymasterDevice.length));
    resp.add((short) 2, KMByteBlob.instance(Google, (short) 0, (short) Google.length));
    // Encode the response - actual bufferLength is 86
    bufferLength = encoder.encode(respPtr, buffer, bufferStartOffset);
    // send buffer to master
    sendOutgoing(apdu);
  }

  private void processAddRngEntropyCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
    // Argument 1
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, KMByteBlob.exp());
    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // Process
    KMByteBlob blob = KMByteBlob.cast(KMArray.cast(args).get((short) 0));
    // Maximum 2KiB of seed is allowed.
    if (blob.length() > MAX_SEED_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    cryptoProvider.addRngEntropy(blob.getBuffer(), blob.getStartOff(), blob.length());
  }

  private void processAbortOperationCmd(APDU apdu) {}

  private void processFinishOperationCmd(APDU apdu) {}

  private void processUpdateOperationCmd(APDU apdu) {}

  private void processBeginOperationCmd(APDU apdu) {}

  private void processGetKeyCharacteristicsCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp());
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp());
    KMArray.cast(tmpVariables[0]).add((short) 2, KMByteBlob.exp());
    // Decode the arguments
    tmpVariables[0] = decoder.decode(tmpVariables[0], buffer, bufferStartOffset, bufferLength);
    data[KEY_BLOB] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[APP_ID] = KMArray.cast(tmpVariables[0]).get((short) 1);
    data[APP_DATA] = KMArray.cast(tmpVariables[0]).get((short) 2);
    if(KMByteBlob.cast(data[APP_ID]).length() == 2){
      if(Util.getShort(repository.getHeap(),KMByteBlob.cast(data[APP_ID]).getStartOff()) == KMType.INVALID_VALUE){
        data[APP_ID] = KMType.INVALID_VALUE;
      }
    }
    if(KMByteBlob.cast(data[APP_DATA]).length() == 2){
      if(Util.getShort(repository.getHeap(),KMByteBlob.cast(data[APP_DATA]).getStartOff()) == KMType.INVALID_VALUE){
        data[APP_DATA] = KMType.INVALID_VALUE;
      }
    }
    // Parse Key Blob
    parseEncryptedKeyBlob(scratchPad);
    // Check Version and Patch Level
    checkVersionAndPatchLevel(scratchPad);
    // make response.
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_CHARACTERISTICS]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void processGetHmacSharingParamCmd(APDU apdu) {}

  private void processVerifyAuthenticationCmd(APDU apdu) {}

  private void processDestroyAttIdsCmd(APDU apdu) {}

  private void processComputeSharedHmacCmd(APDU apdu) {}

  private void processDeleteAllKeysCmd(APDU apdu) {}

  private void processDeleteKeyCmd(APDU apdu) {}

  private void processUpgradeKeyCmd(APDU apdu) {}

  private void processAttestKeyCmd(APDU apdu) {}

  private void processExportKeyCmd(APDU apdu) {}

  private void processImportWrappedKeyCmd(APDU apdu) {}

  private void processImportKeyCmd(APDU apdu) {
    if (repository.keyBlobCount > repository.MAX_BLOB_STORAGE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short)3);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT));
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp());
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    tmpVariables[3] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[IMPORTED_KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 2);
    // Keyformat must be RAW format - X509 and PKCS8 not implemented.
    tmpVariables[3] = KMEnum.cast(tmpVariables[3]).getVal();
    if (tmpVariables[3] != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Check algorithm and dispatch to appropriate handler.
    switch (tmpVariables[3]) {
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
    // create key blob
    data[ORIGIN] = KMType.IMPORTED;
    createEncryptedKeyBlob(scratchPad);
    // persist auth tag for rollback resistance.
    repository.persistAuthTag(data[AUTH_TAG]);
    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_BLOB]);
    KMArray.cast(tmpVariables[0]).add((short) 2, data[KEY_CHARACTERISTICS]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void importECKeys(byte[] scratchPad) {
    // Decode key material
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp()); // public key
    KMArray.cast(tmpVariables[0]).add((short) 2, KMEnumTag.exp()); // curve
    tmpVariables[0] =
      decoder.decode(
        tmpVariables[0],
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[PUB_KEY] = KMArray.cast(tmpVariables[0]).get((short) 1);
    tmpVariables[1] = KMArray.cast(tmpVariables[0]).get((short) 2);
    tmpVariables[1] = KMEnumTag.cast(tmpVariables[1]).getValue();
    // curve must be P_256
    if(tmpVariables[1] != KMType.P_256){
      KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
    }
    // initialize 256 bit p256 key for given private key and public key.
    ECPrivateKey ecKey =
      cryptoProvider.createEcPrivateKey(
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length(),
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length()
        );
    tmpVariables[4] = 0; // index for update list in scratchPad
    // check whether the keysize tag is present in key parameters.
    tmpVariables[2] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    }else{
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short)256);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG,KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[6]);
      tmpVariables[4] +=2;
    }
    // check the curve if present in key parameters.
    tmpVariables[3] = KMEnumTag.getValue(KMType.ECCURVE,data[KEY_PARAMETERS]);
    if(tmpVariables[3] != KMType.INVALID_VALUE){
      if(tmpVariables[3] != tmpVariables[1]){
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    }else{
      // add the curve to scratchPad
      tmpVariables[5] = KMEnumTag.instance(KMType.ECCURVE,KMType.P_256);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[5]);
      tmpVariables[4] +=2;
    }
    // add scratch pad to key parameters
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate updated key parameters.
    validateECKeys(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short)5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void importHmacKey(byte[] scratchPad) {
    // Get Key
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    tmpVariables[0] =
      decoder.decode(
        tmpVariables[0],
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    // create HMAC key of up to 512 bit
    HMACKey hmacKey = cryptoProvider.createHMACKey(
      KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length()
    );
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (!(tmpVariables[2] > 64 && tmpVariables[2] <= 512 && tmpVariables[2]%8 ==0)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    }else{
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16(KMByteBlob.cast(data[SECRET]).length());
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG,KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[6]);
      tmpVariables[4] +=2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate HMAC Key parameters
    validateHmacKey(scratchPad);

    data[KEY_BLOB] = KMArray.instance((short)4);
  }

  private void importTDESKey(byte[] scratchPad) {
    // Decode Key Material
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    tmpVariables[0] =
      decoder.decode(
        tmpVariables[0],
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    DESKey desKey = cryptoProvider.createTDESKey(
      KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length()
    );
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 168) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    }else{
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short)168);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG,KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[6]);
      tmpVariables[4] +=2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate TDES Key parameters
    validateTDESKey(scratchPad);

    data[KEY_BLOB] = KMArray.instance((short)4);
  }

  private void importAESKey(byte[] scratchPad) {
    // Get Key
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    tmpVariables[0] =
      decoder.decode(
        tmpVariables[0],
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
        KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    // create 128 or 256 bit AES key
    AESKey aesKey = cryptoProvider.createAESKey(
      KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length()
    );
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 128 && tmpVariables[2] != 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    }else{
      // add the key size to scratch pad
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16(KMByteBlob.cast(data[SECRET]).length());
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG,KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[6]);
      tmpVariables[4] +=2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate AES Key parameters
    validateAESKey(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short)4);
  }

  private void importRSAKey(byte[] scratchPad) {
    // Decode key material
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret = private exponent
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp()); // modulus
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[PUB_KEY] = KMArray.cast(tmpVariables[0]).get((short) 1);
    tmpVariables[4] = 0; // index in scratchPad for update parameters.
    // validate public exponent if present in key params - it must be 0x010001
    tmpVariables[2] =
      KMIntegerTag.getValue(
        scratchPad,
        (short) 10, // using offset 10 as first 10 bytes reserved for update params
        KMType.ULONG_TAG,
        KMType.RSA_PUBLIC_EXPONENT,
        data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMTag.INVALID_VALUE) {
      if ( tmpVariables[2] != 4 || Util.getShort(scratchPad, (short) 10) != 0x01
        || Util.getShort(scratchPad, (short) 12) != 0x01) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
    }else{
      // add public exponent to scratchPad
      Util.setShort(scratchPad,(short)10, (short)0x01);
      Util.setShort(scratchPad,(short)12, (short)0x01);
      tmpVariables[5] = KMInteger.uint_32(scratchPad,(short)10);
      tmpVariables[6] = KMIntegerTag.instance(KMType.ULONG_TAG,KMType.RSA_PUBLIC_EXPONENT, tmpVariables[5]);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[6]);
      tmpVariables[4] +=2;
    }

    // initialize 2048 bit private key for given private exp and modulus.
    RSAPrivateKey rsaKey =
      cryptoProvider.createRsaPrivateKey(
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length(),
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length()
      );
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 2048) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    }else{
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short)2048);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG,KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad,tmpVariables[4],tmpVariables[6]);
      tmpVariables[4] +=2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate RSA Key parameters
    validateRSAKey(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short)5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void updateKeyParameters(byte[] ptrArr, short len){
    if(len == 0) {
      return; // nothing to update
    }
    // Create Update Param array and copy current params
    tmpVariables[0] = KMKeyParameters.cast(data[KEY_PARAMETERS]).getVals();
    tmpVariables[1] = (short)(KMArray.cast(tmpVariables[0]).length()+(short)(len/2));
    tmpVariables[1] = KMArray.instance(tmpVariables[1]);// update params
    tmpVariables[2] = KMArray.cast(tmpVariables[0]).length();
    tmpVariables[3] = 0;
    // copy the existing key parameters to updated array
    while(tmpVariables[3] < tmpVariables[2]){
      tmpVariables[4] = KMArray.cast(tmpVariables[0]).get(tmpVariables[3]);
      KMArray.cast(tmpVariables[1]).add(tmpVariables[3],tmpVariables[4]);
      tmpVariables[3]++;
    }
    // copy new parameters to updated array
    tmpVariables[2] = KMArray.cast(tmpVariables[1]).length();
    tmpVariables[5] = 0; // index in ptrArr
    while(tmpVariables[3] < tmpVariables[2]){
      tmpVariables[4] = Util.getShort(ptrArr,tmpVariables[5]);
      KMArray.cast(tmpVariables[1]).add(tmpVariables[3],tmpVariables[4]);
      tmpVariables[3]++;
      tmpVariables[5] +=2;
    }
    // replace with updated key parameters.
    data[KEY_PARAMETERS] = KMKeyParameters.instance(tmpVariables[1]);
  }

  // TODO Add Signature verification.
  private void processSetBootParamsCmd(APDU apdu) {
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
    // Argument 1 OS Version
    // short osVersionExp = KMIntegerTag.exp(KMType.UINT_TAG);
    tmpVariables[0] = KMIntegerTag.exp(KMType.UINT_TAG);
    // Argument 2 OS Patch level
    // short osPatchExp = KMIntegerTag.exp(KMType.UINT_TAG);
    tmpVariables[1] = KMIntegerTag.exp(KMType.UINT_TAG);
    // Argument 3 Verified Boot Key
    // short bootKeyExp = KMByteBlob.exp();
    tmpVariables[2] = KMByteBlob.exp();
    // Argument 4 Verified Boot Hash
    // short bootHashExp = KMByteBlob.exp();
    tmpVariables[3] = KMByteBlob.exp();
    // Argument 5 Verified Boot State
    // short bootStateExp = KMEnum.instance(KMType.VERIFIED_BOOT_STATE);
    tmpVariables[4] = KMEnum.instance(KMType.VERIFIED_BOOT_STATE);
    // Argument 6 Device Locked
    // short deviceLockedExp = KMEnum.instance(KMType.DEVICE_LOCKED);
    tmpVariables[5] = KMEnum.instance(KMType.DEVICE_LOCKED);
    // Array of expected arguments
    short argsProto = KMArray.instance((short) 6);
    KMArray.cast(argsProto).add((short) 0, tmpVariables[0]);
    KMArray.cast(argsProto).add((short) 1, tmpVariables[1]);
    KMArray.cast(argsProto).add((short) 2, tmpVariables[2]);
    KMArray.cast(argsProto).add((short) 3, tmpVariables[3]);
    KMArray.cast(argsProto).add((short) 4, tmpVariables[4]);
    KMArray.cast(argsProto).add((short) 5, tmpVariables[5]);
    // Decode the arguments
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // short osVersionTagPtr = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    // short osPatchTagPtr = KMArray.cast(args).get((short) 1);
    tmpVariables[1] = KMArray.cast(args).get((short) 1);
    // short verifiedBootKeyPtr = KMArray.cast(args).get((short) 2);
    tmpVariables[2] = KMArray.cast(args).get((short) 2);
    // short verifiedBootHashPtr = KMArray.cast(args).get((short) 3);
    tmpVariables[3] = KMArray.cast(args).get((short) 3);
    // short verifiedBootStatePtr = KMArray.cast(args).get((short) 4);
    tmpVariables[4] = KMArray.cast(args).get((short) 4);
    // short deviceLockedPtr = KMArray.cast(args).get((short) 5);
    tmpVariables[5] = KMArray.cast(args).get((short) 5);
    if (KMByteBlob.cast(tmpVariables[2]).length() > repository.BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (KMByteBlob.cast(tmpVariables[3]).length() > repository.BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Begin transaction
    JCSystem.beginTransaction();
    short valPtr = KMIntegerTag.cast(tmpVariables[0]).getValue();
    KMInteger.cast(valPtr).getValue(repository.osVersion, (short) 0, (short) 4);
    valPtr = KMIntegerTag.cast(tmpVariables[1]).getValue();
    KMInteger.cast(valPtr).getValue(repository.osPatch, (short) 0, (short) 4);
    repository.actualBootKeyLength = KMByteBlob.cast(tmpVariables[2]).length();
    KMByteBlob.cast(tmpVariables[2])
        .getValue(repository.verifiedBootKey, (short) 0, repository.actualBootKeyLength);
    repository.actualBootHashLength = KMByteBlob.cast(tmpVariables[3]).length();
    KMByteBlob.cast(tmpVariables[3])
        .getValue(repository.verifiedBootHash, (short) 0, repository.actualBootHashLength);
    byte enumVal = KMEnum.cast(tmpVariables[4]).getVal();
    if (enumVal == KMTag.SELF_SIGNED_BOOT) {
      repository.selfSignedBootFlag = true;
      repository.verifiedBootFlag = false;
    } else {
      repository.selfSignedBootFlag = false;
      repository.verifiedBootFlag = true;
    }
    enumVal = KMEnum.cast(tmpVariables[5]).getVal();
    if (enumVal == KMType.DEVICE_LOCKED_TRUE) {
      repository.deviceLockedFlag = true;
    } else {
      repository.deviceLockedFlag = false;
    }
    if (keymasterState == KMKeymasterApplet.FIRST_SELECT_STATE) {
      setBootParamsDone = true;
      if (provisionDone) {
        keymasterState = KMKeymasterApplet.ACTIVE_STATE;
      }
    }
    // end transaction
    JCSystem.commitTransaction();
  }

  private static void processGenerateKey(APDU apdu) {
    // before generating key, check whether max count reached
    if (repository.keyBlobCount > repository.MAX_BLOB_STORAGE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Argument
    tmpVariables[0] = KMKeyParameters.exp();
    // Array of expected arguments
    tmpVariables[1] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[0]);
    // Decode the argument
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Check algorithm and dispatch to appropriate handler.
    switch (tmpVariables[3]) {
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
    // create key blob
    data[ORIGIN] = KMType.GENERATED;
    createEncryptedKeyBlob(scratchPad);
    // persist auth tag for rollback resistance.
    repository.persistAuthTag(data[AUTH_TAG]);
    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_BLOB]);
    KMArray.cast(tmpVariables[0]).add((short) 2, data[KEY_CHARACTERISTICS]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private static void validateRSAKey(byte[] scratchPad){
    // Read key size
    tmpVariables[0] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (tmpVariables[0] != 2048) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read public exponent into scratch pad
    tmpVariables[1] =
      KMIntegerTag.getValue(
        scratchPad,
        (short) 0,
        KMType.ULONG_TAG,
        KMType.RSA_PUBLIC_EXPONENT,
        data[KEY_PARAMETERS]);
    if ((tmpVariables[1] == KMTag.INVALID_VALUE) || (tmpVariables[1] != 4)) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Only exponent support is F4 - 65537 which is 0x00010001.
    if (Util.getShort(scratchPad, (short) 0) != 0x01
      || Util.getShort(scratchPad, (short) 2) != 0x01) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  // Generate key handlers
  private static void generateRSAKey(byte[] scratchPad) {
    // Validate RSA Key
    validateRSAKey(scratchPad);
    // Now generate 2048 bit RSA keypair for the given exponent
    KeyPair rsaKey = cryptoProvider.createRsaKeyPair();
    // store the pub exponent
    data[RSA_PUB_EXPONENT] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[1]);
    // extract modulus
    tmpVariables[0] = ((RSAPrivateKey) rsaKey.getPrivate()).getModulus(scratchPad, (short) 0);
    data[PUB_KEY] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    // extract private key
    tmpVariables[0] = ((RSAPrivateKey) rsaKey.getPrivate()).getExponent(scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }
  private static void validateAESKey(byte[] scratchPad){
    // Read key size
    tmpVariables[0] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if ((tmpVariables[0] != 256) && (tmpVariables[0] != 128)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read Block mode - array of byte values
    tmpVariables[1] =
      KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] != KMTag.INVALID_VALUE) { // block mode specified
      tmpVariables[2] = KMEnumArrayTag.cast(tmpVariables[0]).getValues(); // byte blob
      tmpVariables[3] = KMByteBlob.cast(tmpVariables[2]).length(); // length
      tmpVariables[4] = 0; // index
      tmpVariables[5] = AES_BLOCK_SIZE; // block size
      tmpVariables[5] =
        KMKeyParameters.findTag(
          KMType.UINT_TAG,
          KMType.MIN_MAC_LENGTH,
          data[KEY_PARAMETERS]); // Find Minimum Mac length
      while (tmpVariables[4] < tmpVariables[3]) { // for each value in block mode array
        if (KMByteBlob.cast(tmpVariables[2]).get(tmpVariables[4]) == KMType.GCM) { // if GCM mode
          if (tmpVariables[5] == KMTag.INVALID_VALUE) { // minimum mac length must be specified
            KMException.throwIt(KMError.MISSING_MAC_LENGTH);
          }
          tmpVariables[6] = KMInteger.cast(KMIntegerTag.cast(tmpVariables[5]).getValue()).getByte();
          if (tmpVariables[6] < 12 || tmpVariables[6] > 16) {
            KMException.throwIt(KMError.UNSUPPORTED_MAC_LENGTH);
          }
          tmpVariables[6] = 12; // simulator supports only 12 bits tag for GCM.
        } else { // if not GCM mode
          if (tmpVariables[5] != KMTag.INVALID_VALUE) { // no mac length should be specified
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }
        }
        tmpVariables[4]++;
      }
    }
  }
  private static void generateAESKey(byte[] scratchPad) {
    validateAESKey(scratchPad);
    AESKey aesKey = cryptoProvider.createAESKey(tmpVariables[0]);
    tmpVariables[0] = aesKey.getKey(scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static  void validateECKeys(byte[] scratchPad){
    // Read key size
    tmpVariables[0] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (tmpVariables[0] != 256) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read EC_CURVE
    tmpVariables[1] = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] != KMType.INVALID_VALUE) {
      if (tmpVariables[1] != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
  }

  private static void generateECKeys(byte[] scratchPad) {
    validateECKeys(scratchPad);
    KeyPair ecKey = cryptoProvider.createECKeyPair();
    tmpVariables[5] = ((ECPublicKey) ecKey.getPublic()).getW(scratchPad, (short) 0);
    data[PUB_KEY] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[5]);
    tmpVariables[5] = ((ECPrivateKey) ecKey.getPrivate()).getS(scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[5]);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateTDESKey(byte[] scratchPad){
    // Read Minimum Mac length - it must not be present
    tmpVariables[0] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    // Read keysize
    tmpVariables[1] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (tmpVariables[1] != 168) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }
  private static void generateTDESKey(byte[] scratchPad) {
    validateTDESKey(scratchPad);
    DESKey desKey = cryptoProvider.createTDESKey();
    tmpVariables[0] = desKey.getKey(scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static void validateHmacKey(byte[] scratchPad){
    // Read Minimum Mac length
    tmpVariables[0] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
    }
    if (((short) (tmpVariables[0] % 8) != 0) || (tmpVariables[0] < (short) 64)) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read keysize
    tmpVariables[1] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if ((tmpVariables[1] > 512) || ((short) (tmpVariables[1] % 8) != 0)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read digests
    tmpVariables[2] =
      KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (tmpVariables[2] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[3] = KMEnumArrayTag.cast(tmpVariables[2]).getValues();
    tmpVariables[4] = KMByteBlob.cast(tmpVariables[3]).length();
    tmpVariables[5] = 0;
    // check whether digest sizes are greater then or equal to min mac length.
    while (tmpVariables[5] < tmpVariables[4]) {
      tmpVariables[6] = KMByteBlob.cast(tmpVariables[3]).get(tmpVariables[5]);
      switch (tmpVariables[6]) {
        case KMType.DIGEST_NONE:
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
          break;
        case KMType.MD5:
          tmpVariables[7] = 128;
          break;
        case KMType.SHA1:
          tmpVariables[7] = 160;
          break;
        case KMType.SHA2_224:
          tmpVariables[7] = 224;
          break;
        case KMType.SHA2_256:
          tmpVariables[7] = 256;
          break;
        case KMType.SHA2_384:
          tmpVariables[7] = 384;
          break;
        case KMType.SHA2_512:
          tmpVariables[7] = 512;
          break;
        default:
          tmpVariables[7] = 0;
          break;
      }
      if (tmpVariables[7] == 0) {
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
      }
      if (tmpVariables[0] > tmpVariables[7]) {
        KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
      }
      tmpVariables[5]++;
    }
  }
  private static void generateHmacKey(byte[] scratchPad) {
    validateHmacKey(scratchPad);
    // Read Minimum Mac length
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
    }
    if (((short) (tmpVariables[0] % 8) != 0) || (tmpVariables[0] < (short) 64)) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read keysize
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if ((tmpVariables[1] > 512) || ((short) (tmpVariables[1] % 8) != 0)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read digests
    tmpVariables[2] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (tmpVariables[2] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[3] = KMEnumArrayTag.cast(tmpVariables[2]).getValues();
    tmpVariables[4] = KMByteBlob.cast(tmpVariables[3]).length();
    tmpVariables[5] = 0;
    // check whether digest sizes are greater then or equal to min mac length.
    while (tmpVariables[5] < tmpVariables[4]) {
      tmpVariables[6] = KMByteBlob.cast(tmpVariables[3]).get(tmpVariables[5]);
      switch (tmpVariables[6]) {
        case KMType.DIGEST_NONE:
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
          break;
        case KMType.MD5:
          tmpVariables[7] = 128;
          break;
        case KMType.SHA1:
          tmpVariables[7] = 160;
          break;
        case KMType.SHA2_224:
          tmpVariables[7] = 224;
          break;
        case KMType.SHA2_256:
          tmpVariables[7] = 256;
          break;
        case KMType.SHA2_384:
          tmpVariables[7] = 384;
          break;
        case KMType.SHA2_512:
          tmpVariables[7] = 512;
          break;
        default:
          tmpVariables[7] = 0;
          break;
      }
      if (tmpVariables[7] == 0) {
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
      }
      if (tmpVariables[0] > tmpVariables[7]) {
        KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
      }
      tmpVariables[5]++;
    }
    // generate HMAC Key
    HMACKey hmacKey = cryptoProvider.createHMACKey(tmpVariables[1]);
    tmpVariables[0] = hmacKey.getKey(scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void checkVersionAndPatchLevel(byte[] scratchPad) {
    tmpVariables[0] =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_VERSION, data[HW_PARAMETERS]);
    if ((tmpVariables[0] != KMType.INVALID_VALUE)
        && (Util.arrayCompare(
                repository.osVersion, (short) 0, scratchPad, (short) 0, tmpVariables[0])
            != 0)) {
      if (Util.arrayCompare(repository.osVersion, (short) 0, scratchPad, (short) 0, tmpVariables[0])
          == -1) {
        // If the key characteristics has os version > current os version
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
    tmpVariables[0] =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    if ((tmpVariables[0] != KMType.INVALID_VALUE)
        && (Util.arrayCompare(repository.osPatch, (short) 0, scratchPad, (short) 0, tmpVariables[0])
            != 0)) {
      if (Util.arrayCompare(repository.osPatch, (short) 0, scratchPad, (short) 0, tmpVariables[0])
          == -1) {
        // If the key characteristics has os patch level > current os patch
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
  }

  private static void makeKeyCharacteristics(byte[] scratchPad) {
    tmpVariables[0] =
        KMInteger.instance(repository.osPatch, (short) 0, (short) repository.osPatch.length);
    tmpVariables[1] =
        KMInteger.instance(repository.osVersion, (short) 0, (short) repository.osVersion.length);
    data[HW_PARAMETERS] =
        KMKeyParameters.makeHwEnforced(
            data[KEY_PARAMETERS], (byte)data[ORIGIN], tmpVariables[1], tmpVariables[0], scratchPad);
    data[SW_PARAMETERS] = KMKeyParameters.makeSwEnforced(data[KEY_PARAMETERS], scratchPad);
    data[KEY_CHARACTERISTICS] = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setHardwareEnforced(data[HW_PARAMETERS]);
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setSoftwareEnforced(data[SW_PARAMETERS]);
  }

  private static void createEncryptedKeyBlob(byte[] scratchPad) {
    // make key characteristics - returns key characteristics in data[KEY_CHARACTERISTICS]
    makeKeyCharacteristics(scratchPad);
    // make root of trust blob
    data[ROT] =
        KMByteBlob.instance(
            repository.verifiedBootKey, (short) 0, (short) repository.verifiedBootKey.length);
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
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_KEYCHAR, data[KEY_CHARACTERISTICS]);
    tmpVariables[0] = repository.alloc((short) 256); // TODO use buffer
    tmpVariables[1] = encoder.encode(data[KEY_BLOB], repository.getHeap(), tmpVariables[0]);
    data[KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), tmpVariables[0], tmpVariables[1]);
  }

  private static void parseEncryptedKeyBlob(byte[] scratchPad) {
    tmpVariables[0] = KMByteBlob.cast(data[KEY_BLOB]).getStartOff();
    tmpVariables[1] = KMArray.instance((short)5);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    tmpVariables[2] = KMKeyCharacteristics.exp();
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    data[KEY_BLOB]=decoder.decodeArray(tmpVariables[1],
      KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
      KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
      KMByteBlob.cast(data[KEY_BLOB]).length());
    tmpVariables[0] = KMArray.cast(data[KEY_BLOB]).length();
    if (tmpVariables[0] < 4) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Validate Auth Tag
    data[AUTH_TAG] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_AUTH_TAG);
    if (!KMRepository.validateAuthTag(data[AUTH_TAG])) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // initialize data
    data[NONCE] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_NONCE);
    data[SECRET] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_SECRET);
    data[KEY_CHARACTERISTICS] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_KEYCHAR);
    data[PUB_KEY] = KMType.INVALID_VALUE;
    if (tmpVariables[0] == 5) {
      data[PUB_KEY] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_PUB_KEY);
    }
    data[HW_PARAMETERS] = KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getHardwareEnforced();
    data[SW_PARAMETERS] = KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getSoftwareEnforced();
    // make root of trust blob
    data[ROT] =
      KMByteBlob.instance(
        repository.verifiedBootKey, (short) 0, (short) repository.verifiedBootKey.length);
    data[HIDDEN_PARAMETERS] =
        KMKeyParameters.makeHidden(data[APP_ID], data[APP_DATA], data[ROT], scratchPad);
    // Decrypt Secret and verify auth tag
    decryptSecret(scratchPad);
  }

  private static void decryptSecret(byte[] scratchPad) {
    // derive master key - stored in derivedKey
    tmpVariables[0] = deriveKey(scratchPad);
    AESKey derivedKey =
        cryptoProvider.createAESKey(repository.getHeap(), data[DERIVED_KEY], tmpVariables[0]);
    if (derivedKey == null) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    boolean verification =
        cryptoProvider.aesGCMDecrypt(
            derivedKey,
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
    if (verification != true) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
  }

  private static void encryptSecret(byte[] scratchPad) {
    // make nonce
    data[NONCE] = KMByteBlob.instance((short) AES_GCM_NONCE_LENGTH);
    data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    Util.arrayCopy(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(data[NONCE]).length());
    cryptoProvider.newRandomNumber(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length());
    // derive master key - stored in derivedKey
    tmpVariables[0] = deriveKey(scratchPad);
    AESKey derivedKey =
        cryptoProvider.createAESKey(repository.getHeap(), data[DERIVED_KEY], tmpVariables[0]);
    if (derivedKey == null) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    tmpVariables[1] =
        cryptoProvider.aesGCMEncrypt(
            derivedKey,
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
    if (tmpVariables[1] > 0) {
      if (tmpVariables[1] != KMByteBlob.cast(data[SECRET]).length()) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      KMByteBlob.cast(data[SECRET]).setValue(scratchPad, (short) 0, tmpVariables[1]);
    }
  }

  private static void makeAuthData(byte[] scratchPad) {
    tmpVariables[0] =
        addPtrToAAD(KMKeyParameters.cast(data[HW_PARAMETERS]).getVals(), scratchPad, (short) 0);
    tmpVariables[0] +=
        addPtrToAAD(
            KMKeyParameters.cast(data[SW_PARAMETERS]).getVals(), scratchPad, tmpVariables[0]);
    tmpVariables[0] +=
        addPtrToAAD(
            KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals(), scratchPad, tmpVariables[0]);
    // convert scratch pad to KMArray
    tmpVariables[1] = KMArray.instance(tmpVariables[0]);
    short index = 0;
    short objPtr = 0;
    while (index < tmpVariables[0]) {
      objPtr = Util.getShort(scratchPad, (short) (index * 2));
      KMArray.cast(tmpVariables[1]).add(index, objPtr);
      index++;
    }
    data[AUTH_DATA] = repository.alloc(MAX_AUTH_DATA_SIZE);
    short len = encoder.encode(tmpVariables[1], repository.getHeap(), data[AUTH_DATA]);
    data[AUTH_DATA_LENGTH] = len;
  }

  private static short addPtrToAAD(short dataArrPtr, byte[] aadBuf, short offset) {
    short index = (short) (offset * 2);
    short tagInd = 0;
    short tagPtr = 0;
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
    tmpVariables[0] = KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals();
    tmpVariables[1] = repository.alloc((short) 256);
    // generate derivation material from hidden parameters
    tmpVariables[2] = encoder.encode(tmpVariables[0], repository.getHeap(), tmpVariables[1]);
    // create derived key i.e. MAC
    tmpVariables[3] =
        cryptoProvider.aesCCMSign(
            repository.getHeap(),
            tmpVariables[1],
            tmpVariables[2],
            repository.getMasterKeySecret(),
            scratchPad,
            (short) 0);
    if (tmpVariables[3] < 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // store the derived secret in data dictionary
    data[DERIVED_KEY] = repository.alloc(tmpVariables[3]);
    Util.arrayCopyNonAtomic(
        scratchPad, (short) 0, repository.getHeap(), data[DERIVED_KEY], tmpVariables[3]);
    return tmpVariables[3];
  }

  private static void sendError(APDU apdu, short err) {
    bufferLength = encoder.encodeError(err, buffer, bufferStartOffset, (short) 5);
    sendOutgoing(apdu);
  }
}
