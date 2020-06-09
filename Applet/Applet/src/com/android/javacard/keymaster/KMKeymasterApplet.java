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
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;
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
  public static final byte DES_BLOCK_SIZE = 8;
  public static final short MAX_LENGTH = (short) 0x2000;
  private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
  private static final short KM_HAL_VERSION = (short) 0x4000;
  private static final short MAX_AUTH_DATA_SIZE = (short) 128;
  private static final short MAX_IO_LENGTH = 0x400;
  // "Keymaster HMAC Verification" - used for HMAC key verification.
  public static final byte[] sharingCheck = {
    0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x48, 0x4D, 0x41, 0x43, 0x20, 0x56,
    0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E
  };
  // "KeymasterSharedMac"
  public static final byte[] ckdfLable = {
    0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x4D,
    0x61, 0x63
  };
  // "Auth Verification"
  public static final byte[] authVerification = {0x41, 0x75, 0x74, 0x68, 0x20, 0x56, 0x65, 0x72, 0x69,
  0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E};
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
  public static final byte DATA_ARRAY_SIZE = 30;
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
  public static final byte ENC_TRANSPORT_KEY = 19;
  public static final byte MASKING_KEY = 20;
  public static final byte HMAC_SHARING_PARAMS = 21;
  public static final byte OP_HANDLE = 22;
  public static final byte IV = 23;
  public static final byte INPUT_DATA = 24;
  public static final byte OUTPUT_DATA = 25;
  public static final byte HW_TOKEN = 26;
  public static final byte VERIFICATION_TOKEN = 27;

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
  // ComputeHMAC constants
  private static final short HMAC_SEED_SIZE = 32;
  private static final short HMAC_NONCE_SIZE = 32;
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
    cryptoProvider = KMCryptoProviderImpl.instance();
    provisionDone = false;
    setBootParamsDone = false;
    byte[] buf =
        JCSystem.makeTransientByteArray(
            repository.HMAC_SEED_NONCE_SIZE, JCSystem.CLEAR_ON_DESELECT);
    keymasterState = KMKeymasterApplet.INSTALL_STATE;
    data = JCSystem.makeTransientShortArray((short) DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    repository = new KMRepository();
    tmpVariables =
        JCSystem.makeTransientShortArray((short) TMP_VARIABLE_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    Util.arrayCopyNonAtomic(
        cryptoProvider.getTrueRandomNumber(repository.HMAC_SEED_NONCE_SIZE),
        (short) 0,
        buf,
        (short) 0,
        repository.HMAC_SEED_NONCE_SIZE);
    repository.initMasterKey(buf, repository.HMAC_SEED_NONCE_SIZE);
    cryptoProvider.newRandomNumber(buf, (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    // TODO remove this when key agreement protocol is implemented.
    repository.initHmacKey(buf, repository.HMAC_SEED_NONCE_SIZE);
    cryptoProvider.newRandomNumber(buf, (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    repository.initHmacSeed(buf, repository.HMAC_SEED_NONCE_SIZE);
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
      if(data[OP_HANDLE] != KMType.INVALID_VALUE){
        KMOperationState op = repository.findOperation(KMInteger.cast(data[OP_HANDLE]).getShort());
        if(op != null){
          repository.releaseOperation(op);
        }
      }
      sendError(apdu, exception.reason);
      exception.clear();
    } finally {
      resetData();
      repository.clean();
    }
  }
  private void resetData(){
    short index = 0;
    while (index < data.length){
      data[index] = KMType.INVALID_VALUE;
      index++;
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

  private void processProvisionCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
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
    if (!KMByteBlob.cast(data[APP_ID]).isValid()) {
      data[APP_ID] = KMType.INVALID_VALUE;
    }
    if (!KMByteBlob.cast(data[APP_DATA]).isValid()) {
      data[APP_DATA] = KMType.INVALID_VALUE;
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

  private void processGetHmacSharingParamCmd(APDU apdu) {
    // No Arguments
    byte[] scratchPad = apdu.getBuffer();
    // Create blob containing seed
    tmpVariables[0] =
        KMByteBlob.instance(repository.getHmacSeed(), (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    // Create blob containing nonce
    cryptoProvider.newRandomNumber(scratchPad, (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    tmpVariables[1] = KMByteBlob.instance(scratchPad, (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    // Create HMAC Sharing Parameters
    tmpVariables[2] = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(tmpVariables[2]).setNonce(tmpVariables[1]);
    KMHmacSharingParameters.cast(tmpVariables[2]).setSeed(tmpVariables[0]);
    // prepare the response
    tmpVariables[3] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[3]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[3]).add((short) 1, tmpVariables[2]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void processDeleteAllKeysCmd(APDU apdu) {
    // No arguments
    repository.removeAllAuthTags();
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private void processDeleteKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
    // Arguments
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, KMByteBlob.exp());
    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // Process
    data[KEY_BLOB] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMByteBlob.cast(data[KEY_BLOB]).getStartOff();
    tmpVariables[1] = KMArray.instance((short) 5);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    tmpVariables[2] = KMKeyCharacteristics.exp();
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    data[KEY_BLOB] =
        decoder.decodeArray(
            tmpVariables[1],
            KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[KEY_BLOB]).length());
    tmpVariables[0] = KMArray.cast(data[KEY_BLOB]).length();
    if (tmpVariables[0] < 4) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Validate Auth Tag
    data[AUTH_TAG] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_AUTH_TAG);
    if (!repository.validateAuthTag(data[AUTH_TAG])) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // delete the auth tag
    repository.removeAuthTag(data[AUTH_TAG]);
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private void processComputeSharedHmacCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 1);
    tmpVariables[2] = KMKeyParameters.exp();
    tmpVariables[3] = KMHmacSharingParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMArray.exp(tmpVariables[3])); // Vector
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]); // Key Params
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[HMAC_SHARING_PARAMS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    // Concatenate HMAC Params
    tmpVariables[0] = 0;
    tmpVariables[1] = KMArray.cast(data[HMAC_SHARING_PARAMS]).length();
    tmpVariables[5] = 0; // index in scratchPad
    while (tmpVariables[0] < tmpVariables[1]) {
      // read HmacSharingParam
      tmpVariables[2] = KMArray.cast(data[HMAC_SHARING_PARAMS]).get(tmpVariables[0]);
      // get seed
      tmpVariables[3] = KMHmacSharingParameters.cast(tmpVariables[2]).getSeed();
      tmpVariables[4] = KMByteBlob.cast(tmpVariables[3]).length();
      // if seed is present
      if (tmpVariables[4] == HMAC_SEED_SIZE /*32*/) {
        // then copy that to scratchPad
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(tmpVariables[3]).getBuffer(),
            KMByteBlob.cast(tmpVariables[3]).getStartOff(),
            scratchPad,
            tmpVariables[5],
            tmpVariables[4]);
        tmpVariables[5] += tmpVariables[4];
      }
      // get nonce
      tmpVariables[3] = KMHmacSharingParameters.cast(tmpVariables[2]).getNonce();
      tmpVariables[4] = KMByteBlob.cast(tmpVariables[3]).length();
      // if nonce is not present
      if (tmpVariables[4] != HMAC_NONCE_SIZE /*32*/) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      // copy nonce to scratchPad
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(tmpVariables[3]).getBuffer(),
          KMByteBlob.cast(tmpVariables[3]).getStartOff(),
          scratchPad,
          tmpVariables[5],
          tmpVariables[4]);
      tmpVariables[5] += tmpVariables[4];
    }
    // ckdf to derive hmac key
    HMACKey key =
        cryptoProvider.cmacKdf(
            repository.getHmacKey(), ckdfLable, scratchPad, (short) 0, tmpVariables[5]);
    tmpVariables[5] = key.getKey(scratchPad, (short) 0);
    repository.initComputedHmac(scratchPad, (short) 0, tmpVariables[5]);
    // Generate sharingKey verification
    tmpVariables[5] =
        cryptoProvider.hmacSign(
            key, sharingCheck, (short) 0, (short) sharingCheck.length, scratchPad, (short) 0);
    tmpVariables[1] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[5]);
    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, tmpVariables[1]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void processUpgradeKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 2);
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMByteBlob.exp()); // Key Blob
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]); // Key Params
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(tmpVariables[0]).getValue();
    }
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(tmpVariables[0]).getValue();
    }
    // parse existing key blob
    parseEncryptedKeyBlob(scratchPad);
    // validate characteristics to be upgraded.
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
        Util.arrayFillNonAtomic(scratchPad, (short) 0, tmpVariables[0], (byte) 0);
        // If the os version is not zero
        if (Util.arrayCompare(
                repository.osVersion, (short) 0, scratchPad, (short) 0, tmpVariables[0])
            != 0) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
      }
    }
    tmpVariables[0] =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    if ((tmpVariables[0] != KMType.INVALID_VALUE)
        && (Util.arrayCompare(repository.osPatch, (short) 0, scratchPad, (short) 0, tmpVariables[0])
            != 0)) {
      if (Util.arrayCompare(repository.osPatch, (short) 0, scratchPad, (short) 0, tmpVariables[0])
          < 0) {
        // If the key characteristics has os patch level > current os patch
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
    }
    // remove Auth Tag
    repository.removeAuthTag(data[AUTH_TAG]);
    // copy origin
    data[ORIGIN] = KMEnumTag.getValue(KMType.ORIGIN, data[HW_PARAMETERS]);
    // create new key blob with current os version etc.
    createEncryptedKeyBlob(scratchPad);
    // persist new auth tag for rollback resistance.
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

  private void processExportKeyCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private void processImportWrappedKeyCmd(APDU apdu) {
    // Currently only RAW formatted import key blob are supported
    if (repository.keyBlobCount > repository.MAX_BLOB_STORAGE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 11);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[2]); // Key Params
    KMArray.cast(tmpVariables[1]).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT)); // Key Format
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp()); // Wrapped Import Key Blob
    KMArray.cast(tmpVariables[1]).add((short) 3, KMByteBlob.exp()); // Auth Tag
    KMArray.cast(tmpVariables[1]).add((short) 4, KMByteBlob.exp()); // IV - Nonce
    KMArray.cast(tmpVariables[1]).add((short) 5, KMByteBlob.exp()); // Encrypted Transport Key
    KMArray.cast(tmpVariables[1]).add((short) 6, KMByteBlob.exp()); // Wrapping Key KeyBlob
    KMArray.cast(tmpVariables[1]).add((short) 7, KMByteBlob.exp()); // Masking Key
    KMArray.cast(tmpVariables[1]).add((short) 8, tmpVariables[2]); // Un-wrapping Params
    KMArray.cast(tmpVariables[1]).add((short) 9, KMInteger.exp()); // Password Sid
    KMArray.cast(tmpVariables[1]).add((short) 10, KMInteger.exp()); // Biometric Sid
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    tmpVariables[3] = KMArray.cast(tmpVariables[2]).get((short) 0);
    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, tmpVariables[3]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.RSA
        || tmpVariables[3] == KMType.EC) { // RSA and EC not implemented
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    // Key format must be RAW format - X509 and PKCS8 not implemented.
    tmpVariables[3] = KMArray.cast(tmpVariables[2]).get((short) 1);
    tmpVariables[3] = KMEnum.cast(tmpVariables[3]).getVal();
    if (tmpVariables[3] != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    data[AUTH_DATA] = KMArray.cast(tmpVariables[2]).get((short) 3);
    data[AUTH_TAG] = KMArray.cast(tmpVariables[2]).get((short) 4);
    data[NONCE] = KMArray.cast(tmpVariables[2]).get((short) 5);
    data[ENC_TRANSPORT_KEY] = KMArray.cast(tmpVariables[2]).get((short) 6);
    data[MASKING_KEY] = KMArray.cast(tmpVariables[2]).get((short) 8);
    // Step 1 - parse wrapping key blob
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 9); // wrapping key parameters
    // Check for app id and app data.
    data[APP_ID] = KMType.INVALID_VALUE;
    data[APP_DATA] = KMType.INVALID_VALUE;
    tmpVariables[3] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    if (tmpVariables[3] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    tmpVariables[3] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (tmpVariables[3] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    // wrapping key blob
    data[KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 7);
    parseEncryptedKeyBlob(scratchPad);

    // Step 2 - Decrypt the encrypted transport key
    // enforce authorization for WRAP_KEY operation using RSA algorithm according to javacard caps.
    if (KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]) != KMType.RSA) {
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    if (!(KMEnumArrayTag.contains(KMType.DIGEST, KMType.SHA2_256, data[HW_PARAMETERS]))) {
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    if (!(KMEnumArrayTag.contains(KMType.PADDING, KMType.RSA_OAEP, data[HW_PARAMETERS]))) {
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    KMCipher cipher =
        cryptoProvider.createRsaDecrypt(
            KMCipher.CIPHER_RSA,
            KMCipher.PAD_PKCS1_OAEP_SHA256,
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
            KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
            KMByteBlob.cast(data[PUB_KEY]).length());
    // Decrypt the transport key
    tmpVariables[3] =
        cipher.doFinal(
            KMByteBlob.cast(data[ENC_TRANSPORT_KEY]).getBuffer(),
            KMByteBlob.cast(data[ENC_TRANSPORT_KEY]).getStartOff(),
            KMByteBlob.cast(data[ENC_TRANSPORT_KEY]).length(),
            scratchPad,
            (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[3]);
    cryptoProvider.delete(cipher);

    // Step 3 - XOR with masking key
    tmpVariables[4] = KMByteBlob.cast(data[MASKING_KEY]).length();
    if (tmpVariables[3] != tmpVariables[4]) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    tmpVariables[3] = 0; // index in scratchPad
    byte[] buf = KMByteBlob.cast(MASKING_KEY).getBuffer();
    tmpVariables[5] = KMByteBlob.cast(MASKING_KEY).getStartOff();
    while (tmpVariables[3] < tmpVariables[4]) {
      scratchPad[tmpVariables[3]] =
          (byte) (scratchPad[tmpVariables[3]] ^ buf[(short) (tmpVariables[3] + tmpVariables[5])]);
      scratchPad[3]++;
    }
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[3]);

    // Step 4 - AES-GCM decrypt
    data[IMPORTED_KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 2);
    data[AUTH_DATA] = KMArray.cast(tmpVariables[2]).get((short) 3);
    data[AUTH_TAG] = KMArray.cast(tmpVariables[2]).get((short) 4);
    data[NONCE] = KMArray.cast(tmpVariables[2]).get((short) 5);
    data[ENC_TRANSPORT_KEY] = KMArray.cast(tmpVariables[2]).get((short) 6);
    data[MASKING_KEY] = KMArray.cast(tmpVariables[2]).get((short) 8);
    AESKey key =
        cryptoProvider.createAESKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
    boolean verification =
        cryptoProvider.aesGCMDecrypt(
            key,
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length(),
            scratchPad,
            (short) 0,
            KMByteBlob.cast(data[NONCE]).getBuffer(),
            KMByteBlob.cast(data[NONCE]).getStartOff(),
            KMByteBlob.cast(data[NONCE]).length(),
            KMByteBlob.cast(data[AUTH_DATA]).getBuffer(),
            KMByteBlob.cast(data[AUTH_DATA]).getStartOff(),
            KMByteBlob.cast(data[AUTH_DATA]).length(),
            KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
            KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
            KMByteBlob.cast(data[AUTH_TAG]).length());
    if (verification == false) {
      KMException.throwIt(KMError.IMPORTED_KEY_VERIFICATION_FAILED);
    }
    cryptoProvider.delete(key);

    // Step 5 - Import Decrypted Key.
    data[ORIGIN] = KMType.SECURELY_IMPORTED;
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    importKey(apdu, scratchPad);
  }

  private void processAttestKeyCmd(APDU apdu) {}

  private void processDestroyAttIdsCmd(APDU apdu) {}

  private void processVerifyAuthorizationCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private void processAbortOperationCmd(APDU apdu) {}

  private void processFinishOperationCmd(APDU apdu) {
    // TODO AES GCM
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    Util.arrayFill(scratchPad, (short)0,(short)256, (byte)0);
    tmpVariables[1] = KMArray.instance((short) 6);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMInteger.exp());
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add((short) 3, KMByteBlob.exp());
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 4, tmpVariables[3]);
    tmpVariables[4] = KMVerificationToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 5, tmpVariables[4]);
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[OP_HANDLE] = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[INPUT_DATA] = KMArray.cast(tmpVariables[2]).get((short) 2);
    data[HW_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 4);
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 5);
    // Check Operation Handle
    tmpVariables[1] = KMInteger.cast(data[OP_HANDLE]).getShort();
    KMOperationState op = repository.findOperation(tmpVariables[1]);
    if (KMInteger.compare(data[OP_HANDLE], KMInteger.uint_16(op.getHandle())) != 0) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    //Authorize the final operation
    authorizeUpdateFinalOperation(op, scratchPad);
    short len = 0;
    // If the operation is signing
    if(op.getPurpose() == KMType.SIGN){
      // Perform trusted confirmation if required
      if (op.isTrustedConfirmationRequired()) {
        tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.CONFIRMATION_TOKEN, data[KEY_PARAMETERS]);
        if(tmpVariables[0] == KMType.INVALID_VALUE){
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        tmpVariables[0] = KMByteTag.cast(tmpVariables[0]).getValue();
        tmpVariables[1] = op.getTrustedConfirmationSigner()
          .sign(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            KMByteBlob.cast(data[INPUT_DATA]).length(), scratchPad, (short)0);
        if(tmpVariables[1] != KMByteBlob.cast(tmpVariables[0]).length() ){
          KMException.throwIt(KMError.VERIFICATION_FAILED);
        }
        tmpVariables[0]=Util.arrayCompare(scratchPad,(short)0,
          KMByteBlob.cast(tmpVariables[0]).getBuffer(),
          KMByteBlob.cast(tmpVariables[0]).getStartOff(),
          tmpVariables[1]);
        if(tmpVariables[0] != 0){
          KMException.throwIt(KMError.VERIFICATION_FAILED);
        }
      }
      tmpVariables[1] = op.getSigner().getCipherAlgorithm();
      tmpVariables[2] = op.getSigner().getMessageDigestAlgorithm();
      tmpVariables[3] = op.getSigner().getPaddingAlgorithm();
      len = KMByteBlob.cast(data[INPUT_DATA]).length();
      //For RSA Signing algorithm
      if(tmpVariables[1] == Signature.SIG_CIPHER_RSA){
        //If no padding and no digest - then zero padding up to 256 on left
        if(tmpVariables[2] == MessageDigest.ALG_NULL && tmpVariables[3] == KMCipher.PAD_NOPAD){
          // If data length is greater then key length
          if(len > 256){
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }else if(len == 256){ // if data length is same as key length
            // Compare the data with key value - date should be less then key value.
            // TODO the assumption is that private key exponent value is considered here.
            tmpVariables[0]= op.getKey(scratchPad,(short)0);
            tmpVariables[0] = Util.arrayCompare(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)0, tmpVariables[0]);
            if(tmpVariables[0] >= 0){
              KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
            }
          }
          Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)(256 - len),len);
            len = (short)256;
        } else if (tmpVariables[2] == MessageDigest.ALG_NULL
            && tmpVariables[3] == KMCipher.PAD_PKCS1) {
          // If PKCS1 padding and no digest - then 0x01||0x00||PS||0x00 on left such that PS = 8 bytes
          if(len > 245){ // 256 -11 bytes
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
          scratchPad[0] = 0x00;
          scratchPad[1] = 0x01;
          cryptoProvider.newRandomNumber(scratchPad, (short)2, (short)8);
          scratchPad[10] = 0x00;
          Util.arrayCopyNonAtomic(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            scratchPad, (short)11,len);
          len += (short)11;
        }else if (tmpVariables[2] != MessageDigest.ALG_NULL && tmpVariables[3] == KMCipher.PAD_PKCS1){
          //If PKCS1 padding and digest != ALG_NULL - just copy the data on the scratch pad
          Util.arrayCopyNonAtomic(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            scratchPad, (short)0,len);
        }
      }else if(tmpVariables[1] == Signature.SIG_CIPHER_ECDSA){ // For ECDSA algorithm
        //If no digest then truncate the data to 32 byte if required
        if(tmpVariables[2] == MessageDigest.ALG_NULL){
          if(len > 32){
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)0,(short)32);
            len = 32;
          }
        }else{
          //If digest is present then copy the data to scratchpad
          Util.arrayCopyNonAtomic(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            scratchPad, (short)0,len);
        }
      }else if(tmpVariables[1] == Signature.SIG_CIPHER_HMAC){ // For HMAC algorithm
        // Just copy the data as digest is always present.
        Util.arrayCopyNonAtomic(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          scratchPad, (short)0,len);
      }else{ // This is should never happen
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      // Sign the data and also complete the trusted verification.
      tmpVariables[0]= op.getSigner()
        .sign(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          KMByteBlob.cast(data[INPUT_DATA]).length(),scratchPad, (short)0);
      data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short)0, tmpVariables[0]);
    } else{ //If decrypt or encrypt operation
      tmpVariables[1] = op.getCipher().getCipherAlgorithm();
      tmpVariables[2] = op.getCipher().getPaddingAlgorithm();
      len = KMByteBlob.cast(data[INPUT_DATA]).length();
      if(tmpVariables[1] == KMCipher.CIPHER_RSA){ // For RSA algorithm
        // If no padding and no digest - then zero padding up to 256 on left
        if (tmpVariables[2] == KMCipher.PAD_NOPAD) {
          if(len > 256){
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
          if(len < 256){
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)(256 - len),len);
            len = (short)256;
          }
        } else {
          // If OAEP padding with digest - just copy the data to scratchpad and continue.
          Util.arrayCopyNonAtomic(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            scratchPad, (short)0,len);
        }
      }else if(tmpVariables[1] == KMCipher.CIPHER_DES_CBC || tmpVariables[1] == KMCipher.CIPHER_DES_ECB
        || tmpVariables[1] == KMCipher.CIPHER_AES_CBC ||
        tmpVariables[1] == KMCipher.CIPHER_AES_ECB){
        if(tmpVariables[1] == KMCipher.CIPHER_AES_CBC ||
          tmpVariables[1] == KMCipher.CIPHER_AES_ECB){ // For AES algorithm
          tmpVariables[5] = AES_BLOCK_SIZE;
        }else{
          tmpVariables[5] = DES_BLOCK_SIZE;
        }
          //If no padding then data length must be block aligned
          if (tmpVariables[2] == KMCipher.PAD_NOPAD && ((short)(len % tmpVariables[5]) != 0)){
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
          //If padding i.e. pkcs7 then add padding to right
          if(tmpVariables[2] != KMCipher.PAD_NOPAD){
            tmpVariables[3] = (short)(len % tmpVariables[5]);
            if(tmpVariables[3] != 0){
              // If not block aligned then pkcs7 padding on right
              tmpVariables[4] = (short)((len / tmpVariables[5])+tmpVariables[5]);
              Util.arrayFillNonAtomic(scratchPad, (short)0, tmpVariables[4], (byte)tmpVariables[3]);
            }else{
              // If block aligned then one complete block of pkcs7 padding of block length value
              // on the right.
              tmpVariables[4] = (short)(len + tmpVariables[5]);
              Util.arrayFillNonAtomic(scratchPad, (short)0, tmpVariables[4], (byte)tmpVariables[5]);
            }
            Util.arrayCopyNonAtomic( KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)0,len);
            len = tmpVariables[4];
          }
          // AES / DES Cipher
        tmpVariables[0]= op.getCipher()
          .doFinal(scratchPad, (short)0,len, scratchPad, (short)len);
        data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short)len, tmpVariables[0]);
        } else{ // This should never happen
          KMException.throwIt(KMError.OPERATION_CANCELLED);
        }
      }
      // Remove the operation handle
    repository.releaseOperation(op);
    // Make response
    // make response
    tmpVariables[1] = KMArray.instance((short) 0);
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short) 4);
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    KMArray.cast(tmpVariables[2]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[2]).add((short) 1, tmpVariables[1]);
    KMArray.cast(tmpVariables[2]).add((short) 2, data[OUTPUT_DATA]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void authorizeUpdateFinalOperation(KMOperationState op, byte[] scratchPad) {
    // User Authentication
    if (!op.isAuthPerOperation()) {
      if (!op.isAuthTimeoutValidated()) {
        validateVerificationToken(op, data[VERIFICATION_TOKEN], scratchPad);
        tmpVariables[0] = KMInteger.uint_64(op.getAuthTime(), (short) 0);
        tmpVariables[2] = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getTimestamp();
        if (tmpVariables[3] == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.VERIFICATION_FAILED);
        }
        if (KMInteger.compare(tmpVariables[0], tmpVariables[3]) >= 0) {
          KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
        }
        op.setAuthTimeoutValidated(true);
      }
    } else { // Auth per operation
      authorizeUserIdPerKeyOperation(data[HW_TOKEN], scratchPad);
    }
  }

  private void validateVerificationToken(KMOperationState op, short verToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian and Java is big endian
    short ptr = KMVerificationToken.cast(verToken).getMac();
    short len = 0;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    // validate operation handle.
    ptr = KMVerificationToken.cast(verToken).getChallenge();
    if(op.getHandle() != KMInteger.cast(ptr).getShort()){
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    // concatenation length will be 37 + length of verified parameters list.
    short params = KMVerificationToken.cast(verToken).getParametersVerified();
    Util.arrayFillNonAtomic(scratchPad, (short) 0,
      (short) (37+KMByteBlob.cast(params).length()), (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopy(authVerification,(short)0, scratchPad, (short)0, (short)authVerification.length);
    len = (short)authVerification.length;
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
    // concatenate security level - 4 bytes
    ptr = KMVerificationToken.cast(verToken).getSecurityLevel();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += 4;
    // concatenate Parameters verified - blob of encoded data.
    ptr = KMVerificationToken.cast(verToken).getParametersVerified();
    len += KMByteBlob.cast(ptr).getValues(scratchPad, (short)0);
    len += 4;
    // hmac the data
    HMACKey key =
      cryptoProvider.createHMACKey(
        repository.getComputedHmacKey(),
        (short) 0,
        (short) repository.getComputedHmacKey().length);
    ptr = KMVerificationToken.cast(verToken).getMac();
    boolean verified =
      cryptoProvider.hmacVerify(key, scratchPad, (short) 0, len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
    if(!verified){
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    /*

    // Compare mac.
    ptr = KMVerificationToken.cast(verToken).getMac();
    if (macLen != KMByteBlob.cast(ptr).length()) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    if (Util.arrayCompare(
      scratchPad, (short) (len+1),
      KMByteBlob.cast(ptr).getBuffer(), KMByteBlob.cast(ptr).getStartOff(), macLen) != 0) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    */

  }

  private void processUpdateOperationCmd(APDU apdu) {
    // TODO Add Support for AES-GCM
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 5);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMInteger.exp());
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp());
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 3, tmpVariables[3]);
    tmpVariables[4] = KMVerificationToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 4, tmpVariables[4]);
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[OP_HANDLE] = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[INPUT_DATA] = KMArray.cast(tmpVariables[2]).get((short) 2);
    data[HW_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 3);
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 4);
    // Check Operation Handle and get op state
    tmpVariables[1] = KMInteger.cast(data[OP_HANDLE]).getShort();
    KMOperationState op = repository.findOperation(tmpVariables[1]);
    if (KMInteger.compare(data[OP_HANDLE], KMInteger.uint_16(op.getHandle())) != 0) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // authorize the update operation
    authorizeUpdateFinalOperation(op, scratchPad);
    // If signing without  digest then do length validation checks
    tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
    if (op.getPurpose() == KMType.SIGN) {
      // If signing without  digest then update should not be called by HAL only final must be
      // called
      if (op.getSigner().getMessageDigestAlgorithm() == MessageDigest.ALG_NULL) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      op.getSigner()
          .update(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length());

      if (op.isTrustedConfirmationRequired()) {
        op.getTrustedConfirmationSigner()
            .update(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                KMByteBlob.cast(data[INPUT_DATA]).length());
      }
      data[OUTPUT_DATA] = KMType.INVALID_VALUE;
    } else {
      // purpose is Encrypt or Decrypt - input data must be block aligned.
        tmpVariables[1] = op.getCipher().getCipherAlgorithm();
        // TODO Update for decrypt for RSA may not be necessary - confirm this
        if (tmpVariables[1] == KMCipher.CIPHER_RSA) {
          KMException.throwIt(KMError.OPERATION_CANCELLED);
        }
        if (tmpVariables[1] == KMCipher.CIPHER_AES_CBC
            || op.getCipher().getCipherAlgorithm() == KMCipher.CIPHER_AES_ECB) {
          // 128 bit block size - HAL must send block aligned data
          if (tmpVariables[0] % 16 != 0) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
        } else if (op.getCipher().getCipherAlgorithm() == KMCipher.CIPHER_DES_CBC
            || op.getCipher().getCipherAlgorithm() == KMCipher.CIPHER_DES_ECB) {
          // 64 bit block size - HAL must send block aligned data
          if (tmpVariables[0] % 8 != 0) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
        }
        tmpVariables[1] =
            op.getCipher()
                .update(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(),
                    scratchPad,
                    (short) 0);
        data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[1]);
      }
    // make response
    tmpVariables[1] = KMArray.instance((short) 0);
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short) 4);
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    KMArray.cast(tmpVariables[2]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[2]).add((short) 1, KMInteger.uint_16(tmpVariables[0]));
    KMArray.cast(tmpVariables[2]).add((short) 2, tmpVariables[1]);
    KMArray.cast(tmpVariables[2]).add((short) 3, data[OUTPUT_DATA]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void processBeginOperationCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 4);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMEnum.instance(KMType.PURPOSE));
    KMArray.cast(tmpVariables[1]).add((short) 1, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add((short) 2, tmpVariables[2]);
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 3, tmpVariables[3]);
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 2);
    data[KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 1);
    tmpVariables[0] = KMArray.cast(tmpVariables[2]).get((short) 0);
    tmpVariables[0] = KMEnum.cast(tmpVariables[0]).getVal();
    tmpVariables[4] = KMArray.cast(tmpVariables[2]).get((short) 3);
    // Check for app id and app data.
    data[APP_ID] = KMType.INVALID_VALUE;
    data[APP_DATA] = KMType.INVALID_VALUE;
    tmpVariables[3] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    if (tmpVariables[3] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    tmpVariables[3] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (tmpVariables[3] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    // Parse the encrypted blob and decrypt it.
    parseEncryptedKeyBlob(scratchPad);
    // Authorize the begin operation and reserve op - data[OP_HANDLE] will have the handle.
    // It will also set data[IV] field if required.
    authorizeBeginOperation(tmpVariables[4], scratchPad);
    // Check for trusted confirmation - if required then set the signer in op state.
    tmpVariables[0] =
        KMKeyParameters.findTag(
            KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      // get operation
      KMOperationState op = repository.findOperation(data[OP_HANDLE]);
      // get the hmac key
      if (repository.getComputedHmacKey() == null) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      // set the Hmac signer
      op.setTrustedConfirmationSigner(
          cryptoProvider.createHmacSigner(
              MessageDigest.ALG_SHA_256,
              repository.getComputedHmacKey(),
              (short) 0,
              (short) repository.getComputedHmacKey().length));
    }
    // If the data[IV] is required to be returned.
    if (data[IV] != KMType.INVALID_VALUE) {
      // TODO confirm  why this is needed
      tmpVariables[2] = KMArray.instance((short) 1);
      KMArray.cast(tmpVariables[2]).add((short) 0, data[IV]);
    } else {
      tmpVariables[2] = KMArray.instance((short) 0);
    }
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[2]);
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, tmpVariables[1]);
    KMArray.cast(tmpVariables[0]).add((short) 2, data[OP_HANDLE]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[0], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void authorizeBeginOperation(short hwToken, byte[] scratchPad) {
    // Read purpose from key parameters - cannot be null.
    short purpose =
        KMEnumArrayTag.getValues(KMType.PURPOSE, data[KEY_PARAMETERS], scratchPad, (short) 0);
    if (purpose == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (purpose != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    purpose = scratchPad[0];
    if (!(KMEnumArrayTag.contains(KMType.PURPOSE, purpose, data[HW_PARAMETERS]))) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    // Read digest from key parameters - can be null for EC.
    short digest =
        KMEnumArrayTag.getValues(KMType.DIGEST, data[KEY_PARAMETERS], scratchPad, (short) 0);
    if (digest != KMType.INVALID_VALUE && digest != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    digest = scratchPad[0];
    // Read padding from key parameters - can be null for AES/DES.
    short padding =
        KMEnumArrayTag.getValues(KMType.PADDING, data[KEY_PARAMETERS], scratchPad, (short) 0);
    if (padding != KMType.INVALID_VALUE && padding != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    padding = scratchPad[0];
    // Read Blockmode
    short blockmode =
        KMEnumArrayTag.getValues(KMType.BLOCK_MODE, data[KEY_PARAMETERS], scratchPad, (short) 0);
    if (blockmode != KMType.INVALID_VALUE && blockmode != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    blockmode = scratchPad[0];

    // Max uses per boot
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      // get prescribed limit
      tmpVariables[0] = KMIntegerTag.cast(tmpVariables[0]).getValue();
      authorizeKeyUsageForCount(tmpVariables[0]);
    }
    // Authorize UserId - auth timeout check cannot be done in javacard
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[0] =
          KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, data[HW_PARAMETERS]);
      if (tmpVariables[0] != KMType.INVALID_VALUE) {
        // check if hw token is empty - mac should not be empty.
        tmpVariables[1] = KMHardwareAuthToken.cast(hwToken).getMac();
        if (KMByteBlob.cast(tmpVariables[1]).length() == 0) {
          KMException.throwIt(KMError.INVALID_MAC_LENGTH);
        }
        authorizeUserId(hwToken, scratchPad);
      }
    }
    // Authorize Caller Nonce - if caller nonce absent in key char and nonce present in
    // key params then fail.
    tmpVariables[2] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.NONCE, data[KEY_PARAMETERS]);
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.CALLER_NONCE, data[HW_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      if (tmpVariables[2] != KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.CALLER_NONCE_PROHIBITED);
      }
    }
    // Authorize Bootloader Only - assumption is that if this is is present then always fail.
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, data[HW_PARAMETERS]);
    if (tmpVariables[1] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    tmpVariables[0] = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    switch (tmpVariables[0]) {
      case KMType.RSA:
        authorizeRsa(purpose, digest, padding);
        break;
      case KMType.EC:
        authorizeEC(purpose, digest);
        break;
      case KMType.DES:
      case KMType.AES:
        if (tmpVariables[2] == KMType.INVALID_VALUE) {
          tmpVariables[2] = KMByteBlob.instance((short) 16);
          cryptoProvider.newRandomNumber(
              KMByteBlob.cast(tmpVariables[2]).getBuffer(),
              KMByteBlob.cast(tmpVariables[2]).getStartOff(),
              KMByteBlob.cast(tmpVariables[2]).length());
        }
        data[IV] = tmpVariables[2];
        authorizeAesDes(tmpVariables[0], purpose, blockmode, padding);
        break;
      case KMType.HMAC:
        authorizeHmac(purpose, digest);
        break;
      default:
        KMException.throwIt(KMError.UNIMPLEMENTED);
        break;
    }
  }

  private void authorizeGCM(short purpose, short padding) {
    data[OP_HANDLE] = KMType.INVALID_VALUE;
    if (purpose == KMType.SIGN || purpose == KMType.VERIFY) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    if (purpose == KMType.ENCRYPT) {
      purpose = KMCipher.MODE_ENCRYPT;
    } else {
      purpose = KMCipher.MODE_DECRYPT;
    }
    if (padding != KMType.PADDING_NONE) {
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    // Read and authorizeBeginOperation mac length
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MAC_LENGTH);
    }
    if (tmpVariables[0] % 8 != 0) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS]);
    if (tmpVariables[0] < tmpVariables[1]) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    if (tmpVariables[0] > 128) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    KMOperationState op = repository.reserveOperation();
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    op.setPurpose(purpose);
    op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length());
    op.setCipher(
        cryptoProvider.createGCMCipher(
            purpose,
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            KMByteBlob.cast(data[IV]).getBuffer(),
            KMByteBlob.cast(data[IV]).getStartOff(),
            KMByteBlob.cast(data[IV]).length()));
    data[OP_HANDLE] = op.getHandle();
  }

  private void authorizeHmac(short purpose, short digest) {
    data[OP_HANDLE] = KMType.INVALID_VALUE;
    if (purpose == KMType.ENCRYPT || purpose == KMType.DECRYPT) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    if (digest == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (!(KMEnumArrayTag.contains(KMType.DIGEST, digest, data[HW_PARAMETERS]))) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // Read and authorizeBeginOperation mac length
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MAC_LENGTH);
    }
    if (tmpVariables[0] % 8 != 0) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS]);
    if (tmpVariables[0] < tmpVariables[1]) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }

    switch (digest) {
      case KMType.MD5:
        tmpVariables[2] = MessageDigest.ALG_MD5;
        tmpVariables[1] = 128;
        break;
      case KMType.SHA1:
        tmpVariables[2] = MessageDigest.ALG_SHA;
        tmpVariables[1] = 160;
        break;
      case KMType.SHA2_224:
        tmpVariables[2] = MessageDigest.ALG_SHA_224;
        tmpVariables[1] = 224;
        break;
      case KMType.SHA2_256:
        tmpVariables[2] = MessageDigest.ALG_SHA_256;
        tmpVariables[1] = 256;
        break;
      case KMType.SHA2_384:
        tmpVariables[2] = MessageDigest.ALG_SHA_384;
        tmpVariables[1] = 384;
        break;
      case KMType.SHA2_512:
        tmpVariables[2] = MessageDigest.ALG_SHA_512;
        tmpVariables[1] = 512;
        break;
      default:
        tmpVariables[1] = 512;
        break;
    }
    if (tmpVariables[0] > tmpVariables[1]) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    KMOperationState op = repository.reserveOperation();
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    op.setPurpose(purpose);
    op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length());
    op.setSigner(
        cryptoProvider.createHmacSigner(
            tmpVariables[0],
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length()));
    data[OP_HANDLE] = op.getHandle();
  }

  private void authorizeAesDes(short alg, short purpose, short blockmode, short padding) {
    data[OP_HANDLE] = KMType.INVALID_VALUE;
    if (purpose == KMType.SIGN || purpose == KMType.VERIFY) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    if (blockmode == KMType.GCM) {
      authorizeGCM(purpose, padding);
    }
    if (purpose == KMType.ENCRYPT) {
      purpose = KMCipher.MODE_ENCRYPT;
    } else {
      purpose = KMCipher.MODE_DECRYPT;
    }
    KMOperationState op = null;
    // padding must be no pad - PKCS7 is not supported in javacard
    // TODO implement PCKS7 in cryptoProvider
    if (padding == KMType.PADDING_NONE) {
      padding = KMCipher.PAD_NULL;
    } else if (padding == KMType.PKCS7) {
      padding = KMCipher.PAD_PKCS7;
    } else {
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    if (alg == KMType.AES) {
      if (blockmode == KMType.CBC) {
        tmpVariables[0] = KMCipher.CIPHER_AES_CBC;
      } else if (blockmode == KMType.ECB) {
        tmpVariables[0] = KMCipher.CIPHER_AES_ECB;
      } else {
        // data[CIPHER_ALGORITHM] = Cipher.CIPHER_AES_CTR; // Not supported in 3.0.5
        // TODO change this once we can test.
        KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
      }
      op = repository.reserveOperation();
    } else if (alg == KMType.DES) {
      if (blockmode == KMType.CBC) {
        tmpVariables[0] = KMCipher.CIPHER_DES_CBC;
      } else if (blockmode == KMType.ECB) {
        tmpVariables[0] = KMCipher.CIPHER_DES_ECB;
      } else {
        // data[CIPHER_ALGORITHM] = Cipher.CIPHER_DES_CTR; // Not supported in 3.0.5
        // TODO change this once we can test.
        KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
      }
      op = repository.reserveOperation();
    } else {
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    op.setPurpose(purpose);
    op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length());
    op.setCipher(
        cryptoProvider.createSymmetricCipher(
            tmpVariables[0],
            padding,
            purpose,
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            KMByteBlob.cast(data[IV]).getBuffer(),
            KMByteBlob.cast(data[IV]).getStartOff(),
            KMByteBlob.cast(data[IV]).length()));
    data[OP_HANDLE] = op.getHandle();
  }

  private void authorizeEC(short purpose, short digest) {
    data[OP_HANDLE] = KMType.INVALID_VALUE;
    // purpose will be always sign.
    // Only ECDSA signing supported
    if (purpose == KMType.ENCRYPT || purpose == KMType.VERIFY || purpose == KMType.DECRYPT) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    switch (digest) {
      case KMType.DIGEST_NONE:
        tmpVariables[0] = MessageDigest.ALG_NULL;
        break;
      case KMType.SHA1:
        tmpVariables[0] = MessageDigest.ALG_SHA;
        break;
      case KMType.SHA2_224:
        tmpVariables[0] = MessageDigest.ALG_SHA_224;
        break;
      case KMType.SHA2_256:
        tmpVariables[0] = MessageDigest.ALG_SHA_256;
        break;
      case KMType.SHA2_384:
        tmpVariables[0] = MessageDigest.ALG_SHA_384;
        break;
      case KMType.SHA2_512:
        tmpVariables[0] = MessageDigest.ALG_SHA_512;
        break;
      default:
        KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        break;
    }
    KMOperationState op = repository.reserveOperation();
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    op.setPurpose(purpose);
    op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length());
    op.setSigner(
        cryptoProvider.createEcSigner(
            tmpVariables[0],
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length()));
    data[OP_HANDLE] = op.getHandle();
  }

  private void authorizeRsa(short purpose, short digest, short padding) {
    KMOperationState op = null;
    data[OP_HANDLE] = KMType.INVALID_VALUE;
    if (purpose == KMType.ENCRYPT || purpose == KMType.VERIFY) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    switch (purpose) {
      case KMType.DECRYPT:
        tmpVariables[0] = KMCipher.CIPHER_RSA;
        if (padding == KMType.PADDING_NONE) {
          // There is no way to select digest with no padding. Digest is also none.
          padding = KMCipher.PAD_NOPAD;
        } else if (padding != KMType.RSA_OAEP) {
          KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
        } else {
          // There is no way to ascertain MGF1 and SHA1 in javacard - this should be part of PKCS1.
          switch (digest) {
            case KMType.DIGEST_NONE:
              KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
              break;
            case KMType.SHA2_224:
              padding = KMCipher.PAD_PKCS1_OAEP_SHA224;
              break;
            case KMType.SHA2_256:
              padding = KMCipher.PAD_PKCS1_OAEP_SHA256;
              break;
            case KMType.SHA2_384:
              padding = KMCipher.PAD_PKCS1_OAEP_SHA384;
              break;
            case KMType.SHA2_512:
              padding = KMCipher.PAD_PKCS1_OAEP_SHA512;
              break;
            default:
              KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
              break;
          }
        }
        op = repository.reserveOperation();
        if (op == null) {
          KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
        }
        op.setPurpose(purpose);
        op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
          KMByteBlob.cast(data[SECRET]).getStartOff(),
          KMByteBlob.cast(data[SECRET]).length());
        op.setCipher(
            cryptoProvider.createRsaDecrypt(
                tmpVariables[0],
                padding,
                KMByteBlob.cast(data[SECRET]).getBuffer(),
                KMByteBlob.cast(data[SECRET]).getStartOff(),
                KMByteBlob.cast(data[SECRET]).length(),
                KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                KMByteBlob.cast(data[PUB_KEY]).length()));
        break;
      case KMType.SIGN:
        if (padding == KMType.PADDING_NONE) {
          if(digest == KMType.DIGEST_NONE){
            tmpVariables[0] = MessageDigest.ALG_NULL;
            padding = KMCipher.PAD_NOPAD;
          }else{
            KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
          }
        } else if (padding != KMType.RSA_PKCS1_1_5_SIGN) {
          KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
        } else {
          padding = KMCipher.PAD_PKCS1;
          switch (digest) { // TODO No digest not supported at this moment
            case KMType.DIGEST_NONE:
              tmpVariables[0] = MessageDigest.ALG_NULL;
              break;
            case KMType.SHA2_224:
              tmpVariables[0] = MessageDigest.ALG_SHA_224;
              break;
            case KMType.SHA2_256:
              tmpVariables[0] = MessageDigest.ALG_SHA_256;
              break;
            case KMType.SHA2_384:
              tmpVariables[0] = MessageDigest.ALG_SHA_384;
              break;
            case KMType.SHA2_512:
              tmpVariables[0] = MessageDigest.ALG_SHA_512;
              break;
            default:
              KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
              break;
          }
        }
        op = repository.reserveOperation();
        if (op == null) {
          KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
        }
        op.setPurpose(purpose);
        op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
          KMByteBlob.cast(data[SECRET]).getStartOff(),
          KMByteBlob.cast(data[SECRET]).length());
        op.setSigner(
            cryptoProvider.createRsaSigner(
                tmpVariables[0],
                padding,
                KMByteBlob.cast(data[SECRET]).getBuffer(),
                KMByteBlob.cast(data[SECRET]).getStartOff(),
                KMByteBlob.cast(data[SECRET]).length(),
                KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                KMByteBlob.cast(data[PUB_KEY]).length()));
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        break;
    }
    data[OP_HANDLE] = op.getHandle();
  }

  private void authorizeUserId(short hwToken, byte[] scratchPad) {
    validateHwToken(hwToken, scratchPad);
    tmpVariables[0] = KMHardwareAuthToken.cast(hwToken).getUserId();
    if (KMInteger.cast(tmpVariables[0]).isZero()) {
      tmpVariables[0] = KMHardwareAuthToken.cast(hwToken).getAuthenticatorId();
      if (KMInteger.cast(tmpVariables[0]).isZero()) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
    }
    // check user secure id
    if (!KMIntegerArrayTag.contains(KMType.USER_SECURE_ID, tmpVariables[0], data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
    // check auth type
    tmpVariables[1] = KMEnumTag.getValue(KMType.USER_AUTH_TYPE, data[HW_PARAMETERS]);
    tmpVariables[2] = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
    tmpVariables[2] = KMEnum.cast(tmpVariables[2]).getVal();
    if (((byte) tmpVariables[2] & (byte) tmpVariables[1]) == 0) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
  }

  private void validateHwToken(short hwToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian
    short ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    short len = 0;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 37, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getUserId();
    KMInteger.cast(tmpVariables[0])
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getAuthenticatorId();
    KMInteger.cast(tmpVariables[0])
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += 4;
    // concatenate timestamp -8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
    KMInteger.cast(tmpVariables[0])
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // hmac the data
    HMACKey key =
        cryptoProvider.createHMACKey(
            repository.getComputedHmacKey(),
            (short) 0,
            (short) repository.getComputedHmacKey().length);
    ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    boolean verified =
      cryptoProvider.hmacVerify(key, scratchPad, (short) 0, len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
    if(!verified){
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
/*
    len =
        cryptoProvider.hmac(key, scratchPad, (short) 0, len, scratchPad, (short) (len + 1) );
    // Compare mac.
    ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    if (len != KMByteBlob.cast(ptr).length()) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    if (Util.arrayCompare(
            scratchPad,
            (short) 38,
            KMByteBlob.cast(ptr).getBuffer(),
            KMByteBlob.cast(ptr).getStartOff(),
            len)
        != 0) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    */
  }

  private void authorizeUserIdPerKeyOperation(short hwToken, byte[] scratchPad) {
    tmpVariables[0] = KMHardwareAuthToken.cast(hwToken).getChallenge();
    if (KMInteger.compare(data[OP_HANDLE], tmpVariables[0]) != 0) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
    authorizeUserId(hwToken, scratchPad);
  }

  private void authorizeKeyUsageForCount(short limit) {
    // get current counter
    // TODO currently only short counter supported - max count 32K.
    short val = repository.getRateLimitedKeyCount(data[AUTH_TAG]);
    if (val != KMType.INVALID_VALUE) {
      short count = KMInteger.uint_16(val);
      // compare 32 bit values - is current counter less then prescribed limit
      if (KMInteger.compare(count, limit) != -1) {
        KMException.throwIt(KMError.KEY_MAX_OPS_EXCEEDED);
      }
      // increment the counter and store it back.
      val++;
      repository.setRateLimitedKeyCount(data[AUTH_TAG], val);
    } else {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }

  private void processImportKeyCmd(APDU apdu) {
    if (repository.keyBlobCount > repository.MAX_BLOB_STORAGE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 3);
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
    // Key format must be RAW format - X509 and PKCS8 not implemented.
    tmpVariables[3] = KMEnum.cast(tmpVariables[3]).getVal();
    if (tmpVariables[3] != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    data[ORIGIN] = KMType.IMPORTED;
    importKey(apdu, scratchPad);
  }

  private void importKey(APDU apdu, byte[] scratchPad) {
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
    if (tmpVariables[1] != KMType.P_256) {
      KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
    }
    // initialize 256 bit p256 key for given private key and public key.
    ECPrivateKey ecKey =
        cryptoProvider.createEcKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
    tmpVariables[4] = 0; // index for update list in scratchPad
    // check whether the keysize tag is present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) 256);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // check the curve if present in key parameters.
    tmpVariables[3] = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (tmpVariables[3] != KMType.INVALID_VALUE) {
      if (tmpVariables[3] != tmpVariables[1]) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the curve to scratchPad
      tmpVariables[5] = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[5]);
      tmpVariables[4] += 2;
    }
    // add scratch pad to key parameters
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate updated key parameters.
    validateECKeys(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short) 5);
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
    HMACKey hmacKey =
        cryptoProvider.createHMACKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (!(tmpVariables[2] >= 64 && tmpVariables[2] <= 512 && tmpVariables[2] % 8 == 0)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16(KMByteBlob.cast(data[SECRET]).length());
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate HMAC Key parameters
    validateHmacKey(scratchPad);

    data[KEY_BLOB] = KMArray.instance((short) 4);
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
    DESKey desKey =
        cryptoProvider.createTDESKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 168) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) 168);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate TDES Key parameters
    validateTDESKey(scratchPad);

    data[KEY_BLOB] = KMArray.instance((short) 4);
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
    AESKey aesKey =
        cryptoProvider.createAESKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 128 && tmpVariables[2] != 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratch pad
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16(KMByteBlob.cast(data[SECRET]).length());
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate AES Key parameters
    validateAESKey(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short) 4);
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
      if (tmpVariables[2] != 4
          || Util.getShort(scratchPad, (short) 10) != 0x01
          || Util.getShort(scratchPad, (short) 12) != 0x01) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
    } else {
      // add public exponent to scratchPad
      Util.setShort(scratchPad, (short) 10, (short) 0x01);
      Util.setShort(scratchPad, (short) 12, (short) 0x01);
      tmpVariables[5] = KMInteger.uint_32(scratchPad, (short) 10);
      tmpVariables[6] =
          KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }

    // initialize 2048 bit private key for given private exp and modulus.
    RSAPrivateKey rsaKey =
        cryptoProvider.createRsaKey(
            KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
            KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
            KMByteBlob.cast(data[PUB_KEY]).length(),
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 2048) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) 2048);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate RSA Key parameters
    validateRSAKey(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void updateKeyParameters(byte[] ptrArr, short len) {
    if (len == 0) {
      return; // nothing to update
    }
    // Create Update Param array and copy current params
    tmpVariables[0] = KMKeyParameters.cast(data[KEY_PARAMETERS]).getVals();
    tmpVariables[1] = (short) (KMArray.cast(tmpVariables[0]).length() + (short) (len / 2));
    tmpVariables[1] = KMArray.instance(tmpVariables[1]); // update params
    tmpVariables[2] = KMArray.cast(tmpVariables[0]).length();
    tmpVariables[3] = 0;
    // copy the existing key parameters to updated array
    while (tmpVariables[3] < tmpVariables[2]) {
      tmpVariables[4] = KMArray.cast(tmpVariables[0]).get(tmpVariables[3]);
      KMArray.cast(tmpVariables[1]).add(tmpVariables[3], tmpVariables[4]);
      tmpVariables[3]++;
    }
    // copy new parameters to updated array
    tmpVariables[2] = KMArray.cast(tmpVariables[1]).length();
    tmpVariables[5] = 0; // index in ptrArr
    while (tmpVariables[3] < tmpVariables[2]) {
      tmpVariables[4] = Util.getShort(ptrArr, tmpVariables[5]);
      KMArray.cast(tmpVariables[1]).add(tmpVariables[3], tmpVariables[4]);
      tmpVariables[3]++;
      tmpVariables[5] += 2;
    }
    // replace with updated key parameters.
    data[KEY_PARAMETERS] = KMKeyParameters.instance(tmpVariables[1]);
  }

  // TODO Add Signature verification.
  private void processSetBootParamsCmd(APDU apdu) {
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Argument 1 OS Version
    // short osVersionExp = KMIntegerTag.exp(KMType.UINT_TAG);
    tmpVariables[0] = KMInteger.exp();
    // Argument 2 OS Patch level
    // short osPatchExp = KMIntegerTag.exp(KMType.UINT_TAG);
    tmpVariables[1] = KMInteger.exp();
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
    //System.out.println("Process boot params buffer: "+byteArrayToHexString(buffer));
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
    KMInteger.cast(tmpVariables[0]).value(repository.osVersion, (short) 0);
    KMInteger.cast(tmpVariables[1]).value(repository.osPatch, (short) 0);
    //KMInteger.cast(valPtr).getValue(repository.osVersion, (short) 0, (short) 4);
    //valPtr = KMIntegerTag.cast(tmpVariables[1]).getValue();
    //KMInteger.cast(valPtr).getValue(repository.osPatch, (short) 0, (short) 4);
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

  private static void validateRSAKey(byte[] scratchPad) {
    // Read key size
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
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

  private static void validateAESKey(byte[] scratchPad) {
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
      // Find Minimum Mac length
      tmpVariables[2] =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
      // If block modes contain GCM mode
      if(KMEnumArrayTag.cast(tmpVariables[1]).contains(KMType.GCM)){
        // minimum mac length must be specified
        if (tmpVariables[2] == KMTag.INVALID_VALUE) {
          KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
        }
        tmpVariables[3] = KMIntegerTag.cast(tmpVariables[2]).getValue();
        // Validate the MIN_MAC_LENGTH for AES - should be multiple of 8, less then 128 bits
        // and greater the 96 bits
        if(KMInteger.cast(tmpVariables[3]).getSignificantShort() != 0 ||
          KMInteger.cast(tmpVariables[3]).getShort() > 128 ||
          KMInteger.cast(tmpVariables[3]).getShort() < 96 ||
          (KMInteger.cast(tmpVariables[3]).getShort() % 8) != 0){
          KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
        }
      }else{ // No GCM mode then no minimum mac length must be specified
        if (tmpVariables[2] != KMTag.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
      }
    }
  }

  private static void generateAESKey(byte[] scratchPad) {
    validateAESKey(scratchPad);
    tmpVariables[0] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    AESKey aesKey = cryptoProvider.createAESKey(tmpVariables[0]);
    tmpVariables[0] = aesKey.getKey(scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static void validateECKeys(byte[] scratchPad) {
    // Read key size
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    tmpVariables[1] = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if ((tmpVariables[0] == KMTag.INVALID_VALUE) && (tmpVariables[1] == KMType.INVALID_VALUE)){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }else if((tmpVariables[1] != KMTag.INVALID_VALUE) && (tmpVariables[1] != KMType.P_256)){
      KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
    }else if ((tmpVariables[0] != KMTag.INVALID_VALUE) && (tmpVariables[0] != (short)256)){
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
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

  private static void validateTDESKey(byte[] scratchPad) {
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

  private static void validateHmacKey(byte[] scratchPad) {
    // check whether digest sizes are greater then or equal to min mac length.
    // Only SHA256 digest must be supported.
    if(!KMEnumArrayTag.contains(KMType.DIGEST, KMType.SHA2_256, data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    if(KMEnumArrayTag.length(KMType.DIGEST,data[KEY_PARAMETERS]) != 1){
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    // Read Minimum Mac length
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
    }
    if (((short) (tmpVariables[0] % 8) != 0) ||
      (tmpVariables[0] < (short) 64)||
      tmpVariables[0] > (short)256) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read keysize
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (!(tmpVariables[1] >= 64 && tmpVariables[1] <= 512 && tmpVariables[1] % 8 == 0)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private static void generateHmacKey(byte[] scratchPad) {
    validateHmacKey(scratchPad);
    tmpVariables[1] =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
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
            data[KEY_PARAMETERS],
            (byte) data[ORIGIN],
            tmpVariables[1],
            tmpVariables[0],
            scratchPad);
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
    tmpVariables[0] = repository.alloc((short) 1024); // TODO use buffer
    tmpVariables[1] = encoder.encode(data[KEY_BLOB], repository.getHeap(), tmpVariables[0]);
    data[KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), tmpVariables[0], tmpVariables[1]);
  }

  private static void parseEncryptedKeyBlob(byte[] scratchPad) {
    tmpVariables[0] = KMByteBlob.cast(data[KEY_BLOB]).getStartOff();
    tmpVariables[1] = KMArray.instance((short) 5);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    tmpVariables[2] = KMKeyCharacteristics.exp();
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    data[KEY_BLOB] =
        decoder.decodeArray(
            tmpVariables[1],
            KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[KEY_BLOB]).length());
    tmpVariables[0] = KMArray.cast(data[KEY_BLOB]).length();
    if (tmpVariables[0] < 4) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Validate Auth Tag
    data[AUTH_TAG] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_AUTH_TAG);
    if (!repository.validateAuthTag(data[AUTH_TAG])) {
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
    data[HW_PARAMETERS] =
        KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getHardwareEnforced();
    data[SW_PARAMETERS] =
        KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getSoftwareEnforced();
    // make root of trust blob
    data[ROT] =
        KMByteBlob.instance(
            repository.verifiedBootKey, (short) 0, (short) repository.verifiedBootKey.length);
    data[HIDDEN_PARAMETERS] =
        KMKeyParameters.makeHidden(data[APP_ID], data[APP_DATA], data[ROT], scratchPad);
    // make auth data
    makeAuthData(scratchPad);
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
    // Copy the decrypted secret
    data[SECRET] =
        KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.cast(data[SECRET]).length());
  }

  private static void encryptSecret(byte[] scratchPad) {
    // make nonce
    data[NONCE] = KMByteBlob.instance((short) AES_GCM_NONCE_LENGTH);
    data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    Util.arrayCopyNonAtomic(
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
  /*
  private static void print (String lab, byte[] b, short s, short l){
    byte[] i = new byte[l];
    Util.arrayCopyNonAtomic(b,s,i,(short)0,l);
    print(lab,i);
  }
  private static void print(String label, byte[] buf){
    System.out.println(label+": ");
    StringBuilder sb = new StringBuilder();
    for(int i = 0; i < buf.length; i++){
      sb.append(String.format(" 0x%02X", buf[i])) ;
      if(((i-1)%38 == 0) && ((i-1) >0)){
        sb.append(";\n");
      }
    }
    System.out.println(sb.toString());
  }*/
}
