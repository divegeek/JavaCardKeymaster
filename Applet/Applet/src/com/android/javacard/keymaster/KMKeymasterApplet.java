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
import javacard.security.CryptoException;
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
  private static final short MAX_AUTH_DATA_SIZE = (short) 512;
  private static final short MAX_IO_LENGTH = 0x600;
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
  // "confirmation token"
  public static final byte[] confirmationToken = {0x63, 0x6F, 0x6E, 0x66, 0x69, 0x72, 0x6D, 0x61, 0x74,
  0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E};

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
  private static final byte INS_DEVICE_LOCKED_CMD = 0x25;
  private static final byte INS_EARLY_BOOT_ENDED_CMD = 0x26;

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
  private static final byte SIGNATURE = 28;

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
  // 64 bit unsigned calculations for time
  private final static byte[] oneSecMsec = {0,0,0,0,0,0,0x03,(byte)0xE8};//1000 msec
  private final static byte[] oneMinMsec = {0,0,0,0,0,0,(byte)0xEA,0x60};//60000 msec
  private final static byte[] oneHourMsec = {0,0,0,0,0,0x36,(byte)0xEE,(byte)0x80};//3600000 msec
  private final static byte[] oneDayMsec = {0,0,0,0,0x05,0x26,0x5C,0x00};//86400000 msec
  private final static byte[] oneMonthMsec ={0,0,0,0,(byte)0x9A,0x7E,(byte)0xC8,0x00}; //2592000000 msec
  private final static byte[] oneYearMsec = {0,0,0,0x07,0x57,(byte)0xB1,0x2C,0x00}; //31536000000 msec
  // Leap year + 3 yrs
  private final static byte[] fourYrsMsec = {0,0,0,0x1D,0x63,(byte)0xEB,0x0C,0x00};//126230400000 msec
  private final static byte[] firstJan2020 =  {0,0,0x01,0x6F,0x60,0x1E,0x5C,0x00}; //1577865600000 msec
  private final static byte[] firstJan2051 =  {0,0,0x02,0x53,0x27,(byte)0xC5,(byte)0x90,0x00}; // 2556172800000 msec

  // Keymaster Applet attributes
  private static byte keymasterState = ILLEGAL_STATE;
  private static KMEncoder encoder;
  private static KMDecoder decoder;
  private static KMRepository repository;
  private static KMSEProvider cryptoProvider;
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
    cryptoProvider = KMSEProviderImpl.instance();
    provisionDone = false;
    setBootParamsDone = false;
    byte[] buf =
        JCSystem.makeTransientByteArray(
          (short)32, JCSystem.CLEAR_ON_DESELECT);
    keymasterState = KMKeymasterApplet.INSTALL_STATE;
    data = JCSystem.makeTransientShortArray((short) DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    repository = new KMRepository();
    tmpVariables =
        JCSystem.makeTransientShortArray((short) TMP_VARIABLE_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    Util.arrayCopyNonAtomic(cryptoProvider.getTrueRandomNumber(repository.MASTER_KEY_SIZE),
      (short) 0, buf, (short) 0, repository.MASTER_KEY_SIZE);
    repository.initMasterKey(buf, repository.MASTER_KEY_SIZE);
    cryptoProvider.newRandomNumber(buf, (short) 0, repository.SHARED_SECRET_KEY_SIZE);
    // TODO remove this when key agreement protocol is implemented.
    repository.initHmacSharedSecretKey(buf, repository.SHARED_SECRET_KEY_SIZE);
    // TODO currently hmac nonce is generated once when installing the applet. Remove this once boot
    //  signal reception is incorporated in the design.
    cryptoProvider.newRandomNumber(buf, (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    repository.initHmacNonce(buf, (short)0, repository.HMAC_SEED_NONCE_SIZE);
    // TODO Confirm before removing seed generation.
    //cryptoProvider.newRandomNumber(buf, (short) 0, repository.HMAC_SEED_NONCE_SIZE);
    //repository.initHmacSeed(buf, repository.HMAC_SEED_NONCE_SIZE);
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
    //TODO remove oracle Provisioning Cmd later.
    if (!(apduIns >= INS_GENERATE_KEY_CMD && apduIns <= INS_EARLY_BOOT_ENDED_CMD)) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    // Validate if INS is provision command if applet is in FIRST_SELECT_STATE.
    //TODO remove oracle Provisioning Cmd later.
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
        case INS_DEVICE_LOCKED_CMD:
          processDeviceLockedCmd(apdu);
          break;
        case INS_EARLY_BOOT_ENDED_CMD:
          processEarlyBootEndedCmd(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } catch (KMException exception) {
      freeOperations();
      sendError(apdu, exception.reason);
      exception.clear();
    } catch(ISOException exp){
      freeOperations();
    }finally{
      resetData();
      repository.clean();
    }
  }

  private void freeOperations(){
    if(data[OP_HANDLE] != KMType.INVALID_VALUE){
      KMOperationState op = repository.findOperation(KMInteger.cast(data[OP_HANDLE]).getShort());
      if(op != null){
        repository.releaseOperation(op);
      }
    }
  }
  private void processEarlyBootEndedCmd(APDU apdu) {
    KMException.throwIt(KMError.UNIMPLEMENTED);
  }

  private void processDeviceLockedCmd(APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.exp());
    tmpVariables[1] = KMVerificationToken.exp();
    KMArray.cast(tmpVariables[0]).add((short) 1, tmpVariables[1]);
    // Decode the arguments
    tmpVariables[0] = decoder.decode(tmpVariables[0], buffer, bufferStartOffset, bufferLength);
    tmpVariables[1] = KMArray.cast(tmpVariables[0]).get((short) 0);
    tmpVariables[1] = KMInteger.cast(tmpVariables[1]).getByte();
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[0]).get((short)1);
    validateVerificationToken(data[VERIFICATION_TOKEN],scratchPad);
    short verTime = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getTimestamp();
    short lastDeviceLockedTime = KMInteger.uint_64(repository.deviceLockedTimestamp, (short)0);
    if(KMInteger.compare(verTime,lastDeviceLockedTime) > 0){
      Util.arrayFillNonAtomic(scratchPad,(short)0, (short)8, (byte)0);
      KMInteger.cast(verTime).getValue(scratchPad,(short)0,(short)8);
      repository.deviceLockedFlag = true;
      if(tmpVariables[1] == 0x01) repository.deviceUnlockPasswordOnly = true;
      else repository.deviceUnlockPasswordOnly = false;
      Util.arrayCopy(scratchPad,(short)0,repository.deviceLockedTimestamp,(short)0,(short)repository.deviceLockedTimestamp.length);
    }
    sendError(apdu,KMError.OK);
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
    //Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
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
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormat = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 6);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormat);
    KMArray.cast(argsProto).add((short) 2, blob);
    KMArray.cast(argsProto).add((short) 3, blob); // Cert - DER encoded issuer
    KMArray.cast(argsProto).add((short) 4, blob); // Cert - Expiry Time
    KMArray.cast(argsProto).add((short) 5, blob); // Cert - Auth Key Id

    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // key params should have os patch, os version and verified root of trust
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMArray.cast(args).get((short) 1);
    data[IMPORTED_KEY_BLOB] = KMArray.cast(args).get((short) 2);
    // Key format must be RAW format
    tmpVariables[0] = KMEnum.cast(tmpVariables[0]).getVal();
    if (tmpVariables[0] != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    data[ORIGIN] = KMType.IMPORTED;

    // get algorithm - only RSA keys expected
    tmpVariables[0] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.RSA) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // get digest - only SHA256 supported
    tmpVariables[0] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST,data[KEY_PARAMETERS]);
    if(tmpVariables[0] != KMType.INVALID_VALUE){
      if(KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short)0);
      if(tmpVariables[0] != KMType.SHA2_256) KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }else{
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // get padding - only PKCS1 supported
    tmpVariables[0] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING,data[KEY_PARAMETERS]);
    if(tmpVariables[0] != KMType.INVALID_VALUE){
      if(KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short)0);
      if(tmpVariables[0] != KMType.RSA_PKCS1_1_5_SIGN) KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }else{
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[0] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,data[KEY_PARAMETERS]);
    if(tmpVariables[0] != KMType.INVALID_VALUE){
      if(KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short)0);
      if(tmpVariables[0] != KMType.ATTEST_KEY) KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }else{
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[0] = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE,data[KEY_PARAMETERS]);
    if(tmpVariables[0] != KMType.INVALID_VALUE){
      tmpVariables[0] = KMIntegerTag.cast(tmpVariables[0]).getValue();
      if(KMInteger.cast(tmpVariables[0]).getSignificantShort() != 0 || KMInteger.cast(tmpVariables[0]).getShort() != (short)2048){
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }else{
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Import Rsa Key - initializes data[PUB_KEY] and data[SECRET]
    importRSAKey(scratchPad);
    // persist key
    repository.persistAttestationKey(data[PUB_KEY], data[SECRET]);
    // save issuer - DER Encoded
    tmpVariables[0] = KMArray.cast(args).get((short)3);
    repository.setIssuer(KMByteBlob.cast(tmpVariables[0]).getBuffer(),
      KMByteBlob.cast(tmpVariables[0]).getStartOff(),
      KMByteBlob.cast(tmpVariables[0]).length());
    // save expiry time - UTC or General Time - YYMMDDhhmmssZ or YYYYMMDDhhmmssZ.
    tmpVariables[0] = KMArray.cast(args).get((short)4);
    repository.setCertExpiryTime(KMByteBlob.cast(tmpVariables[0]).getBuffer(),
      KMByteBlob.cast(tmpVariables[0]).getStartOff(),
      KMByteBlob.cast(tmpVariables[0]).length());
    // Auth Key Id - from cert associated with imported attestation key.
    tmpVariables[0] = KMArray.cast(args).get((short)5);
    repository.setAuthKeyId(KMByteBlob.cast(tmpVariables[0]).getBuffer(),
      KMByteBlob.cast(tmpVariables[0]).getStartOff(),
      KMByteBlob.cast(tmpVariables[0]).length());
    //persist attestation Ids - if any is missing then exception occurs
    saveAttId(KMType.ATTESTATION_ID_BRAND);
    saveAttId(KMType.ATTESTATION_ID_DEVICE);
    saveAttId(KMType.ATTESTATION_ID_PRODUCT);
    saveAttId(KMType.ATTESTATION_ID_MANUFACTURER);
    saveAttId(KMType.ATTESTATION_ID_MODEL);
    saveAttId(KMType.ATTESTATION_ID_IMEI);
    saveAttId(KMType.ATTESTATION_ID_MEID);
    saveAttId(KMType.ATTESTATION_ID_SERIAL);
    // Change the state to ACTIVE
    if (keymasterState == KMKeymasterApplet.FIRST_SELECT_STATE) {
      provisionDone = true;
      if (setBootParamsDone) {
        keymasterState = KMKeymasterApplet.ACTIVE_STATE;
      }
    }
    sendError(apdu, KMError.OK);
  }

  private void saveAttId(short attTag){
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG, attTag,data[KEY_PARAMETERS]);
    if(tmpVariables[0] != KMType.INVALID_VALUE){
      tmpVariables[0] = KMByteTag.cast(tmpVariables[0]).getValue();
      repository.persistAttId(
        mapToAttId(attTag),
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length());
    }else{
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  private byte mapToAttId(short attTag){
    switch (attTag){
      case KMType.ATTESTATION_ID_BRAND:
        return repository.ATT_ID_BRAND;
      case KMType.ATTESTATION_ID_DEVICE:
        return repository.ATT_ID_DEVICE;
      case KMType.ATTESTATION_ID_IMEI:
        return repository.ATT_ID_IMEI;
      case KMType.ATTESTATION_ID_MANUFACTURER:
        return repository.ATT_ID_MANUFACTURER;
      case KMType.ATTESTATION_ID_MEID:
        return repository.ATT_ID_MEID;
      case KMType.ATTESTATION_ID_MODEL:
        return repository.ATT_ID_MODEL;
      case KMType.ATTESTATION_ID_PRODUCT:
        return repository.ATT_ID_PRODUCT;
      case KMType.ATTESTATION_ID_SERIAL:
        return repository.ATT_ID_SERIAL;
    }
    KMException.throwIt(KMError.INVALID_TAG);
    return (byte)0xFF; // should never happen
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
    // Create HMAC Sharing Parameters
    tmpVariables[2] = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(tmpVariables[2]).setNonce(
      KMByteBlob.instance(repository.getHmacNonce(), (short) 0,
      repository.HMAC_SEED_NONCE_SIZE));
    KMHmacSharingParameters.cast(tmpVariables[2]).setSeed(KMByteBlob.instance((short)0));
    // prepare the response
    tmpVariables[3] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[3]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[3]).add((short) 1, tmpVariables[2]);
    // Encode the response
    bufferLength = encoder.encode(tmpVariables[3], buffer, bufferStartOffset);
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
    tmpVariables[1] = KMHmacSharingParameters.exp();
    tmpVariables[0] = KMArray.exp(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short)1);
    KMArray.cast(tmpVariables[2]).add((short) 0, tmpVariables[0]); // Vector of hmac params
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[2], buffer, bufferStartOffset, bufferLength);
    data[HMAC_SHARING_PARAMS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    // Concatenate HMAC Params
    tmpVariables[0] = 0;
    tmpVariables[1] = KMArray.cast(data[HMAC_SHARING_PARAMS]).length();//total number of params
    tmpVariables[5] = 0; // index in scratchPad
    while (tmpVariables[0] < tmpVariables[1]) {
      // read HmacSharingParam
      tmpVariables[2] = KMArray.cast(data[HMAC_SHARING_PARAMS]).get(tmpVariables[0]);
      // get seed - 32 bytes max
      tmpVariables[3] = KMHmacSharingParameters.cast(tmpVariables[2]).getSeed();
      tmpVariables[4] = KMByteBlob.cast(tmpVariables[3]).length();
      // if seed is present
      if (tmpVariables[4] == repository.HMAC_SEED_NONCE_SIZE) {
        // then copy that to scratchPad
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(tmpVariables[3]).getBuffer(),
            KMByteBlob.cast(tmpVariables[3]).getStartOff(),
            scratchPad,
            tmpVariables[5],// index in scratch pad
            tmpVariables[4]);
        tmpVariables[5] += tmpVariables[4]; // increment by seed length
      }
      // if nonce is present get nonce - 32 bytes
      tmpVariables[3] = KMHmacSharingParameters.cast(tmpVariables[2]).getNonce();
      tmpVariables[4] = KMByteBlob.cast(tmpVariables[3]).length();
      // if nonce is not present
      if (tmpVariables[4] != repository.HMAC_SEED_NONCE_SIZE) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      // copy nonce to scratchPad
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(tmpVariables[3]).getBuffer(),
          KMByteBlob.cast(tmpVariables[3]).getStartOff(),
          scratchPad,
          tmpVariables[5],
          tmpVariables[4]);
      tmpVariables[5] += tmpVariables[4]; // increment by nonce length
      tmpVariables[0]++; // go to next hmac param in the vector
    }
    // ckdf to derive hmac key - scratch pad has the context
    HMACKey key =
        cryptoProvider.cmacKdf(
            repository.getSharedKey(), ckdfLable , scratchPad, (short) 0, tmpVariables[5]);
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
    // TODO currently only os version and os patch level are upgraded.
    tmpVariables[0] = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_VERSION, data[HW_PARAMETERS]);
    tmpVariables[0] = KMIntegerTag.cast(tmpVariables[0]).getValue();
    tmpVariables[1] = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    tmpVariables[1] = KMIntegerTag.cast(tmpVariables[1]).getValue();
    tmpVariables[2] = KMInteger.uint_32(repository.osVersion,(short)0);
    tmpVariables[3] = KMInteger.uint_32(repository.osPatch,(short)0);
    tmpVariables[4] = KMInteger.uint_8((byte)0);
    if(tmpVariables[0] != KMType.INVALID_VALUE){
      // os version in key characteristics must be less the os version stored in javacard or the
      // stored version must be zero. Then only upgrade is allowed else it is invalid argument.
      if(KMInteger.compare(tmpVariables[0], tmpVariables[2]) != -1 &&
      KMInteger.compare(tmpVariables[2], tmpVariables[4]) != 0){
      //Key Should not be upgraded, but error code should be OK, As per VTS.
        //KMException.throwIt(KMError.INVALID_ARGUMENT);
      	tmpVariables[5] = KMError.INVALID_ARGUMENT;
      }
    }
    if(tmpVariables[1] != KMType.INVALID_VALUE){
      // The key characteristics should have has os patch level < os patch level stored in javacard
      // then only upgrade is allowed.
      if(KMInteger.compare(tmpVariables[1], tmpVariables[3]) != -1){
      	//Key Should not be upgraded, but error code should be OK, As per VTS.
        //KMException.throwIt(KMError.INVALID_ARGUMENT);
      	tmpVariables[5] = KMError.INVALID_ARGUMENT;
      }
    }
/*    KMIntegerTag.getValue(
            scratchPad, (short) 0, );
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
    }*/
    // remove Auth Tag
    if(tmpVariables[5] != KMError.INVALID_ARGUMENT) {
    	repository.removeAuthTag(data[AUTH_TAG]);
    	// copy origin
    	data[ORIGIN] = KMEnumTag.getValue(KMType.ORIGIN, data[HW_PARAMETERS]);
    	// create new key blob with current os version etc.
    	createEncryptedKeyBlob(scratchPad);
    	// persist new auth tag for rollback resistance.
    	repository.persistAuthTag(data[AUTH_TAG]);
    } else {
      data[KEY_BLOB] = KMByteBlob.instance((short)0);
    }
    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_BLOB]);
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
    tmpVariables[1] = KMArray.instance((short) 12);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[2]); // Key Params of wrapped key
    KMArray.cast(tmpVariables[1]).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT)); // Key Format
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp()); // Wrapped Import Key Blob
    KMArray.cast(tmpVariables[1]).add((short) 3, KMByteBlob.exp()); // Auth Tag
    KMArray.cast(tmpVariables[1]).add((short) 4, KMByteBlob.exp()); // IV - Nonce
    KMArray.cast(tmpVariables[1]).add((short) 5, KMByteBlob.exp()); // Encrypted Transport Key
    KMArray.cast(tmpVariables[1]).add((short) 6, KMByteBlob.exp()); // Wrapping Key KeyBlob
    KMArray.cast(tmpVariables[1]).add((short) 7, KMByteBlob.exp()); // Masking Key
    KMArray.cast(tmpVariables[1]).add((short) 8, tmpVariables[2]); // Un-wrapping Params
    KMArray.cast(tmpVariables[1]).add((short) 9, KMByteBlob.exp()); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.cast(tmpVariables[1]).add((short) 10, KMInteger.exp()); // Password Sid
    KMArray.cast(tmpVariables[1]).add((short) 11, KMInteger.exp()); // Biometric Sid
    short i = KMArray.cast(tmpVariables[1]).length();
    // Decode the arguments
    short args = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    // Step -0 - check whether the key format and algorithm supported
    // read algorithm
    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    tmpVariables[1] = KMEnumTag.getValue(KMType.ALGORITHM, tmpVariables[0]);
    // read key format
    tmpVariables[2] = KMArray.cast(args).get((short) 1);
    tmpVariables[2] = KMEnum.cast(tmpVariables[2]).getVal();
    // import of RSA and EC not supported with pkcs8 or x509 format
    if ((tmpVariables[1] == KMType.RSA || tmpVariables[1] == KMType.EC) &&
      (tmpVariables[2] != KMType.RAW)) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    // Step -1 parse the wrapping key blob
    // read wrapping key blob
    data[KEY_BLOB] = KMArray.cast(args).get((short) 6);
    // read un wrapping key params
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 8);
    // Read App Id and App Data if any from un wrapping key params
    data[APP_ID] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    data[APP_DATA] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    // parse the wrapping key blob
    parseEncryptedKeyBlob(scratchPad);
    // check whether the wrapping key is RSA with purpose KEY_WRAP, padding RSA_OAEP and Digest SHA2_256.
    if(KMEnumTag.getValue(KMType.ALGORITHM,data[HW_PARAMETERS]) != KMType.RSA ){
      KMException.throwIt(KMError.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
    }
    if(!KMEnumArrayTag.contains(KMType.DIGEST,KMType.SHA2_256, data[HW_PARAMETERS])){
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    if(!KMEnumArrayTag.contains(KMType.PADDING,KMType.RSA_OAEP, data[HW_PARAMETERS])){
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    if(!KMEnumArrayTag.contains(KMType.PURPOSE,KMType.WRAP_KEY, data[HW_PARAMETERS])){
      KMException.throwIt((KMError.INCOMPATIBLE_PURPOSE));
    }
    // Step 2 - decrypt the encrypted transport key - 32 bytes AES-GCM key
    // create rsa decipher
    KMCipher cipher =
      cryptoProvider.createRsaDecipher(
        //KMCipher.PAD_PKCS1, // TODO remove this when KMCipher.PAD_PKCS1_OAEP_SHA256 is supported
    	KMCipher.PAD_PKCS1_OAEP_SHA256,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length());
    //read encrypted transport key from args
    tmpVariables[0] = KMArray.cast(args).get((short) 5);
    // Decrypt the transport key
    tmpVariables[1] =
      cipher.doFinal(
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length(),
        scratchPad,
        (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[1]);
    cryptoProvider.delete(cipher);
    // Step 3 - XOR the decrypted AES-GCM key with with masking key
    // read masking key
    tmpVariables[0] = KMArray.cast(args).get((short) 7);
    tmpVariables[1] = KMByteBlob.cast(tmpVariables[0]).length();
    // Length of masking key and transport key must be same.
    if (tmpVariables[1] != KMByteBlob.cast(data[SECRET]).length()) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    tmpVariables[2] = 0; // index
    // Xor every byte of masking and key and store the result in data[SECRET]
    while (tmpVariables[2] < tmpVariables[1]) {
      tmpVariables[3] = (short)(((short)KMByteBlob.cast(tmpVariables[0]).get(tmpVariables[2]))&0x00FF);
      tmpVariables[4] = (short)(((short)KMByteBlob.cast(data[SECRET]).get(tmpVariables[2]))&0x00FF);
      KMByteBlob.cast(data[SECRET]).add(tmpVariables[2], (byte)(tmpVariables[3]^tmpVariables[4]));
      tmpVariables[2]++;
    }
    // Step 4 - AES-GCM decrypt the wrapped key
    data[INPUT_DATA] = KMArray.cast(args).get((short) 2);
    data[AUTH_DATA] = KMArray.cast(args).get((short) 9);
    data[AUTH_TAG] = KMArray.cast(args).get((short) 3);
    data[NONCE] = KMArray.cast(args).get((short) 4);
    Util.arrayFillNonAtomic(scratchPad,(short)0, KMByteBlob.cast(data[INPUT_DATA]).length(),(byte)0);
    AESKey key =
      cryptoProvider.createAESKey(
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());
    boolean verification =
      cryptoProvider.aesGCMDecrypt(
        key,
        KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
        KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
        KMByteBlob.cast(data[INPUT_DATA]).length(),
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
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    cryptoProvider.delete(key);

    // Step 5 - Import decrypted key
    data[ORIGIN] = KMType.SECURELY_IMPORTED;
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    // create key blob array
    data[IMPORTED_KEY_BLOB] = KMArray.instance((short)1);
    // add the byte blob containing decrypted input data
    KMArray.cast(data[IMPORTED_KEY_BLOB]).add((short)0,
      KMByteBlob.instance(scratchPad,(short)0, KMByteBlob.cast(data[INPUT_DATA]).length()));
    // encode the key blob
    tmpVariables[0] = repository.alloc((short)(KMByteBlob.cast(data[INPUT_DATA]).length()+16));
    tmpVariables[1] = encoder.encode(data[IMPORTED_KEY_BLOB],repository.getHeap(),tmpVariables[0]);
    data[IMPORTED_KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), tmpVariables[0], tmpVariables[1]);
    importKey(apdu,scratchPad);
  }

  private void processAttestKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyBlob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 2);
    KMArray.cast(argsProto).add((short) 0, keyBlob);
    KMArray.cast(argsProto).add((short) 1, keyparams);
    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    data[KEY_BLOB] = KMArray.cast(args).get((short)0);
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 1);
    //parse key blob
    parseEncryptedKeyBlob(scratchPad);
    // The key which is being attested should be asymmetric i.e. RSA or EC
    tmpVariables[0] = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    if(tmpVariables[0] != KMType.RSA && tmpVariables[0] != KMType.EC){
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    boolean rsaCert = true;
    if(tmpVariables[0] == KMType.EC) rsaCert = false;
    // Save attestation application id - must be present.
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ATTESTATION_APPLICATION_ID,data[KEY_PARAMETERS]);
    if(tmpVariables[0] == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    // Save attestation challenge
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ATTESTATION_CHALLENGE,data[KEY_PARAMETERS]);
    if(tmpVariables[0] == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // extract key characteristics
    //makeKeyCharacteristics(scratchPad);
    // unique id byte blob - uses application id and temporal month count of creation time.
    tmpVariables[0] = makeUniqueId(scratchPad);
    // validity period
    // active time or creation time - byte blob
    // TODO current assumption is that if active and creation time are missing from characteristics then
    //  then it is an error. Alternative can be to use 1 Jan 1970 as validity start period.
    tmpVariables[1] = KMKeyParameters.findTag(KMType.DATE_TAG,KMType.ACTIVE_DATETIME,data[SW_PARAMETERS]);
    if(tmpVariables[1] != KMType.INVALID_VALUE) tmpVariables[1] = KMIntegerTag.cast(tmpVariables[1]).getValue();
    else {
      tmpVariables[1] = KMKeyParameters.findTag(KMType.DATE_TAG,KMType.CREATION_DATETIME,data[SW_PARAMETERS]);
      if(tmpVariables[1] == KMType.INVALID_VALUE) KMException.throwIt(KMError.INVALID_KEY_BLOB);
      tmpVariables[1] = KMIntegerTag.cast(tmpVariables[1]).getValue();
    }
    // convert milliseconds to UTC date. Start of validity period has to be UTC.
    tmpVariables[1] = convertToDate(tmpVariables[1], scratchPad, true);
    // expiry time - byte blob
    tmpVariables[2] = KMKeyParameters.findTag(KMType.DATE_TAG,KMType.USAGE_EXPIRE_DATETIME,data[SW_PARAMETERS]);
    if(tmpVariables[2] != KMType.INVALID_VALUE) {
      // compare if the expiry time is greater then 2051 then use generalized time format else use
      // utc time format
      tmpVariables[2] = KMIntegerTag.cast(tmpVariables[1]).getValue();
      tmpVariables[3] = KMInteger.uint_64(firstJan2051,(short)0);
      if(KMInteger.compare(tmpVariables[2],tmpVariables[3])>=0) tmpVariables[2]=convertToDate(tmpVariables[2],scratchPad, false);
      else tmpVariables[2] = convertToDate(tmpVariables[1], scratchPad, true);
    } else { // if no expiry tag is present then use the attestation key certificate's expiry time
      // that was provisioned in the provision command. This will be in Generalized or UTC time
      tmpVariables[2] = KMByteBlob.instance(repository.getCertDataBuffer(),
        repository.getCertExpiryTime(),repository.getCertExpiryTimeLen());
    }

    // buffer for cert - we allocate 1024 bytes buffer - should be sufficient for 2Kbits RSA cert
    tmpVariables[3] = KMByteBlob.instance((short)2048);
    // read att application id.
    tmpVariables[4] = KMKeyParameters.findTag(KMType.BYTES_TAG,KMType.ATTESTATION_APPLICATION_ID,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE) tmpVariables[4] = KMByteTag.cast(tmpVariables[4]).getValue();
    else tmpVariables[4] = 0;
    // read att challenge
    tmpVariables[5] = KMKeyParameters.findTag(KMType.BYTES_TAG,KMType.ATTESTATION_CHALLENGE,data[KEY_PARAMETERS]);
    if(tmpVariables[5] == KMType.INVALID_VALUE) KMException.throwIt(KMError.ATTESTATION_CHALLENGE_MISSING);
    tmpVariables[5] = KMByteTag.cast(tmpVariables[5]).getValue();

    // create X509 certificate.
    KMX509Certificate.encodeCert(tmpVariables[3]/*buf*/, data[KEY_CHARACTERISTICS]/*key char*/,
    tmpVariables[0]/*unique Id*/,tmpVariables[1]/*start*/,tmpVariables[2]/*end*/,
        data[PUB_KEY]/*pub key/modulus*/,tmpVariables[5],tmpVariables[4], rsaCert);

    // Now sign the cert
    // Create signer
    Signature signer = cryptoProvider.createRsaSigner(
      MessageDigest.ALG_SHA_256,
      KMCipher.PAD_PKCS1,
      repository.getAttKeyExponent(),(short)0, repository.ATT_KEY_EXP_SIZE,
      repository.getAttKeyModulus(),(short)0,repository.ATT_KEY_MOD_SIZE);
    //Sign the cert - returns the length of complete cert
    tmpVariables[1] = KMX509Certificate.sign(signer);

    // Send the response back. This is slightly different we do not copy the cert blob again.
    // We just add CBOR encoding around it.
    // Encode the response
    buffer = KMX509Certificate.getBuffer();
    // add CBOR header and elements
    bufferStartOffset = encoder.encodeCert(KMX509Certificate.getBuffer(), KMX509Certificate.getBufferStart(),
      KMX509Certificate.getCertStart(),KMX509Certificate.getCertLength());
    bufferLength = (short)(KMX509Certificate.getCertLength() + (KMX509Certificate.getCertStart()- bufferStartOffset));
    sendOutgoing(apdu);
  }

  private short convertToDate(short time, byte[] scratchPad, boolean utcFlag){
    short yrsCount=0;
    short monthCount=0;
    short dayCount=0;
    short hhCount=0;
    short mmCount=0;
    short ssCount=0;
    byte Z = 0x5A;
    boolean from2020 = true;
    Util.arrayFillNonAtomic(scratchPad,(short)0,(short)256,(byte)0);
    Util.arrayCopyNonAtomic(
      KMInteger.cast(time).getBuffer(),
      KMInteger.cast(time).getStartOff(),
      scratchPad,(short)(8-KMInteger.cast(time).length()),KMInteger.cast(time).length());
    // If the time is less then 1 Jan 2020 then it is an error
    if(Util.arrayCompare(scratchPad,(short)0,firstJan2020,(short)0,(short)8) < 0){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if(utcFlag && Util.arrayCompare(scratchPad,(short)0,firstJan2051,(short)0,(short)8) >=0){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    if(Util.arrayCompare(scratchPad,(short)0,firstJan2051,(short)0,(short)8) < 0){
      Util.arrayCopyNonAtomic(firstJan2020,(short)0,scratchPad,(short)8, (short)8);
      subtract(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }else{
      from2020 = false;
      Util.arrayCopyNonAtomic(firstJan2051,(short)0,scratchPad,(short)8, (short)8);
      subtract(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }
    // divide the given time with four yrs msec count
    if(Util.arrayCompare(scratchPad,(short)0,fourYrsMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(fourYrsMsec,(short)0,scratchPad,(short)8, (short)8);
      yrsCount = divide(scratchPad,(short)0, (short)8,(short)16); // quotient is multiple of 4
      yrsCount = (short)(yrsCount*4); // number of yrs.
      // copy reminder as new dividend
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }
    // divide the given time with one yr msec count
    if(Util.arrayCompare(scratchPad,(short)0,oneYearMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(oneYearMsec,(short)0, scratchPad,(short)8, (short)8);
      yrsCount += divide(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }
    // total yrs from 1970
    if(from2020) yrsCount = (short)(2020+yrsCount);
    else yrsCount = (short)(2051+yrsCount);

    // divide the given time with one month msec count
    if(Util.arrayCompare(scratchPad,(short)0,oneMonthMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(oneMonthMsec,(short)0, scratchPad,(short)8, (short)8);
      monthCount = divide(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }

    // divide the given time with one day msec count
    if(Util.arrayCompare(scratchPad,(short)0,oneDayMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(oneDayMsec,(short)0, scratchPad,(short)8, (short)8);
      dayCount = divide(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }

    // divide the given time with one hour msec count
    if(Util.arrayCompare(scratchPad,(short)0,oneHourMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(oneHourMsec,(short)0, scratchPad,(short)8, (short)8);
      hhCount = divide(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }

    // divide the given time with one minute msec count
    if(Util.arrayCompare(scratchPad,(short)0,oneMinMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(oneMinMsec,(short)0, scratchPad,(short)8, (short)8);
      mmCount = divide(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }

    // divide the given time with one second msec count
    if(Util.arrayCompare(scratchPad,(short)0,oneSecMsec,(short)0,(short)8) >=0){
      Util.arrayCopyNonAtomic(oneSecMsec,(short)0, scratchPad,(short)8, (short)8);
      ssCount = divide(scratchPad,(short)0, (short)8,(short)16);
      Util.arrayCopyNonAtomic(scratchPad,(short)16, scratchPad, (short)0,(short)8);
    }

    // Now convert to ascii string YYMMDDhhmmssZ or YYYYMMDDhhmmssZ
    Util.arrayFillNonAtomic(scratchPad,(short)0,(short)256,(byte)0);
    short len = numberToString(yrsCount, scratchPad,(short)0); // returns YYYY
    len += numberToString(monthCount, scratchPad, len);
    len += numberToString(dayCount, scratchPad,len);
    len += numberToString(hhCount, scratchPad,len);
    len += numberToString(mmCount, scratchPad,len);
    len += numberToString(ssCount, scratchPad,len);
    scratchPad[len] = Z;
    len++;
    if(utcFlag) return KMByteBlob.instance(scratchPad,(short)2,(short)(len -2)); // YY
    else return KMByteBlob.instance(scratchPad,(short)0,len); // YYYY
  }

  private short numberToString(short number, byte[] scratchPad, short offset){
    byte zero = 0x30;
    byte len = 2;
    byte digit = 0;
    if(number > 999) len = 4;
    byte index = len;
    while(index > 0){
      digit = (byte)(number%10);
      number = (short)(number / 10);
      scratchPad[(short)(offset+index-1)]=(byte)(digit+zero);
      index--;
    }
    return len;
  }

  private short makeUniqueId(byte[] scratchPad){
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BOOL_TAG,KMType.INCLUDE_UNIQUE_ID,data[HW_PARAMETERS]);
    if(tmpVariables[0] == KMType.INVALID_VALUE){
      return 0;
    }
    // Concatenate T||C||R
    // temporal count T
    tmpVariables[0] = KMKeyParameters.findTag(KMType.DATE_TAG,KMType.CREATION_DATETIME,data[SW_PARAMETERS]);
    if(tmpVariables[0] == KMType.INVALID_VALUE) KMException.throwIt(KMError.INVALID_TAG);
    tmpVariables[0] = KMIntegerTag.cast(tmpVariables[0]).getValue();
    tmpVariables[0] = countTemporalCount(tmpVariables[0], scratchPad); // just a short count
    Util.setShort(scratchPad,(short)0,tmpVariables[0]);
    tmpVariables[1] = (short)2;

    // Application Id C
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG,KMType.ATTESTATION_APPLICATION_ID,data[KEY_PARAMETERS]);
    if(tmpVariables[0] == KMType.INVALID_VALUE) KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    tmpVariables[0] = KMByteTag.cast(tmpVariables[0]).getValue();
    Util.arrayCopyNonAtomic(
      KMByteBlob.cast(tmpVariables[0]).getBuffer(),
      KMByteBlob.cast(tmpVariables[0]).getStartOff(),
      scratchPad,tmpVariables[1],
      KMByteBlob.cast(tmpVariables[0]).length()
    );
    tmpVariables[1] += KMByteBlob.cast(tmpVariables[0]).length();

    // Reset After Rotation R - it will be part of HW Enforced key characteristics
    scratchPad[tmpVariables[1]] = (byte)0;
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BOOL_TAG,KMType.RESET_SINCE_ID_ROTATION, data[HW_PARAMETERS]);
    if(tmpVariables[0] != KMType.INVALID_VALUE) {
      scratchPad[tmpVariables[1]]  = (byte) 0x01;
    }
    tmpVariables[1]++;

    // Sign - signature becomes unique id of 32 bits. Use 128 bits master key as an hmac key.
    HMACKey key = cryptoProvider.createHMACKey(repository.getMasterKeySecret(),(short)0,
      (short)repository.getMasterKeySecret().length);
    tmpVariables[0] = KMByteBlob.instance((short)32);
    tmpVariables[1]=cryptoProvider.hmacSign(key,scratchPad,(short)0,tmpVariables[1],
      KMByteBlob.cast(tmpVariables[0]).getBuffer(),
      KMByteBlob.cast(tmpVariables[0]).getStartOff());

    if(tmpVariables[1] != 32){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return tmpVariables[0];
  }

  private short countTemporalCount(short time, byte[] scratchPad){
    Util.arrayFillNonAtomic(scratchPad,(short)0,(short)24, (byte)0);
    short result = 0;
    Util.arrayCopyNonAtomic(KMInteger.cast(time).getBuffer(),
      KMInteger.cast(time).getStartOff(),
      scratchPad,(short)(8-KMInteger.cast(time).length()),
      KMInteger.cast(time).length());
    Util.arrayCopyNonAtomic(oneMonthMsec,(short)0,scratchPad,(short)8,(short)8);
    result = divide(scratchPad, (short)0,(short)8,(short)16);
    return result;
  }

  private void processDestroyAttIdsCmd(APDU apdu) {
    repository.deleteAttIds();
    sendError(apdu, KMError.OK);
  }

  private void processVerifyAuthorizationCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private void processAbortOperationCmd(APDU apdu) {
    receiveIncoming(apdu);
    tmpVariables[1] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[1]).add((short) 0, KMInteger.exp());
    tmpVariables[2] = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[OP_HANDLE] = KMArray.cast(tmpVariables[2]).get((short) 0);
    tmpVariables[1] = KMInteger.cast(data[OP_HANDLE]).getShort();
    KMOperationState op = repository.findOperation(tmpVariables[1]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    repository.releaseOperation(op);
    sendError(apdu, KMError.OK);
  }

  private void processFinishOperationCmd(APDU apdu) {
    // TODO AES GCM
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
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
    data[SIGNATURE] = KMArray.cast(tmpVariables[2]).get((short) 3);
    data[HW_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 4);
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 5);
    // Check Operation Handle
    tmpVariables[1] = KMInteger.cast(data[OP_HANDLE]).getShort();
    KMOperationState op = repository.findOperation(tmpVariables[1]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    //Authorize the finish operation
    authorizeUpdateFinishOperation(op, scratchPad);
    //Finish trusted Confirmation operation
    switch(op.getPurpose()){
      case KMType.SIGN:
        finishTrustedConfirmationOperation(op);
      case KMType.VERIFY:
        finishSigningVerifyingOperation(op,scratchPad);
        break;
      case KMType.ENCRYPT:
        finishEncryptOperation(op, scratchPad);
        break;
      case KMType.DECRYPT:
        finishDecryptOperation(op,scratchPad);
        break;
    }
    // Remove the operation handle
    repository.releaseOperation(op);
    // make response
    tmpVariables[1] = KMArray.instance((short) 0);
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short) 3);
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    KMArray.cast(tmpVariables[2]).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(tmpVariables[2]).add((short) 1, tmpVariables[1]);
    KMArray.cast(tmpVariables[2]).add((short) 2, data[OUTPUT_DATA]);

    // Encode the response
    bufferLength = encoder.encode(tmpVariables[2], buffer, bufferStartOffset);
    sendOutgoing(apdu);
    }

    private void finishEncryptOperation(KMOperationState op, byte[] scratchPad) {
      short len = KMByteBlob.cast(data[INPUT_DATA]).length();
      switch(op.getAlgorithm()){
        // Only supported for testing purpose
        // TODO remove this later on
        case KMType.RSA:
          data[OUTPUT_DATA] = KMByteBlob.instance((short)256);
          // Fill the scratch pad with zero
          Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
          if(op.getPadding() == KMType.PADDING_NONE){
              // Length cannot be greater then key size according to jcard sim
              if(len >= 256) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
 /*             // If Length is same as key size then
              // compare the data with key value - date should be less then key value.
              if(len == 255) {
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
*/            // copy input data to scratchpad.
          //TODO the current jacrdsim implementation requires 255 bytes when using encryption with no pad
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)(255 - len),len);
            len = (short)255;
          }else{
            //copy input data to scratchpad.
          Util.arrayCopyNonAtomic(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            scratchPad, (short)0,len);
          }
          len = op.getCipher().doFinal(
            scratchPad, (short)0,len, KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
            break;
        case KMType.AES:
          if(op.getBlockMode() == KMType.GCM){
            finishAesGcmOperation(op, scratchPad);
            return;
          }
        case KMType.DES:
              if(op.getAlgorithm() == KMType.AES){
                tmpVariables[0] = KMCipher.AES_BLOCK_SIZE;
              }else{
                tmpVariables[0] = KMCipher.DES_BLOCK_SIZE;
              }
              //If no padding then data length must be block aligned
              if ((op.getBlockMode() == KMType.ECB || op.getBlockMode() == KMType.CBC) &&
            		  op.getPadding() == KMType.PADDING_NONE && ((short)(len % tmpVariables[0]) != 0)){
                KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
              }
              //If padding i.e. pkcs7 then add padding to right
              if(op.getPadding() == KMType.PKCS7){
                // padding bytes
                if(len % tmpVariables[0] == 0) tmpVariables[1] = tmpVariables[0];
                else tmpVariables[1] = (short)(tmpVariables[0] - (len % tmpVariables[0]));
                // final len with padding
                len = (short)(len+tmpVariables[1]);
                // intermediate buffer to copy input data+padding
                tmpVariables[2] = KMByteBlob.instance(len);
                // fill in the padding
                Util.arrayFillNonAtomic(
                  KMByteBlob.cast(tmpVariables[2]).getBuffer(),
                  KMByteBlob.cast(tmpVariables[2]).getStartOff(),
                  KMByteBlob.cast(tmpVariables[2]).length(),
                  (byte)tmpVariables[1]);
                //copy the input data
                Util.arrayCopyNonAtomic(
                  KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                  KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                  KMByteBlob.cast(tmpVariables[2]).getBuffer(),
                  KMByteBlob.cast(tmpVariables[2]).getStartOff(),
                  KMByteBlob.cast(data[INPUT_DATA]).length());
                data[INPUT_DATA] = tmpVariables[2];
              }
              data[OUTPUT_DATA] = KMByteBlob.instance(len);
          len = op.getCipher().doFinal(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            KMByteBlob.cast(data[INPUT_DATA]).length(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
          break;
      }
  }

  private void finishDecryptOperation(KMOperationState op, byte[] scratchPad) {
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    switch(op.getAlgorithm()){
      // Only supported for testing purpose
      // TODO remove this later on
      case KMType.RSA:
        // Fill the scratch pad with zero
        Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
        if(op.getPadding() == KMType.PADDING_NONE &&
          len != 256) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        len = op.getCipher().doFinal(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          len, scratchPad,
          (short)0);
        data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad,(short)0, len);
        break;
      case KMType.AES:
        if(op.getBlockMode() == KMType.GCM){
          finishAesGcmOperation(op, scratchPad);
          return;
        }
      case KMType.DES:
        if(op.getAlgorithm() == KMType.AES){
          tmpVariables[0] = KMCipher.AES_BLOCK_SIZE;
        }else{
          tmpVariables[0] = KMCipher.DES_BLOCK_SIZE;
        }
        if((op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.ECB)&& len > 0 &&
          (len%tmpVariables[0]) != 0)KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        tmpVariables[1] = repository.alloc(len);
        byte[] heap = repository.getHeap();
        len = op.getCipher().doFinal(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(), len,heap,
          tmpVariables[1]);
        //remove padding bytes if pkcs7
        if(op.getPadding() == KMType.PKCS7 && len >0) {
        	//verify if padding is corrupted.
            byte paddingByte = heap[(short)(tmpVariables[1]+len -1)];
            //padding byte always should be <= blocksize
            if((short)paddingByte > tmpVariables[0] ||
            		(short)paddingByte <= 0) KMException.throwIt(KMError.INVALID_ARGUMENT);
        	len = (short)(len - (short)paddingByte);
        }
        //If padding i.e. pkcs7 then add padding to right
        data[OUTPUT_DATA] = KMByteBlob.instance(heap, tmpVariables[1], len);
        break;
    }
  }

  //update operation should send 0x00 for finish variable, where as finish operation
  //should send 0x01 for finish variable.
  private void updateAAD(KMOperationState op, byte finish){
    // Is input data absent
    if(data[INPUT_DATA] == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Update can be called either to update auth data, update input data or both.
    // But if it is called for neither then return error.
    tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
    tmpVariables[1] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ASSOCIATED_DATA,data[KEY_PARAMETERS]);
    //For Finish operation the input data can be zero length and associated data can be INVALID_VALUE
    //For update operation either input data or associated data should be present.
    if(tmpVariables[1] == KMType.INVALID_VALUE && tmpVariables[0] <=0 && finish == 0x00){
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    // Check if associated data is present and update aad still allowed by the operation.
    if(tmpVariables[1] != KMType.INVALID_VALUE){
      if (!op.isAesGcmUpdateAllowed()) {
        KMException.throwIt(KMError.INVALID_TAG);
      }
      // If allowed the update the aad
      tmpVariables[1] = KMByteTag.cast(tmpVariables[1]).getValue();
      op.getCipher().updateAAD(
        KMByteBlob.cast(tmpVariables[1]).getBuffer(),
        KMByteBlob.cast(tmpVariables[1]).getStartOff(),
        KMByteBlob.cast(tmpVariables[1]).length());
    }
  }
  
  private void updateAesGcmOperation(KMOperationState op, APDU apdu) {
    updateAAD(op, (byte) 0x00);
    // Now handle the input data
    tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
    // If the input data is non zero length
    if (tmpVariables[0] > 0) {
      // input data must be block aligned.
      if (tmpVariables[0] % AES_BLOCK_SIZE != 0) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
      }
      // no more future updateAAD allowed.
      if (op.isAesGcmUpdateAllowed()) {
        op.setAesGcmUpdateComplete();
      }
      // Adjust input data wrt to last aes block and saved aes block
      tmpVariables[0] = (short) (tmpVariables[0] - AES_BLOCK_SIZE);
      if (op.isAesBlockSaved()) {
        tmpVariables[0] = (short) (tmpVariables[0] + AES_BLOCK_SIZE);
      }
      // Allocate new data buffer in which input data will be assembled
      tmpVariables[1] = KMByteBlob.instance(tmpVariables[0]);
      if (op.isAesBlockSaved() && tmpVariables[0] > 0) {
        // First copy the previously saved block to the buffer
        Util.arrayCopy(
            op.getAesBlock(),
            (short) 0,
            KMByteBlob.cast(tmpVariables[1]).getBuffer(),
            KMByteBlob.cast(tmpVariables[1]).getStartOff(),
            AES_BLOCK_SIZE);
        tmpVariables[0] = (short)(tmpVariables[0] -AES_BLOCK_SIZE);
        if (tmpVariables[0] > 0) {
            // Then copy rest of the input data to the buffer
            Util.arrayCopy(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                KMByteBlob.cast(tmpVariables[1]).getBuffer(),
                (short) (KMByteBlob.cast(tmpVariables[1]).getStartOff() + AES_BLOCK_SIZE),
                tmpVariables[0]);
          }
      } else {
        if (tmpVariables[0] > 0) {
          Util.arrayCopy(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(tmpVariables[1]).getBuffer(),
              (short) (KMByteBlob.cast(tmpVariables[1]).getStartOff()),
              tmpVariables[0]);
        }
      }

      // Save the last aes block from input data into the op state
      tmpVariables[0] = (short) (KMByteBlob.cast(data[INPUT_DATA]).length() - AES_BLOCK_SIZE);
        op.setAesBlock(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            (short) (KMByteBlob.cast(data[INPUT_DATA]).getStartOff() + tmpVariables[0]),
            AES_BLOCK_SIZE);
      data[INPUT_DATA] = tmpVariables[1];
      }

      data[OUTPUT_DATA] = KMByteBlob.instance(KMByteBlob.cast(data[INPUT_DATA]).length());
      // Update the rest of the data
      if (KMByteBlob.cast(data[INPUT_DATA]).length() > 0) {
        // allocate output data buffer as input data is always block aligned.
        tmpVariables[0] =
            op.getCipher()
                .update(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
        //TODO: Not always the output length is equal to input length.
        //TODO: Few VTS tests fail because of this below code.
        //if (tmpVariables[0] != KMByteBlob.cast(data[INPUT_DATA]).length()) {
        //  KMException.throwIt(KMError.UNKNOWN_ERROR);
        //}
        //In case if output length not equal to input length. Allocate actual size of output.
        if(tmpVariables[0] != KMByteBlob.cast(data[INPUT_DATA]).length()) {
        	data[INPUT_DATA] = data[OUTPUT_DATA];
        	data[OUTPUT_DATA] = KMByteBlob.instance(tmpVariables[0]);
        	Util.arrayCopy(KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
        			KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
        			KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
        			KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff(),
        			tmpVariables[0]);
        }
      }
  // make response
  tmpVariables[1] = KMArray.instance((short) 0);
  tmpVariables[1] = KMKeyParameters.instance(tmpVariables[1]);
  tmpVariables[2] = KMArray.instance((short) 4);
  KMArray.cast(tmpVariables[2]).add((short) 0, KMInteger.uint_16(KMError.OK));
  KMArray.cast(tmpVariables[2]).add((short) 1, KMInteger.uint_16(tmpVariables[0]));
  KMArray.cast(tmpVariables[2]).add((short) 2, tmpVariables[1]);
  KMArray.cast(tmpVariables[2]).add((short) 3, data[OUTPUT_DATA]);
  // Encode the response
  bufferLength = encoder.encode(tmpVariables[2], buffer, bufferStartOffset);
  sendOutgoing(apdu);
  }

  private void finishAesGcmOperation(KMOperationState op, byte[] scratchPad) {
    // update aad if there is any and if it is allowed
    updateAAD(op, (byte)0x01);
    // Check if there at least MAC Length length of data
    if(data[INPUT_DATA] == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
    tmpVariables[1] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ASSOCIATED_DATA,data[KEY_PARAMETERS]);
    if(!op.isAesBlockSaved() &&
    		(tmpVariables[0] < (short)(op.getMacLength()/8)) &&
    		(op.getPurpose()==KMType.DECRYPT) &&
    		(tmpVariables[1] == KMType.INVALID_VALUE)){
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    // Now add the aes block saved in op.state to input data
    if(op.isAesBlockSaved()){
      tmpVariables[0] = KMByteBlob.instance((short)(tmpVariables[0]+AES_BLOCK_SIZE));
      Util.arrayCopy(op.getAesBlock(), (short)0,
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        (short)op.getAesBlock().length);
      Util.arrayCopy(
        KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
        KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        (short)(KMByteBlob.cast(tmpVariables[0]).getStartOff()+op.getAesBlock().length),
        KMByteBlob.cast(data[INPUT_DATA]).length());
      data[INPUT_DATA] = tmpVariables[0];
    }
    // Allocate output data buffer based on mac length and encrypt or decrypt operation
    tmpVariables[0] = op.getCipher().getAesGcmOutputSize(KMByteBlob.cast(data[INPUT_DATA]).length(),
                                                          (short)(op.getMacLength()/8));
   /* if(op.getPurpose() == KMType.ENCRYPT){
      data[OUTPUT_DATA] = KMByteBlob.instance((short)(tmpVariables[0]+(op.getMacLength()/8)));
    }else{
    	data[OUTPUT_DATA] = KMByteBlob.instance((short)(tmpVariables[0]-(op.getMacLength()/8)));
    }
    */
    data[OUTPUT_DATA] = KMByteBlob.instance(tmpVariables[0]);
    //This will throw KMError.VERIFICATION_FAILED if the tag does not match during decrypt.
    tmpVariables[0] = op.getCipher().doFinal(
      KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
      KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
      KMByteBlob.cast(data[INPUT_DATA]).length(),
      KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
      KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
    if(tmpVariables[0] != KMByteBlob.cast(data[OUTPUT_DATA]).length()){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }

    /*    //TODO HACK The SunJCE update multipart decryption does not return any output instead it stores
	  // the input. The doFinal call returns the complete plain text at once. so here as a hack
	  // we are allocation a 256 buffer(VTS MAX input message size) to store the plain text.
	if(KMCipher.SUN_JCE == op.getCipher().getCipherProvider() && op.getPurpose() == KMType.DECRYPT) {
		if (KMCipherImpl.aes_gcm_decrypt_final_data != 0x00) {
		 data[OUTPUT_DATA] = KMCipherImpl.aes_gcm_decrypt_final_data;
		 KMCipherImpl.aes_gcm_decrypt_final_data = 0x00;
		}
	}
*/
  }

  private void beginAesGcmOperation(KMOperationState op) {
    short purpose;
    // TODO [Venkat] What is the reason to make data[OP_HANDLE] to KMType.INVALID_VALUE
    //This is commented because if some exception is thrown below data[OP_HANDLE] points to
    // INVALID_VALUE and is not getting cleared from OperationState.
    //data[OP_HANDLE] = KMType.INVALID_VALUE;
    if (op.getPurpose() == KMType.ENCRYPT) {
      purpose = KMCipher.MODE_ENCRYPT;
      if (data[IV] == KMType.INVALID_VALUE) {
        data[IV] = KMByteBlob.instance((short) 12);
        cryptoProvider.newRandomNumber(
          KMByteBlob.cast(data[IV]).getBuffer(),
          KMByteBlob.cast(data[IV]).getStartOff(),
          KMByteBlob.cast(data[IV]).length());
      }
    } else {
      purpose = KMCipher.MODE_DECRYPT;
    }
    op.setAesGcmUpdateStart();
    op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
      KMByteBlob.cast(data[SECRET]).getStartOff(),
      KMByteBlob.cast(data[SECRET]).length());
    try {
    //TODO [Venkat] CryptoException is not been converted to KMException here.
    op.setCipher(
      cryptoProvider.createAesGcmCipher(
        purpose,
        op.getMacLength(),
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[IV]).getBuffer(),
        KMByteBlob.cast(data[IV]).getStartOff(),
        KMByteBlob.cast(data[IV]).length()));
    } catch (CryptoException exception) {
    	if(exception.getReason() == CryptoException.ILLEGAL_VALUE)
    		KMException.throwIt(KMError.INVALID_ARGUMENT);
    	else if(exception.getReason() == CryptoException.NO_SUCH_ALGORITHM)
    		KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    //data[OP_HANDLE] = op.getHandle();
  }

  private void finishSigningVerifyingOperation(KMOperationState op, byte[]scratchPad) {
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    switch(op.getAlgorithm()){
        case KMType.RSA:
          data[OUTPUT_DATA] = KMByteBlob.instance((short)256);
          // No digest and no padding - This case is not supported in javacard api
          // However as there is no padding we can treat signing as a RSA decryption operation.
          if(op.getDigest() == KMType.DIGEST_NONE && op.getPadding() == KMType.PADDING_NONE){
            if(op.getPurpose() == KMType.SIGN){
              /*
            // Length cannot be greater then key size
            if(len > op.getKeySize()) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
            // If Length is same as key size then
            // compare the data with key value - data should be less then key value.
            if(len == op.getKeySize()) {
              tmpVariables[0]= op.getKey(scratchPad,(short)0);
              tmpVariables[0] = Util.arrayCompare(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                scratchPad, (short)0, tmpVariables[0]);
              if(tmpVariables[0] >= 0){
                KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
              }
            }*/
            }else{//Verify
              if(len != 256) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
            }
/*            // Fill the scratch pad with zero
            Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
            // Everything is fine so copy input data to scratchpad.
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)(256 - len),len);
            len = (short)256;*/
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)0,len);
          }else if (op.getDigest() == KMType.DIGEST_NONE && op.getPadding() == KMType.RSA_PKCS1_1_5_SIGN) {
    /*        // If PKCS1 padding and no digest - then 0x01||0x00||PS||0x00 on left such that PS >= 8 bytes
            // Data Length should be atleast 11 less then the key size - which is 256 bytes
            if(len > (short)(op.getKeySize() - 11)){
              KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
            }
            // Fill the scratch pad with pkcs1 padding zero according to RFC 2313 section 8.1
            // Signing is done using private key.
            Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
            scratchPad[0] = 0x00;
            scratchPad[1] = 0x01;
            //cryptoProvider.newRandomNumber(scratchPad, (short)2, (short)8);
            // We fill in 0xFF as PS following the javacard pkcs1 padding example.
            tmpVariables[0] = (short)(op.getKeySize()-len-3);
            Util.arrayFillNonAtomic(scratchPad,(short)2,tmpVariables[0],(byte)0xFF);
            scratchPad[(short)(tmpVariables[0]+2)] = 0x00;
            //copy the rest of the data on scratch pad.
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)(tmpVariables[0]+3),len);
            len = op.getKeySize(); // this will be 256*/
            Util.arrayCopyNonAtomic(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              scratchPad, (short)0,len);

          }else if(op.getDigest()==KMType.SHA2_256 &&
            (op.getPadding() == KMType.RSA_PKCS1_1_5_SIGN ||op.getPadding() == KMType.RSA_PSS)){
            // Normal case with PKCS1 or PSS padding and with Digest SHA256
            // Fill the scratch pad with zero
          Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
          // Copy the data on the scratch pad.
          Util.arrayCopyNonAtomic(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            scratchPad, (short)0,len);
          }else{
           KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
          }
          if(op.getPurpose() == KMType.SIGN){
          // len of signature will be 256 bytes
          try {
          len = op.getSignerVerifier().sign(scratchPad,(short)0,len,
            KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
          } catch (CryptoException e) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }
          }else{
            if(!op.getSignerVerifier().verify(scratchPad,(short)0,len,
              KMByteBlob.cast(data[SIGNATURE]).getBuffer(),
              KMByteBlob.cast(data[SIGNATURE]).getStartOff(),
              KMByteBlob.cast(data[SIGNATURE]).length())){
              KMException.throwIt(KMError.VERIFICATION_FAILED);
            }
          }
          break;
        case KMType.EC:
          // Fill the scratch pad with zero
          Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
          // If DIGEST NONE then truncate the data to 32 bytes.
          // TODO Confirm whether this case needs to be supported as javacard does not support.
          if(op.getDigest() == KMType.DIGEST_NONE && len > 32){
              len = 32;
          }
          if(op.getPurpose() == KMType.SIGN){
            // len of signature will be 512 bits i.e. 64 bytes
          len = op.getSignerVerifier().sign(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),len,
            scratchPad,(short)0);
          data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad,(short)0, len);
          }else{
            if(!op.getSignerVerifier().verify(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),len,
              KMByteBlob.cast(data[SIGNATURE]).getBuffer(),
              KMByteBlob.cast(data[SIGNATURE]).getStartOff(),
              KMByteBlob.cast(data[SIGNATURE]).length())){
              KMException.throwIt(KMError.VERIFICATION_FAILED);
            }
          }
          break;
        case KMType.HMAC:
          //For HMAC, either sign or verify we do sign operation only and we compare the
          //signature manually. The reason for doing this is the TAG_MAC_LENGTH can be 32 bytes
          //length or less than that in case if it is less than 32 we are truncating it and sending
          //back to the user. For Verify user will send the truncated and if we pass the truncated
          //signature to javacard verify API it will fail because it expects the full length signature.
          Util.arrayFillNonAtomic(scratchPad,(short)0, (short)256, (byte)0);
          // digest is always present.
          // len of signature will always be 32 bytes.
          len = op.getSignerVerifier().sign(KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),len,scratchPad,
            (short)0);
          // Copy only signature of mac length size.
          data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad,(short)0, (short) (op.getMacLength() / 8));
          if(op.getPurpose() == KMType.VERIFY){
            if(0 != Util.arrayCompare(KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
            		KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff(),
            		KMByteBlob.cast(data[SIGNATURE]).getBuffer(),
            		KMByteBlob.cast(data[SIGNATURE]).getStartOff(),
            		(short)(op.getMacLength() / 8))) {
            	KMException.throwIt(KMError.VERIFICATION_FAILED);
            }
          }
          break;
        default:// This is should never happen
          KMException.throwIt(KMError.OPERATION_CANCELLED);
          break;
      }
  }

  private void finishTrustedConfirmationOperation(KMOperationState op) {
    // Perform trusted confirmation if required
    if (op.isTrustedConfirmationRequired()) {
      tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.CONFIRMATION_TOKEN, data[KEY_PARAMETERS]);
      if(tmpVariables[0] == KMType.INVALID_VALUE){
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMByteTag.cast(tmpVariables[0]).getValue();
      boolean verified = op.getTrustedConfirmationSigner()
        .verify(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          KMByteBlob.cast(data[INPUT_DATA]).length(),
          KMByteBlob.cast(tmpVariables[0]).getBuffer(),
          KMByteBlob.cast(tmpVariables[0]).getStartOff(),
          KMByteBlob.cast(tmpVariables[0]).length());
      /*
      if(tmpVariables[1] != KMByteBlob.cast(tmpVariables[0]).length() ){
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
      tmpVariables[0]=Util.arrayCompare(scratchPad,(short)0,
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        tmpVariables[1]);*/
      if(!verified){
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
    }

  }

  private void authorizeUpdateFinishOperation(KMOperationState op, byte[] scratchPad) {
    // If one time user Authentication is required
    if (op.isSecureUserIdReqd() && !op.isAuthTimeoutValidated()) {
        validateVerificationToken(op, data[VERIFICATION_TOKEN], scratchPad);
        tmpVariables[0] = KMInteger.uint_64(op.getAuthTime(), (short) 0);
        tmpVariables[2] = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getTimestamp();
        if (tmpVariables[2] == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.VERIFICATION_FAILED);
        }
        if (KMInteger.compare(tmpVariables[0], tmpVariables[2]) < 0) {
          KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
        }
        op.setAuthTimeoutValidated(true);
    } else if(op.isAuthPerOperationReqd()){ // If Auth per operation is required
      tmpVariables[0] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getChallenge();
      if (KMInteger.compare(data[OP_HANDLE], tmpVariables[0]) != 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      authenticateUser(scratchPad);
    }
  }

  private void authorizeDeviceUnlock(short hwToken) {
    // If device is locked and key characteristics requires unlocked device then check whether
    // HW auth token has correct timestamp.
    short ptr =
        KMKeyParameters.findTag(
            KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED, data[HW_PARAMETERS]);
    if (ptr != KMType.INVALID_VALUE && repository.deviceLockedFlag) {
      if (hwToken == KMType.INVALID_VALUE) KMException.throwIt(KMError.DEVICE_LOCKED);
      ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
      // Check if the current auth time stamp is greater then device locked time stamp
      if (KMInteger.compare(ptr, KMInteger.uint_64(repository.deviceLockedTimestamp, (short) 0))
          <= 0) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      // Now check if the device unlock requires password only authentication and whether
      // auth token is generated through password authentication or not.
      if (repository.deviceUnlockPasswordOnly) {
        ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
        ptr = KMEnum.cast(ptr).getVal();
        if (((byte) ptr & KMType.PASSWORD) == 0) {
          KMException.throwIt(KMError.DEVICE_LOCKED);
        }
      }
      // Unlock the device
      repository.deviceLockedFlag = false;
      Util.arrayFillNonAtomic(repository.deviceLockedTimestamp, (short) 0, (short) 8, (byte) 0);
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
    validateVerificationToken(verToken, scratchPad);
    // validate operation handle.
    ptr = KMVerificationToken.cast(verToken).getChallenge();
    if(op.getHandle() != KMInteger.cast(ptr).getShort()){
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private void validateVerificationToken(short verToken, byte[] scratchPad) {
    short ptr = KMVerificationToken.cast(verToken).getMac();
    short len = 0;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    // concatenation length will be 37 + length of verified parameters list  - which is typically empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    short params = KMVerificationToken.cast(verToken).getParametersVerified();

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
    if (KMByteBlob.cast(ptr).length() != 0) {
      len += KMByteBlob.cast(ptr).getValues(scratchPad, (short) 0);
    }
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
    // Check Operation Handle
    tmpVariables[1] = KMInteger.cast(data[OP_HANDLE]).getShort();
    KMOperationState op = repository.findOperation(tmpVariables[1]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // authorize the update operation
    authorizeUpdateFinishOperation(op, scratchPad);
    // If signing without  digest then do length validation checks
    if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY ) {
      if(data[INPUT_DATA] == KMType.INVALID_VALUE){
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
      // update the data.
      op.getSignerVerifier()
          .update(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length());
      // update trusted confirmation operation
      updateTrustedConfirmationOperation(op);
      data[OUTPUT_DATA] = KMType.INVALID_VALUE;
    }
    if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT){
      // TODO Update for encrypt/decrypt using RSA will not be supported because to do this op state
      //  will have to buffer the data - so reject the update if it is rsa algorithm.
        if(op.getAlgorithm() == KMCipher.CIPHER_RSA) {
          KMException.throwIt(KMError.OPERATION_CANCELLED);
        }
      //TODO refactor and optimize this
      if (op.getAlgorithm() == KMType.AES && op.getBlockMode() == KMType.GCM) {
          updateAesGcmOperation(op, apdu);
          return;
        }
      if(data[INPUT_DATA] == KMType.INVALID_VALUE){
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
      if (op.getAlgorithm() == KMType.AES) {
          // input data must be block aligned.
          // 128 bit block size - HAL must send block aligned data
          if (tmpVariables[0] % AES_BLOCK_SIZE != 0 || tmpVariables[0] <=0) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
        }
        if (op.getAlgorithm() == KMType.DES) {
          // 64 bit block size - HAL must send block aligned data
          if (tmpVariables[0] % DES_BLOCK_SIZE != 0) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
        }
        //Allocate output buffer as input data is already block aligned
      data[OUTPUT_DATA] = KMByteBlob.instance(tmpVariables[0]);
        // Otherwise just update the data.
        tmpVariables[0] =
            op.getCipher()
                .update(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
        // update must fully process all of the input data
        if(tmpVariables[0] != KMByteBlob.cast(data[OUTPUT_DATA]).length()){
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
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
    bufferLength = encoder.encode(tmpVariables[2], buffer, bufferStartOffset);
    sendOutgoing(apdu);
  }

  private void updateTrustedConfirmationOperation(KMOperationState op) {
    if (op.isTrustedConfirmationRequired()) {
      op.getTrustedConfirmationSigner()
        .update(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          KMByteBlob.cast(data[INPUT_DATA]).length());
    }
  }

  private void processBeginOperationCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    short args = KMType.INVALID_VALUE;
    tmpVariables[1] = KMArray.instance((short) 4);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMEnum.instance(KMType.PURPOSE));
    KMArray.cast(tmpVariables[1]).add((short) 1, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add((short) 2, tmpVariables[2]);
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 3, tmpVariables[3]);
    // Decode the arguments
    args = decoder.decode(tmpVariables[1], buffer, bufferStartOffset, bufferLength);
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 2);
    data[KEY_BLOB] = KMArray.cast(args).get((short) 1);
    // Check for app id and app data.
    data[APP_ID] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    data[APP_DATA] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(data[APP_ID]).getValue();
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(data[APP_DATA]).getValue();
    }
    // Parse the encrypted blob and decrypt it.
    parseEncryptedKeyBlob(scratchPad);
    // Authorize the begin operation and reserve op - data[OP_HANDLE] will have the handle.
    // It will also set data[IV] field if required.
    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMEnum.cast(tmpVariables[0]).getVal();
    data[HW_TOKEN] = KMArray.cast(args).get((short) 3);
    KMOperationState op = repository.reserveOperation();
    if(op == null) KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    data[OP_HANDLE] = op.getHandle();
    op.setPurpose(tmpVariables[0]);
    op.setKeySize(KMByteBlob.cast(data[SECRET]).length());
    authorizeAndBeginOperation(op, scratchPad);
    switch (op.getPurpose()){
      case KMType.SIGN:
        beginTrustedConfirmationOperation(op);
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
    // If the data[IV] is required to be returned.
    //As per VTS, for the decryption operation don't send the iv back.
    if (data[IV] != KMType.INVALID_VALUE && op.getPurpose() != KMType.DECRYPT) {
      tmpVariables[2] = KMArray.instance((short) 1);
      if(op.getAlgorithm() == KMType.DES && op.getBlockMode() == KMType.CBC) {
    	//For AES/DES we are generate an random iv of length 16 bytes.
    	//While sending the iv back for DES/CBC mode of opeation only send
    	//8 bytes back.
    	tmpVariables[1] = KMByteBlob.instance((short) 8);
    	Util.arrayCopy(KMByteBlob.cast(data[IV]).getBuffer(),
    	        KMByteBlob.cast(data[IV]).getStartOff(),
    			KMByteBlob.cast(tmpVariables[1]).getBuffer(),
    			KMByteBlob.cast(tmpVariables[1]).getStartOff(),
    			(short)8);
    	data[IV] = tmpVariables[1];
      }
      KMArray.cast(tmpVariables[2]).add((short) 0, KMByteTag.instance(KMType.NONCE, data[IV]));
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

  private void beginTrustedConfirmationOperation(KMOperationState op) {
    // Check for trusted confirmation - if required then set the signer in op state.
    if (KMKeyParameters.findTag(
      KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED, data[HW_PARAMETERS]) != KMType.INVALID_VALUE) {
      // get operation
      // get the hmac key
      if (repository.getComputedHmacKey() == null) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      // set the Hmac signer
      op.setTrustedConfirmationSigner(
        cryptoProvider.createHmacSignerVerifier(Signature.MODE_VERIFY,
          MessageDigest.ALG_SHA_256,
          repository.getComputedHmacKey(),
          (short) 0, (short) repository.getComputedHmacKey().length));
      op.getTrustedConfirmationSigner().update(confirmationToken,(short)0,(short)confirmationToken.length);
    }
  }

  private void authorizeAlgorithm(KMOperationState op){
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    if(alg == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    op.setAlgorithm((byte)alg);
  }
  private void authorizePurpose(KMOperationState op){
	switch(op.getAlgorithm()) {
	  case KMType.AES:
	  case KMType.DES:
	    if(op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY)
		  KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
		break;
	  case KMType.EC:
	  case KMType.HMAC:
		if(op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT)
		  KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        break;
      default:
    	break;
	}
    if(!KMEnumArrayTag.contains(KMType.PURPOSE,op.getPurpose(),data[HW_PARAMETERS])){
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
  }

  private void authorizeDigest(KMOperationState op){
    short digests = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[HW_PARAMETERS]);
    op.setDigest(KMType.DIGEST_NONE);
    short param = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if(param != KMType.INVALID_VALUE){
      if(KMEnumArrayTag.cast(param).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
      param = KMEnumArrayTag.cast(param).get((short)0);
      if(!KMEnumArrayTag.cast(digests).contains(param)) KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
      op.setDigest((byte)param);
    }
    short paramPadding = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[KEY_PARAMETERS]);
    if(paramPadding != KMType.INVALID_VALUE){
    	if(KMEnumArrayTag.cast(paramPadding).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
    	paramPadding = KMEnumArrayTag.cast(paramPadding).get((short)0);
    }
    switch(op.getAlgorithm()){
      case KMType.RSA:
    	  if ((paramPadding == KMType.RSA_OAEP || paramPadding == KMType.RSA_PSS)
    	          && param == KMType.INVALID_VALUE) {
    	    KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    	  }
    	  break;
      case KMType.EC:
      case KMType.HMAC:
        if(param == KMType.INVALID_VALUE) KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    	break;
      default:
        break;
    }
  }
  private void authorizePadding(KMOperationState op){
    short paddings = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[HW_PARAMETERS]);
    op.setPadding(KMType.PADDING_NONE);
    short param = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[KEY_PARAMETERS]);
    if(param != KMType.INVALID_VALUE){
      if(KMEnumArrayTag.cast(param).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
      param = KMEnumArrayTag.cast(param).get((short)0);
      if(!KMEnumArrayTag.cast(paddings).contains(param)) KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    switch (op.getAlgorithm()){
      case KMType.RSA:
        if(param == KMType.INVALID_VALUE) KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        if((op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY)&&
          param != KMType.PADDING_NONE &&
          param != KMType.RSA_PSS &&
          param != KMType.RSA_PKCS1_1_5_SIGN) KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        if((op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) &&
          param != KMType.PADDING_NONE &&
          param != KMType.RSA_OAEP &&
          param != KMType.RSA_PKCS1_1_5_ENCRYPT) KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        if (param == KMType.PADDING_NONE && op.getDigest() != KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        if ((param == KMType.RSA_OAEP || param == KMType.RSA_PSS)
          && op.getDigest() == KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        op.setPadding((byte)param);
        break;
      case KMType.DES:
      case KMType.AES:
        if(param == KMType.INVALID_VALUE) KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        op.setPadding((byte)param);
        break;
      default:
        break;
    }
  }
  private void authorizeBlockModeAndMacLength(KMOperationState op){
    short param = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, data[KEY_PARAMETERS]);
    if(param != KMType.INVALID_VALUE){
      if(KMEnumArrayTag.cast(param).length() != 1) KMException.throwIt(KMError.INVALID_ARGUMENT);
      param = KMEnumArrayTag.cast(param).get((short)0);
    }
    if (KMType.AES == op.getAlgorithm() || KMType.DES == op.getAlgorithm()) {
      if(!KMEnumArrayTag.contains(KMType.BLOCK_MODE, param, data[HW_PARAMETERS])){
        KMException.throwIt(KMError.INCOMPATIBLE_BLOCK_MODE);
      }
    }
    short macLen =
      KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MAC_LENGTH, data[KEY_PARAMETERS]);
    switch (op.getAlgorithm()){
      case KMType.AES:
        if(param == KMType.INVALID_VALUE) KMException.throwIt(KMError.INVALID_ARGUMENT);
        if (param == KMType.GCM){
          if(op.getPadding() != KMType.PADDING_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
        }
        if (macLen == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.MISSING_MAC_LENGTH);
        }
        if (macLen % 8 != 0 || macLen > 128 ||
          macLen < KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
          KMException.throwIt(KMError.INVALID_MAC_LENGTH);
        }
        op.setMacLength(macLen);
      }
        //TODO Ignore MAC_LENGTH tag for other modes of operation.
       //else if(macLen != KMType.INVALID_VALUE) KMException.throwIt(KMError.INVALID_ARGUMENT);
      break;
      case KMType.DES:
        if(param == KMType.INVALID_VALUE) KMException.throwIt(KMError.INVALID_ARGUMENT);
        break;
      case KMType.HMAC:
    	if (macLen == KMType.INVALID_VALUE) {
    	  if(op.getPurpose() == KMType.SIGN) {
    		KMException.throwIt(KMError.MISSING_MAC_LENGTH);
    	  }
    	} else {
    	  //MAC length may not be specified for verify.
    	  if(op.getPurpose() == KMType.VERIFY) {
    		KMException.throwIt(KMError.INVALID_ARGUMENT);
    	  }
    	  if (macLen < KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
              KMException.throwIt(KMError.INVALID_MAC_LENGTH);
            } else if  (macLen > KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
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

  private short getMacSize(byte digest){
    switch (digest){
      case KMType.SHA1:
        return 160;
      case KMType.SHA2_224:
        return 224;
      case KMType.SHA2_384:
        return 384;
      case KMType.SHA2_256:
        return 256;
      case KMType.SHA2_512:
        return 512;
      case KMType.MD5:
        return 128;
      default:
        return 0;
    }
  }
  private void authorizeAndBeginOperation(KMOperationState op, byte[] scratchPad) {
    authorizeAlgorithm(op);
    authorizePurpose(op);
    authorizeDigest(op);
    authorizePadding(op);
    authorizeBlockModeAndMacLength(op);
    authorizeKeyUsageForCount();
    if(!validateHwToken(data[HW_TOKEN],scratchPad)){
      data[HW_TOKEN] = KMType.INVALID_VALUE;
    }
    authorizeUserSecureIdAuthTimeout(op, scratchPad);
    authorizeDeviceUnlock(data[HW_TOKEN]);
    // Authorize Caller Nonce - if caller nonce absent in key char and nonce present in
    // key params then fail if it is not a Decrypt operation
    data[IV] = KMType.INVALID_VALUE;
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.CALLER_NONCE, data[HW_PARAMETERS]);
    tmpVariables[1] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.NONCE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      if (tmpVariables[1] != KMType.INVALID_VALUE && op.getPurpose() != KMType.DECRYPT) {
        KMException.throwIt(KMError.CALLER_NONCE_PROHIBITED);
      }
    }
    if (tmpVariables[1] != KMType.INVALID_VALUE) {
      data[IV] = KMByteTag.cast(tmpVariables[1]).getValue();
      //For CBC mode and GCM mode if IV is present in key parameters then it must be of right lengths
      if (op.getBlockMode() == KMType.CBC && op.getAlgorithm() == KMType.DES &&
        KMByteBlob.cast(data[IV]).length() != 8) {
          KMException.throwIt(KMError.INVALID_NONCE);
      }
      if (KMByteBlob.cast(data[IV]).length() != 12 && op.getBlockMode() == KMType.GCM) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }
      if ((op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.CTR)
    		  && op.getAlgorithm() == KMType.AES &&
        KMByteBlob.cast(data[IV]).length() != 16) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }
    }
    if (op.getAlgorithm() == KMType.AES || op.getAlgorithm() == KMType.DES) {
      // For symmetric decryption iv is required
      if (op.getPurpose() == KMType.DECRYPT
          && data[IV] == KMType.INVALID_VALUE
          && (op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.GCM)) {
        KMException.throwIt(KMError.MISSING_NONCE);
      }
    }
  }

  private void beginCipherOperation(KMOperationState op) {
    short padding;
    short alg = -1;
    short purpose;
    if(op.getPurpose() == KMType.ENCRYPT) purpose = KMCipher.MODE_ENCRYPT;
    else purpose = KMCipher.MODE_DECRYPT;

      switch (op.getAlgorithm()) {
        // Not required to be supported - supported for testing purpose
        // TODO remove this later
      case KMType.RSA:
        if (op.getPadding() == KMType.RSA_PKCS1_1_5_ENCRYPT) padding = KMCipher.PAD_PKCS1;
        else if(op.getPadding() == KMType.RSA_OAEP && op.getDigest() == KMType.SHA2_256){
          padding = KMCipher.PAD_PKCS1_OAEP_SHA256;
        } else if (op.getPadding() == KMType.RSA_OAEP && op.getDigest() == KMType.SHA1) {
          padding = KMCipher.PAD_PKCS1_OAEP;
        } else padding = KMCipher.PAD_NOPAD;
        try {
          if(purpose == KMCipher.MODE_DECRYPT){
          op.setKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
          op.setCipher(
              cryptoProvider.createRsaDecipher(
                  padding,
                  KMByteBlob.cast(data[SECRET]).getBuffer(),
                  KMByteBlob.cast(data[SECRET]).getStartOff(),
                  KMByteBlob.cast(data[SECRET]).length(),
                  KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                  KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                  KMByteBlob.cast(data[PUB_KEY]).length()));
          }else{
            op.setKey(
              KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
              KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
              KMByteBlob.cast(data[PUB_KEY]).length());
            op.setCipher(
              cryptoProvider.createRsaCipher(
                padding,
                KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                KMByteBlob.cast(data[PUB_KEY]).length()));
          }
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.AES:
        if (op.getBlockMode() == KMType.GCM) {
          beginAesGcmOperation(op);
          return;
        }
      case KMType.DES:
        if (op.getPadding() == KMType.PADDING_NONE) {
          padding = KMCipher.PAD_NOPAD;
        } else {
          padding = KMCipher.PAD_PKCS7;
        }
        if (op.getAlgorithm() == KMType.AES) {
          if (op.getBlockMode() == KMType.CBC) {
            alg = KMCipher.ALG_AES_BLOCK_128_CBC_NOPAD;
            if (data[IV] == KMType.INVALID_VALUE) {
              data[IV] = KMByteBlob.instance((short) 16);
              cryptoProvider.newRandomNumber(
                  KMByteBlob.cast(data[IV]).getBuffer(),
                  KMByteBlob.cast(data[IV]).getStartOff(),
                  KMByteBlob.cast(data[IV]).length());
              }
          } else if (op.getBlockMode() == KMType.ECB) {
            alg = KMCipher.ALG_AES_BLOCK_128_ECB_NOPAD;
            data[IV] = KMType.INVALID_VALUE;
          } else if (op.getBlockMode() == KMType.CTR){
            alg = KMCipher.ALG_AES_CTR;
            if (data[IV] == KMType.INVALID_VALUE) {
              data[IV] = KMByteBlob.instance((short) 16);
              cryptoProvider.newRandomNumber(
                KMByteBlob.cast(data[IV]).getBuffer(),
                KMByteBlob.cast(data[IV]).getStartOff(),
                KMByteBlob.cast(data[IV]).length());
            }
          }else{
            KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
          }
        } else if (op.getAlgorithm() == KMType.DES) {
          if (op.getBlockMode() == KMType.CBC) {
            alg = KMCipher.ALG_DES_CBC_NOPAD;
            if(data[IV] == KMType.INVALID_VALUE){
              data[IV] = KMByteBlob.instance((short)16); // TODO 8 bytes in length
              cryptoProvider.newRandomNumber(
                KMByteBlob.cast(data[IV]).getBuffer(),
                KMByteBlob.cast(data[IV]).getStartOff(),
                KMByteBlob.cast(data[IV]).length()
              );
            }

          } else if (op.getBlockMode() == KMType.ECB){
            alg = KMCipher.ALG_DES_ECB_NOPAD;
            data[IV] = KMType.INVALID_VALUE;
          }else{
            KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
          }
        } else {
          KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
        }
        op.setKey(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length());
        try {
          if (data[IV] != KMType.INVALID_VALUE) {
            op.setCipher(
                cryptoProvider.createSymmetricCipher(
                    alg,
                    purpose,
                    padding,
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    KMByteBlob.cast(data[IV]).getBuffer(),
                    KMByteBlob.cast(data[IV]).getStartOff(),
                    KMByteBlob.cast(data[IV]).length()));
          } else {
            op.setCipher(
                cryptoProvider.createSymmetricCipher(
                    alg,
                    purpose,
                    padding,
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length()));
          }
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
    }
  }


  private void beginSignVerifyOperation(KMOperationState op) {
    short padding;
    short digest;
    short purpose;;
    if(op.getPurpose() == KMType.SIGN) purpose = Signature.MODE_SIGN;
    else purpose = Signature.MODE_VERIFY;
    switch(op.getAlgorithm()){
      case KMType.RSA:
        if(op.getDigest() == KMType.DIGEST_NONE) digest = MessageDigest.ALG_NULL;
        else digest = MessageDigest.ALG_SHA_256;
        if(op.getPadding() ==  KMType.PADDING_NONE) padding = KMCipher.PAD_NOPAD;
        else if(op.getPadding() ==  KMType.RSA_PSS) padding = KMCipher.PAD_PKCS1_PSS;
        else padding = KMCipher.PAD_PKCS1;
        op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
          KMByteBlob.cast(data[SECRET]).getStartOff(),
          KMByteBlob.cast(data[SECRET]).length());
        try{
          if (op.getPurpose() == KMType.SIGN) {
            op.setSignerVerifier(
                cryptoProvider.createRsaSigner(
                    digest,
                    padding,
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                    KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                    KMByteBlob.cast(data[PUB_KEY]).length()));
          }else{
            op.setSignerVerifier(
              cryptoProvider.createRsaVerifier(
                digest,
                padding,
                KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                KMByteBlob.cast(data[PUB_KEY]).length()));
          }
        }catch(CryptoException exp){
          // Javacard does not support NO digest based signing.
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.EC:
        if(op.getDigest() == KMType.DIGEST_NONE) digest = MessageDigest.ALG_NULL;
        else digest = MessageDigest.ALG_SHA_256;
        op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
          KMByteBlob.cast(data[SECRET]).getStartOff(),
          KMByteBlob.cast(data[SECRET]).length());
        try{
          if (op.getPurpose() == KMType.SIGN) {
            op.setSignerVerifier(
                cryptoProvider.createEcSigner(
                    digest,
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length()));
          }else{
            op.setSignerVerifier(
              cryptoProvider.createEcVerifier(
                digest,
                KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                KMByteBlob.cast(data[PUB_KEY]).length()));
          }
        }catch(CryptoException exp){
          // Javacard does not support NO digest based signing.
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.HMAC:
    	//For HMAC, either sign or verify we do sign operation only and we compare the
          //signature manually. The reason for doing this is the TAG_MAC_LENGTH can be 32 bytes
          //length or less than that in case if it is less than 32 we are truncating it and sending
          //back to the user. For Verify user will send the truncated and if we pass the truncated
          //signature to Javacard verify API it will fail because it expects the full length signature.
        digest = MessageDigest.ALG_SHA_256;
        op.setKey(KMByteBlob.cast(data[SECRET]).getBuffer(),
          KMByteBlob.cast(data[SECRET]).getStartOff(),
          KMByteBlob.cast(data[SECRET]).length());
        try{
          op.setSignerVerifier(
            cryptoProvider.createHmacSignerVerifier(
              Signature.MODE_SIGN, digest,
              KMByteBlob.cast(data[SECRET]).getBuffer(),
              KMByteBlob.cast(data[SECRET]).getStartOff(),
              KMByteBlob.cast(data[SECRET]).length()));
        }catch(CryptoException exp){
          // Javacard does not support NO digest based signing.
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
  }

  private void authorizeUserSecureIdAuthTimeout(KMOperationState op, byte[] scratchPad) {
    short authTime;
    // Authorize User Secure Id and Auth timeout
    tmpVariables[0] =
      KMKeyParameters.findTag(KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[0] =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, data[HW_PARAMETERS]);
      if (tmpVariables[0] != KMType.INVALID_VALUE) {
        // check if hw token is empty - mac should not be empty.
        if(data[HW_TOKEN] == KMType.INVALID_VALUE) KMException.throwIt(KMError.INVALID_MAC_LENGTH);
        authTime = KMIntegerTag.cast(tmpVariables[0]).getValue();
        // authenticate user
        authenticateUser(scratchPad);
        // set the one time auth
        op.setOneTimeAuthReqd(true);
        // set the authentication time stamp in operation state
        authTime = addIntegers(authTime, KMHardwareAuthToken.cast(data[HW_TOKEN]).getTimestamp());
        op.setAuthTime(KMInteger.cast(authTime).getBuffer(), KMInteger.cast(authTime).getStartOff());
        // auth time validation will happen in update or finish
        op.setAuthTimeoutValidated(false);
      } else {
        // auth per operation required
        op.setOneTimeAuthReqd(false);
        op.setAuthPerOperationReqd(true);
      }
    }
  }


  private void authenticateUser(byte[] scratchPad) {
    tmpVariables[0] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getUserId();
    if (KMInteger.cast(tmpVariables[0]).isZero()) {
      tmpVariables[0] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getAuthenticatorId();
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
    tmpVariables[2] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getHwAuthenticatorType();
    tmpVariables[2] = KMEnum.cast(tmpVariables[2]).getVal();
    if (((byte) tmpVariables[2] & (byte) tmpVariables[1]) == 0) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
  }

  private boolean validateHwToken(short hwToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian
    short ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    short len = 0;
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
    return verified;
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

  private void authorizeKeyUsageForCount() {
    // TODO currently only short usageLimit supported - max count 32K.
    short usageLimit = KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT, data[HW_PARAMETERS]);
    if (usageLimit == KMType.INVALID_VALUE) return;
    // get current counter
    short usage = repository.getRateLimitedKeyCount(data[AUTH_TAG]);
    if (usage != KMType.INVALID_VALUE) {
      if(usage < usageLimit){
        KMException.throwIt(KMError.KEY_MAX_OPS_EXCEEDED);
      }
      // increment the counter and store it back.
      usage++;
      repository.setRateLimitedKeyCount(data[AUTH_TAG], usage);
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
    // Bootloader only not supported
    tmpVariables[0] =
      KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }

    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    /*tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidDigests((byte)tmpVariables[3])){
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidPaddingModes((byte)tmpVariables[3])){
        KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidPurpose((byte)tmpVariables[3])){
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidBlockMode((byte)tmpVariables[3])){
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMIntegerTag.cast(tmpVariables[4]).isValidKeySize((byte)tmpVariables[3])){
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }*/
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
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp()); // public key
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[PUB_KEY] = KMArray.cast(tmpVariables[0]).get((short) 1);
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
        //As per NIST.SP.800-186 page 9,  secret for 256 curve should be between
        //256-383
      if(((256 <= (short)(KMByteBlob.cast(data[SECRET]).length()*8)) &&
         (383 >= (short)(KMByteBlob.cast(data[SECRET]).length()*8))) ^
          tmpVariables[2] == 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (tmpVariables[2] != 256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
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
    	 //As per NIST.SP.800-186 page 9,  secret length for 256 curve should be between
        //256-383
      if(((256 <= (short)(KMByteBlob.cast(data[SECRET]).length()*8)) &&
         (383 >= (short)(KMByteBlob.cast(data[SECRET]).length()*8))) ^
          tmpVariables[3] == KMType.P_256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (tmpVariables[3] != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
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
      tmpVariables[5] = KMInteger.uint_16((short)(KMByteBlob.cast(data[SECRET]).length() * 8));
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
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
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
      if (tmpVariables[2] != 2048 || tmpVariables[2] != (short)(KMByteBlob.cast(data[SECRET]).length()*8)) {
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
    } else if(enumVal == KMType.VERIFIED_BOOT) {
      repository.selfSignedBootFlag = false;
      repository.verifiedBootFlag = true;
    }else {
      repository.selfSignedBootFlag = false;
      repository.verifiedBootFlag = false;
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
    // Bootloader only not supported
    tmpVariables[0] =
      KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    /* TODO As per VTS don't do validations for digest, padding, purpose, mode at the time of generation
    // validate digest - only digest none or 256 is supported.
    /*tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidDigests((byte)tmpVariables[3])){
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidPaddingModes((byte)tmpVariables[3])){
        KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidPurpose((byte)tmpVariables[3])){
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMIntegerTag.cast(tmpVariables[4]).isValidKeySize((byte)tmpVariables[3])){
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
    tmpVariables[4] = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMEnumArrayTag.cast(tmpVariables[4]).isValidBlockMode((byte)tmpVariables[3])){
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    }*/
    tmpVariables[4] = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE,data[KEY_PARAMETERS]);
    if(tmpVariables[4] != KMType.INVALID_VALUE){
      if(!KMIntegerTag.cast(tmpVariables[4]).isValidKeySize((byte)tmpVariables[3])){
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
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
      }else{
    	  //TODO as per vts TAG_MIN_MAC_LENGTH if passed can be ignored at creation time.
    	  // No GCM mode then no minimum mac length must be specified
        //if (tmpVariables[2] != KMTag.INVALID_VALUE) {
        //  KMException.throwIt(KMError.INVALID_ARGUMENT);
        //}
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
    if ((tmpVariables[0] == KMTag.INVALID_VALUE) && (tmpVariables[1] == KMTag.INVALID_VALUE)) {
    	KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    } else if ((tmpVariables[0] != KMTag.INVALID_VALUE) && (tmpVariables[0] != (short)256)) {
    	KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    } else if((tmpVariables[1] != KMType.INVALID_VALUE) && (tmpVariables[1] != KMType.P_256)) {
    	KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
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
/*    print("pubkey: ",
    		KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
    		KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
    		KMByteBlob.cast(data[PUB_KEY]).length());
    print("Secret: ",
    		KMByteBlob.cast(data[SECRET]).getBuffer(),
    		KMByteBlob.cast(data[SECRET]).getStartOff(),
    		KMByteBlob.cast(data[SECRET]).length());

 */
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
    if (tmpVariables[1] != 168 && tmpVariables[1] != 192) {
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
	//If params does not contain any digest throw unsupported digest error.
	if(KMType.INVALID_VALUE == KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS])) {
		KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
	}
    // check whether digest sizes are greater then or equal to min mac length.
    // Only SHA256 digest must be supported.
    if(KMEnumArrayTag.contains(KMType.DIGEST, KMType.DIGEST_NONE, data[KEY_PARAMETERS])){
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
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
    if (((short) (tmpVariables[1] % 8) != 0) ||
      (tmpVariables[1] < (short) 64)||
      tmpVariables[1] > (short)512) {
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
    try {
    data[KEY_BLOB] =
        decoder.decodeArray(
            tmpVariables[1],
            KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[KEY_BLOB]).length());
    } catch(ISOException e) {
    	KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
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

    if(KMArray.cast(data[KEY_BLOB]).length() == 5) {
    	tmpVariables[1] = KMArray.instance((short)(tmpVariables[0]+1));
    } else {
    	tmpVariables[1] = KMArray.instance(tmpVariables[0]);
    }
    // convert scratch pad to KMArray
    short index = 0;
    short objPtr = 0;
    while (index < tmpVariables[0]) {
      objPtr = Util.getShort(scratchPad, (short) (index * 2));
      KMArray.cast(tmpVariables[1]).add(index, objPtr);
      index++;
    }
    if(KMArray.cast(data[KEY_BLOB]).length() == 5) {
      KMArray.cast(tmpVariables[1]).add(index, data[PUB_KEY]);
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


  private short addIntegers(short num1, short num2){
    short buf = repository.alloc((short)24);
    byte[] scratchPad = repository.getHeap();
    Util.arrayFillNonAtomic(scratchPad, buf, (short)24,(byte)0);
    Util.arrayCopyNonAtomic(
      KMInteger.cast(num1).getBuffer(),
      KMInteger.cast(num1).getStartOff(),scratchPad,(short)(buf+8-KMInteger.cast(num1).length()),
      KMInteger.cast(num1).length());
    Util.arrayCopyNonAtomic(
      KMInteger.cast(num2).getBuffer(),
      KMInteger.cast(num2).getStartOff(),scratchPad,(short)(buf+16-KMInteger.cast(num2).length()),
      KMInteger.cast(num2).length());
    add(scratchPad, buf, (short)(buf+8), (short)(buf+16));
    return KMInteger.uint_64(scratchPad,(short)(buf+16));
  }

  // num1 must be greater then or equal to num2 and both must be positive
  private short subtractIntegers(short num1, short num2){
    short buf = repository.alloc((short)24);
    byte[] scratchPad = repository.getHeap();
    Util.arrayFillNonAtomic(scratchPad, buf, (short)24,(byte)0);
    Util.arrayCopyNonAtomic(
      KMInteger.cast(num1).getBuffer(),
      KMInteger.cast(num1).getStartOff(),scratchPad,(short)(buf+8-KMInteger.cast(num1).length()),
      KMInteger.cast(num1).length());
    Util.arrayCopyNonAtomic(
      KMInteger.cast(num2).getBuffer(),
      KMInteger.cast(num2).getStartOff(),scratchPad,(short)(buf+16-KMInteger.cast(num2).length()),
      KMInteger.cast(num2).length());
    if(scratchPad[buf] < 0 || scratchPad[(short)(buf+8)] <0)return KMType.INVALID_VALUE;
    if(Util.arrayCompare(scratchPad,buf, scratchPad,(short)(buf+8), (short)8) < 1) return KMType.INVALID_VALUE;
    subtract(scratchPad,buf,(short)(buf+8),(short)(buf+16));
    return KMInteger.uint_64(scratchPad,(short)(buf+16));
  }

  private void add(byte[] buf, short op1, short op2, short result){
    byte index = 7;
    byte carry = 0;
    short tmp = 0;
    while(index >= 0){
      tmp = (short) (buf[(short)(op1+index)] + buf[(short)(op2+index)]+carry);
      carry = 0;
      if(tmp > 255) carry = 1; // max unsigned byte value is 255
      buf[(short)(result+index)] = (byte)(tmp & (byte)0xFF);
      index--;
    }
  }

  // subtraction by borrowing.
  private void subtract(byte[] buf, short op1, short op2, short result) {
/*    short temp1 = KMInteger.uint_64(buf,op1);
    short temp2 = KMInteger.uint_64(buf,op2);
    //twosComplement(buf,  op2);
    negate(buf,  op2);
    add(buf, op1, op2, result);
    increment(buf, result);
    Util.arrayCopyNonAtomic(
      KMInteger.cast(temp1).getBuffer(), KMInteger.cast(temp1).getStartOff(), buf, op1, (short)8);
    Util.arrayCopyNonAtomic(
      KMInteger.cast(temp2).getBuffer(), KMInteger.cast(temp2).getStartOff(), buf, op2, (short)8);
*/
    byte borrow = 0;
    byte index = 7;
    short r = 0;
    short x = 0;
    short y = 0;
    while(index >= 0){
      x = (short)(buf[(short)(op1 + index)] & 0xFF);
      y = (short)(buf[(short)(op2 + index)] & 0xFF);
      r = (short)(x - y - borrow);
      borrow = 0;
      if(r < 0){
        borrow = 1;
        r = (short)(r + 256);// max unsigned byte value is 255
      }
      buf[(short)(result + index)] = (byte)(r & 0xFF);
      index--;
    }
  }
 /* private void twosComplement(byte[] buf, short op){
    negate(buf, op);
    increment(buf, op);
  }
  private void negate(byte[] buf, short op){
    byte index = 7;
    while (index >= 0) {
      buf[(short)(op+index)] = (byte) (~buf[(short)(op+index)]);
      index--;
    }
  }
  private void increment(byte[] buf, short op){
    byte index = 7;
    byte tmp;
    byte carry = 1;
    while(index <= 0){
      tmp = buf[(short)(op+index)];
      buf[(short)(op+index)] = (byte)(buf[(short)(op+index)] + carry);
      if(buf[(short)(op+index)] < tmp) carry = 1;
      else carry = 0;
      index--;
    }
  }*/
  // use Euclid's formula: dividend = quotient*divisor + remainder
  // i.e. dividend - quotient*divisor = remainder where remainder < divisor.
  // so this is division by subtraction until remainder remains.
  private short divide(byte [] buf, short dividend, short divisor, short remainder){
    short expCnt = 1;
    short q = 0;
    // first increase divisor so that it becomes greater then dividend.
    while (compare(buf, divisor, dividend) < 0){
      shiftLeft(buf, divisor);
      expCnt = (short)(expCnt << 1);
    }
    // Now subtract divisor from dividend if dividend is greater then divisor.
    // Copy remainder in the dividend and repeat.
    while(expCnt != 0){
      if(compare(buf, dividend,divisor) >= 0){
       subtract(buf, dividend, divisor, remainder);
       copy(buf, remainder, dividend);
       q = (short)(q + expCnt);
      }
      expCnt = (short)(expCnt >> 1);
      shiftRight(buf, divisor);
    }
    //copy(buf, dividend, remainder);
    return q;
  }

  private void copy(byte[] buf, short from, short to){
    Util.arrayCopyNonAtomic(buf, from, buf,to,(short)8 );
  }

  private byte compare(byte[] buf, short lhs, short rhs){
    return Util.arrayCompare(buf,lhs,buf,rhs,(short)8);
  }
  private void shiftLeft(byte[] buf, short start){
    byte index = 7;
    byte carry = 0;
    byte tmp;
    while (index >= 0){
      tmp = buf[(short)(start+index)];
      buf[(short)(start+index)] = (byte)(buf[(short)(start+index)] << 1);
      buf[(short)(start+index)] = (byte)(buf[(short)(start+index)] + carry);
      if(tmp<0) carry = 1;
      else carry = 0;
      index--;
    }
  }

  private void shiftRight(byte[] buf, short start) {
    byte index = 0;
    byte carry = 0;
    byte tmp;
    while (index < 8) {
      tmp = (byte) (buf[(short)(start+index)] & 0x01);
      buf[(short)(start+index)] = (byte) (buf[(short)(start+index)] >> 1);
      buf[(short)(start+index)] = (byte) (buf[(short)(start+index)] & 0x7F);
      buf[(short)(start+index)] = (byte) (buf[(short)(start+index)] | carry);
      if (tmp == 1) carry = (byte) 0x80;
      else carry = 0;
      index++;
    }
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
  }
*/
}
