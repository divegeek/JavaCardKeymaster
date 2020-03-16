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

import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

// TODO cleanup, move most of the buffers to transient memory with "clear on deselect". Only
//  exception may be OperationState - TBD. The initialize and reset functions will be refactored
//  to handle onInstall and onSelect.

public class KMRepository {
  private static final byte CMD_TABLE_LENGTH = 20;
  private static final byte REF_TABLE_SIZE = 10;
  private static final short HEAP_SIZE = 0x1000;
  private static final byte INT_TABLE_SIZE = 10;
  private static final byte TYPE_ARRAY_SIZE = 100;
  private static final byte INT_SIZE = 4;
  private static final byte LONG_SIZE = 8;
  private KMCommand[] commandTable = null;
  private KMContext context = null;
  private byte[] buffer = null;
  private AESKey masterKey = null;
  private boolean contextLocked = false;
  private KMEncoder encoder = null;
  private KMDecoder decoder = null;

  private KMByteBlob[] byteBlobRefTable = null;
  private byte blobRefIndex = 0;
  private KMInteger[] integerRefTable = null;
  private byte intRefIndex = 0;
  private KMArray[] arrayRefTable = null;
  private byte arrayRefIndex = 0;
  private KMVector[] vectorRefTable = null;
  private byte vectorRefIndex = 0;
  private KMEnum[] enumRefTable = null;
  private byte enumRefIndex = 0;
  private KMByteTag[] byteTagRefTable = null;
  private byte byteTagRefIndex = 0;
  private KMIntegerTag[] intTagRefTable = null;
  private byte intTagRefIndex = 0;
  private KMIntegerArrayTag[] intArrayTagRefTable = null;
  private byte intArrayTagRefIndex = 0;
  private KMEnumTag[] enumTagRefTable = null;
  private byte enumTagRefIndex = 0;
  private KMEnumArrayTag[] enumArrayTagRefTable = null;
  private byte enumArrayTagRefIndex = 0;
  private KMBoolTag[] boolTagRefTable = null;
  private byte boolTagRefIndex = 0;
  private KMKeyParameters[] keyParametersRefTable = null;
  private byte keyParametersRefIndex = 0;
  private KMKeyCharacteristics[] keyCharRefTable = null;
  private byte keyCharRefIndex = 0;
  private KMVerificationToken[] verTokenRefTable = null;
  private byte verTokenRefIndex = 0;
  private KMHmacSharingParameters[] hmacSharingParamsRefTable = null;
  private byte hmacSharingParamsRefIndex = 0;
  private KMHardwareAuthToken[] hwAuthTokenRefTable = null;
  private byte hwAuthTokenRefIndex = 0;
  private KMOperationState[] opStateRefTable = null;
  private byte opStateRefIndex = 0;
  private KMType[] typeRefTable = null;
  private byte typeRefIndex = 0;

  private byte[] byteHeap = null;
  private short byteHeapIndex = 0;
  private Object[] uint32Array = null;
  private byte uint32Index = 0;
  private Object[] uint64Array = null;
  private byte uint64Index = 0;
  private KMOperationState[] operationStateTable = null;

  public void initialize() {
    // Initialize buffers and context.
    JCSystem.beginTransaction();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
    buffer = new byte[KMKeymasterApplet.MAX_LENGTH];
    context = new KMContext();
    context.setRepository(this);
    contextLocked = false;
    operationStateTable = new KMOperationState[4];
    // Initialize command table.
    commandTable = new KMCommand[CMD_TABLE_LENGTH];
    commandTable[0] = new KMProvisionCmd();
    commandTable[1] = new KMGenerateKeyCmd();
    commandTable[2] = new KMImportKeyCmd();
    commandTable[3] = new KMExportKeyCmd();
    commandTable[4] = new KMComputeSharedHmacCmd();
    commandTable[5] = new KMBeginOperationCmd();
    commandTable[6] = new KMUpdateOperationCmd();
    commandTable[7] = new KMFinishOperationCmd();
    commandTable[8] = new KMAbortOperationCmd();
    commandTable[9] = new KMVerifyAuthorizationCmd();
    commandTable[10] = new KMAddRngEntropyCmd();
    commandTable[11] = new KMImportWrappedKeyCmd();
    commandTable[12] = new KMAttestKeyCmd();
    commandTable[13] = new KMUpgradeKeyCmd();
    commandTable[14] = new KMDeleteKeyCmd();
    commandTable[15] = new KMDeleteAllKeysCmd();
    commandTable[16] = new KMDestroyAttestationIdsCmd();
    commandTable[17] = new KMGetHWInfoCmd();
    commandTable[18] = new KMGetKeyCharacteristicsCmd();
    commandTable[19] = new KMGetHmacSharingParametersCmd();
    // Initialize masterkey - AES 256 bit key.
    if (masterKey == null) {
      masterKey =
          (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }
    // Initialize types
    KMType.initialize(this);
    byteBlobRefTable = new KMByteBlob[REF_TABLE_SIZE];
    KMByteBlob.create(byteBlobRefTable);
    integerRefTable = new KMInteger[REF_TABLE_SIZE];
    KMInteger.create(integerRefTable);
    arrayRefTable = new KMArray[REF_TABLE_SIZE];
    KMArray.create(arrayRefTable);
    vectorRefTable = new KMVector[REF_TABLE_SIZE];
    KMVector.create(vectorRefTable);
    enumRefTable = new KMEnum[REF_TABLE_SIZE];
    KMEnum.create(enumRefTable);
    byteTagRefTable = new KMByteTag[REF_TABLE_SIZE];
    KMByteTag.create(byteTagRefTable);
    intTagRefTable = new KMIntegerTag[REF_TABLE_SIZE];
    KMIntegerTag.create(intTagRefTable);
    intArrayTagRefTable = new KMIntegerArrayTag[REF_TABLE_SIZE];
    KMIntegerArrayTag.create(intArrayTagRefTable);
    enumTagRefTable = new KMEnumTag[REF_TABLE_SIZE];
    KMEnumTag.create(enumTagRefTable);
    enumArrayTagRefTable = new KMEnumArrayTag[REF_TABLE_SIZE];
    KMEnumArrayTag.create(enumArrayTagRefTable);
    boolTagRefTable = new KMBoolTag[REF_TABLE_SIZE];
    KMBoolTag.create(boolTagRefTable);
    keyParametersRefTable = new KMKeyParameters[REF_TABLE_SIZE];
    KMKeyParameters.create(keyParametersRefTable);
    keyCharRefTable = new KMKeyCharacteristics[REF_TABLE_SIZE];
    KMKeyCharacteristics.create(keyCharRefTable);
    verTokenRefTable = new KMVerificationToken[REF_TABLE_SIZE];
    KMVerificationToken.create(verTokenRefTable);
    hmacSharingParamsRefTable = new KMHmacSharingParameters[REF_TABLE_SIZE];
    KMHmacSharingParameters.create(hmacSharingParamsRefTable);
    hwAuthTokenRefTable = new KMHardwareAuthToken[REF_TABLE_SIZE];
    KMHardwareAuthToken.create(hwAuthTokenRefTable);
    opStateRefTable = new KMOperationState[REF_TABLE_SIZE];
    KMOperationState.create(opStateRefTable);

    byteHeap = new byte[HEAP_SIZE];
    uint32Array = new Object[INT_TABLE_SIZE];
    uint64Array = new Object[INT_TABLE_SIZE];
    typeRefTable = new KMType[TYPE_ARRAY_SIZE];

    short index = 0;
    while (index < INT_TABLE_SIZE) {
      uint32Array[index] = new byte[INT_SIZE];
      uint64Array[index] = new byte[LONG_SIZE];
      index++;
    }
    JCSystem.commitTransaction();
  }

  public KMEncoder getEncoder() {
    return encoder;
  }

  public KMDecoder getDecoder() {
    return decoder;
  }

  public KMCommand getCommand(byte ins) throws KMException {
    short cmdIndex = 0;
    while (cmdIndex < CMD_TABLE_LENGTH) {
      if (commandTable[cmdIndex].getIns() == ins) {
        return commandTable[cmdIndex];
      }
      cmdIndex++;
    }
    throw new KMException(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  public KMContext getContext() throws KMException {
    if (!contextLocked) {
      contextLocked = true;
      return context;
    } else {
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  public void onUninstall() {
    masterKey = null;
  }

  public void onProcess() {
    reset();
  }

  private void reset() {
    contextLocked = false;
    Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0);
    Util.arrayFillNonAtomic(byteHeap, (short) 0, (short) buffer.length, (byte) 0);
    byteHeapIndex = 0;
    Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0);
    short index = 0;
    while (index < typeRefTable.length) {
      typeRefTable[index] = null;
      index++;
    }
    typeRefIndex = 0;
    index = 0;
    while (index < uint32Array.length) {
      byte[] num = (byte[]) uint32Array[index];
      byte numIndex = 0;
      while (numIndex < INT_SIZE) {
        num[numIndex] = 0;
        numIndex++;
      }
      index++;
    }
    uint32Index = 0;
    index = 0;
    while (index < uint64Array.length) {
      byte[] num = (byte[]) uint64Array[index];
      byte numIndex = 0;
      while (numIndex < LONG_SIZE) {
        num[numIndex] = 0;
        numIndex++;
      }
      index++;
    }
    uint64Index = 0;
    resetTypeObjects(byteBlobRefTable);
    resetTypeObjects(integerRefTable);
    resetTypeObjects(enumRefTable);
    resetTypeObjects(byteTagRefTable);
    resetTypeObjects(boolTagRefTable);
    resetTypeObjects(arrayRefTable);
    resetTypeObjects(enumTagRefTable);
    resetTypeObjects(enumArrayTagRefTable);
    resetTypeObjects(intTagRefTable);
    resetTypeObjects(intArrayTagRefTable);
    resetTypeObjects(vectorRefTable);
    resetTypeObjects(keyCharRefTable);
    resetTypeObjects(keyParametersRefTable);
    resetTypeObjects(hmacSharingParamsRefTable);
    resetTypeObjects(hwAuthTokenRefTable);
    resetTypeObjects(verTokenRefTable);
  }

  public void resetTypeObjects(KMType[] type){
    byte index = 0;
    while(index < type.length){
      type[index].init();
      index++;
    }
  }
  public void onDeselect() {
    // TODO clear operation state?
  }

  public void onSelect() {
    // Nothing to be done currently.
  }

  public byte[] getBuffer() {
    return buffer;
  }

  public AESKey getMasterKey() {
    return masterKey;
  }

  // Allocate 4 bytes or 8 bytes buffer
  public byte[] newIntegerArray(short length) {
    if (length == 4) {
      if (uint32Index >= uint32Array.length) {
        // TODO this is placeholder exception value. This needs to be replaced by 910E, 91A1 or 9210
        throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      byte[] ret = (byte[]) uint32Array[uint32Index];
      uint32Index++;
      return ret;
    } else if (length == 8) {
      if (uint64Index >= uint64Array.length) {
        // TODO this is placeholder exception value. This needs to be replaced by 910E, 91A1 or 9210
        throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      byte[] ret = (byte[]) uint64Array[uint64Index];
      uint64Index++;
      return ret;
    } else {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
  }

  public KMByteBlob newByteBlob() {
    if (blobRefIndex >= byteBlobRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMByteBlob ret = byteBlobRefTable[blobRefIndex];
    blobRefIndex++;
    return ret;
  }

  public KMInteger newInteger() {
    if (intRefIndex >= integerRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMInteger ret = integerRefTable[intRefIndex];
    intRefIndex++;
    return ret;
  }

  public KMEnumTag newEnumTag() {
    if (enumTagRefIndex >= enumTagRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMEnumTag ret = enumTagRefTable[enumTagRefIndex];
    enumTagRefIndex++;
    return ret;
  }

  public KMEnumArrayTag newEnumArrayTag() {
    if (enumArrayTagRefIndex >= enumArrayTagRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMEnumArrayTag ret = enumArrayTagRefTable[enumArrayTagRefIndex];
    enumArrayTagRefIndex++;
    return ret;
  }

  public KMIntegerTag newIntegerTag() {
    if (intTagRefIndex >= intTagRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMIntegerTag ret = intTagRefTable[intTagRefIndex];
    intTagRefIndex++;
    return ret;
  }

  public KMIntegerArrayTag newIntegerArrayTag() {
    if (intArrayTagRefIndex >= intArrayTagRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMIntegerArrayTag ret = intArrayTagRefTable[intArrayTagRefIndex];
    intArrayTagRefIndex++;
    return ret;
  }

  public KMBoolTag newBoolTag() {
    if (boolTagRefIndex >= boolTagRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMBoolTag ret = boolTagRefTable[boolTagRefIndex];
    boolTagRefIndex++;
    return ret;
  }

  public KMByteTag newByteTag() {
    if (byteTagRefIndex >= byteTagRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMByteTag ret = byteTagRefTable[byteTagRefIndex];
    byteTagRefIndex++;
    return ret;
  }

  public KMKeyParameters newKeyParameters() {
    if (keyParametersRefIndex >= keyParametersRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMKeyParameters ret = keyParametersRefTable[keyParametersRefIndex];
    keyParametersRefIndex++;
    return ret;
  }

  public KMArray newArray() {
    if (arrayRefIndex >= arrayRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMArray ret = arrayRefTable[arrayRefIndex];
    arrayRefIndex++;
    return ret;
  }

  public KMKeyCharacteristics newKeyCharacteristics() {
    if (keyCharRefIndex >= keyCharRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMKeyCharacteristics ret = keyCharRefTable[keyCharRefIndex];
    keyCharRefIndex++;
    return ret;
  }

  public KMHardwareAuthToken newHwAuthToken() {
    if (hwAuthTokenRefIndex >= hwAuthTokenRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMHardwareAuthToken ret = hwAuthTokenRefTable[hwAuthTokenRefIndex];
    hwAuthTokenRefIndex++;
    return ret;
  }

  public KMHmacSharingParameters newHmacSharingParameters() {
    if (hmacSharingParamsRefIndex >= hmacSharingParamsRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMHmacSharingParameters ret = hmacSharingParamsRefTable[hmacSharingParamsRefIndex];
    hmacSharingParamsRefIndex++;
    return ret;
  }

  public KMVerificationToken newVerificationToken() {
    if (verTokenRefIndex >= verTokenRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMVerificationToken ret = verTokenRefTable[verTokenRefIndex];
    verTokenRefIndex++;
    return ret;
  }

  public KMOperationState newOperationState() {
    if (opStateRefIndex >= opStateRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMOperationState ret = operationStateTable[opStateRefIndex];
    opStateRefIndex++;
    return ret;
  }

  public void releaseOperationState(KMOperationState state){
    opStateRefIndex--;
    if(opStateRefIndex <0){
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    opStateRefTable[opStateRefIndex] = state;
  }
  public KMVector newVector() {
    if (vectorRefIndex >= vectorRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMVector ret = vectorRefTable[vectorRefIndex];
    vectorRefIndex++;
    return ret;
  }

  public KMEnum newEnum() {
    if (enumRefIndex >= enumRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    KMEnum ret = enumRefTable[enumRefIndex];
    enumRefIndex++;
    return ret;
  }

  public KMType[] getTypeArrayRef(){
    return typeRefTable;
  }

  public byte[] getByteHeapRef(){
    return byteHeap;
  }

  public short newTypeArray(short length) {
    if (((short) (typeRefIndex + length)) >= typeRefTable.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    typeRefIndex += length;
    return (short) (typeRefIndex - length);
  }

  public short newByteArray(short length) {
    if (((short) (byteHeapIndex + length)) >= byteHeap.length) {
      // TODO this is placeholder exception value.
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    byteHeapIndex += length;
    return (short) (byteHeapIndex - length);
  }
}
