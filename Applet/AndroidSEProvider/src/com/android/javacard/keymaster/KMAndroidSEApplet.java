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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import com.android.javacard.seprovider.KMAndroidSEProvider;
import com.android.javacard.seprovider.KMDeviceUniqueKeyPair;
import com.android.javacard.seprovider.KMError;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMType;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

public class KMAndroidSEApplet extends KMKeymasterApplet implements OnUpgradeListener {
  // Magic number version
  private static final byte KM_MAGIC_NUMBER = (byte) 0x82;
  // MSB byte is for Major version and LSB byte is for Minor version.
  public static final short KM_APPLET_PACKAGE_VERSION = 0x0300;

  private static final byte KM_BEGIN_STATE = 0x00;
  private static final byte ILLEGAL_STATE = KM_BEGIN_STATE + 1;
  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;

  // Provider specific Commands
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  // Commands 4, 5 and 6 are reserved for vendor usage.
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 7;
  //0x08 was reserved for INS_INIT_STRONGBOX_CMD
  //0x09 was reserved for INS_SET_BOOT_ENDED_CMD earlier. it is unused now.
  private static final byte INS_SE_FACTORY_PROVISIONING_LOCK_CMD = INS_KEYMINT_PROVIDER_APDU_START + 10;
  private static final byte INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD = INS_KEYMINT_PROVIDER_APDU_START + 11;
  private static final byte INS_OEM_UNLOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 12;
  private static final byte INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 13;
  private static final byte INS_PROVISION_RKP_ADDITIONAL_CERT_CHAIN_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 14;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 15;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 16;  // Unused
  private static final byte INS_OEM_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 17;
  private static final byte INS_PROVISION_SECURE_BOOT_MODE_CMD = INS_KEYMINT_PROVIDER_APDU_START + 18;

  private static final byte INS_KEYMINT_PROVIDER_APDU_END = 0x1F;
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;
  public static final short SHARED_SECRET_KEY_SIZE = 32;

  // Package version.
  protected short packageVersion;

  KMAndroidSEApplet() {
    super(new KMAndroidSEProvider());
    packageVersion = KM_APPLET_PACKAGE_VERSION;
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KMAndroidSEApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  public void handleDeviceBooted() {
    if(seProvider.isBootSignalEventSupported() &&
        seProvider.isDeviceRebooted()) {
      kmDataStore.clearDeviceBootStatus();
      super.reboot();
      seProvider.clearDeviceBooted(true);
    }
  }

  @Override
  public void process(APDU apdu) {
    try {
      handleDeviceBooted();
      // If this is select applet apdu which is selecting this applet then return
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      short apduIns = validateApdu(apdu);
      if (apduIns == KMType.INVALID_VALUE) {
          return;
      }
      if (((KMAndroidSEProvider) seProvider).isPowerReset()) {
        super.powerReset();
      }

      if (isCommandAllowed(apduIns)) {
        switch (apduIns) {
          case INS_PROVISION_ATTEST_IDS_CMD:
            processProvisionAttestIdsCmd(apdu);
            kmDataStore.setProvisionStatus(PROVISION_STATUS_ATTEST_IDS);
            sendResponse(apdu, KMError.OK);
            break;

          case INS_PROVISION_PRESHARED_SECRET_CMD:
            processProvisionPreSharedSecretCmd(apdu);
            kmDataStore.setProvisionStatus(PROVISION_STATUS_PRESHARED_SECRET);
            sendResponse(apdu, KMError.OK);
            break;

          case INS_GET_PROVISION_STATUS_CMD:
            processGetProvisionStatusCmd(apdu);
            break;

          case INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD:
            processProvisionRkpDeviceUniqueKeyPair(apdu);
            break;

          case INS_PROVISION_RKP_ADDITIONAL_CERT_CHAIN_CMD:
            processProvisionRkpAdditionalCertChain(apdu);
            break;
          
          case INS_SE_FACTORY_PROVISIONING_LOCK_CMD:
            kmDataStore.setProvisionStatus(PROVISION_STATUS_SE_LOCKED);
            sendResponse(apdu, KMError.OK);
            break;

          case INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD:
            processProvisionOEMRootPublicKeyCmd(apdu);
            kmDataStore.setProvisionStatus(PROVISION_STATUS_OEM_PUBLIC_KEY);
            sendResponse(apdu, KMError.OK);
            break;

          case INS_OEM_LOCK_PROVISIONING_CMD:
            processOEMLockProvisionCmd(apdu);
            break;
        
          case INS_OEM_UNLOCK_PROVISIONING_CMD:
            processOEMUnlockProvisionCmd(apdu);
            break;

          case INS_PROVISION_SECURE_BOOT_MODE_CMD:
            processSecureBootCmd(apdu);
            break;
        
          default:
            super.process(apdu);
            break;
        }
      } else {
    	ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
    } catch (KMException exception) {
      sendResponse(apdu, KMException.reason());
    } catch (ISOException exp) {
      sendResponse(apdu, mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      sendResponse(apdu, mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      sendResponse(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      repository.clean();
    }
  }

  private boolean isCommandAllowed(short apduIns) {
    boolean result = true;
    switch(apduIns) {
      case INS_PROVISION_ATTEST_IDS_CMD:
      case INS_PROVISION_PRESHARED_SECRET_CMD:
      case INS_PROVISION_SECURE_BOOT_MODE_CMD:
      case INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD:
        if(kmDataStore.isProvisionLocked()) {
          result = false;  
        }
        break;

      case INS_OEM_UNLOCK_PROVISIONING_CMD:
    	if(!kmDataStore.isProvisionLocked()) {
          result = false;  
        }
    	break;
    	
      case INS_SE_FACTORY_PROVISIONING_LOCK_CMD:
        if(isSeFactoryProvisioningLocked() || !isSeFactoryProvisioningComplete()) {
          result = false;  
        }
        break;
        
      case INS_OEM_LOCK_PROVISIONING_CMD:
        // Allow lock only when
        // 1. All the necessary provisioning commands are succcessfully executed
        // 2. SE provision is locked
        // 3. OEM Root Public is provisioned.
        if (kmDataStore.isProvisionLocked() || !(isProvisioningComplete()
            && isSeFactoryProvisioningLocked())) {
          result = false;
        }
        break;
        
      case INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD:
      case INS_PROVISION_RKP_ADDITIONAL_CERT_CHAIN_CMD:
        if(isSeFactoryProvisioningLocked()) {
          result = false;  
        }
        break;
        
      case INS_GET_PROVISION_STATUS_CMD:
    	break;
    	
      default:
        // Allow other commands only if provision is completed.  
    	if (!isProvisioningComplete()) {
    	  result = false;
    	}   	          
    }
    return result;
  }
  
  private boolean isSeFactoryProvisioningLocked() {
    short pStatus  = kmDataStore.getProvisionStatus();
    boolean result = false;
    if ((0 != (pStatus & PROVISION_STATUS_SE_LOCKED))) {
    	result = true;
    }
    return result;
  }

  private boolean isSeFactoryProvisioningComplete() {
    short pStatus = kmDataStore.getProvisionStatus();
    if (PROVISION_STATUS_DEVICE_UNIQUE_KEYPAIR ==
        (pStatus & PROVISION_STATUS_DEVICE_UNIQUE_KEYPAIR)) {
      return true;
    }
    return false;
  }

  private void processSecureBootCmd(APDU apdu) {
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, KMInteger.exp());
    short args = receiveIncoming(apdu, argsProto);
    short val = KMInteger.cast(KMArray.cast(args).get((short) 0)).getShort();
    if (val != 1 && val != 0) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Store secure boot mode value.
    JCSystem.beginTransaction();
    kmDataStore.secureBootMode = (byte) val;
    JCSystem.commitTransaction();
    kmDataStore.setProvisionStatus(PROVISION_STATUS_SECURE_BOOT_MODE);
    sendResponse(apdu, KMError.OK);
  }

  private void processOEMUnlockProvisionCmd(APDU apdu) {
    authenticateOEM(OEM_UNLOCK_PROVISION_VERIFICATION_LABEL, apdu);
    kmDataStore.unlockProvision();
    sendResponse(apdu, KMError.OK);
  }

  private void processOEMLockProvisionCmd(APDU apdu) {
    authenticateOEM(OEM_LOCK_PROVISION_VERIFICATION_LABEL, apdu);
    // Enable the lock bit in provision status.
    kmDataStore.setProvisionStatus(PROVISION_STATUS_PROVISIONING_LOCKED);
    sendResponse(apdu, KMError.OK);
  }

  private void authenticateOEM(byte[] plainMsg, APDU apdu) {
    
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp());
    short args = receiveIncoming(apdu, tmpVariables[0]);
    // Get the signature input.
    short signature = KMArray.cast(args).get((short) 0);
    byte[] oemPublicKey = kmDataStore.getOEMRootPublicKey();

    if (!seProvider.ecVerify256(
        oemPublicKey, (short) 0, (short) oemPublicKey.length,
        plainMsg, (short) 0, (short) plainMsg.length,
        KMByteBlob.cast(signature).getBuffer(),
        KMByteBlob.cast(signature).getStartOff(),
        KMByteBlob.cast(signature).length())) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private void processProvisionOEMRootPublicKeyCmd(APDU apdu) {  
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormatPtr);
    KMArray.cast(argsProto).add((short) 2, blob);
    short args = receiveIncoming(apdu, argsProto);

    // key params should have os patch, os version and verified root of trust
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMArray.cast(args).get((short) 1);
    // Key format must be RAW format
    byte keyFormat = KMEnum.cast(tmpVariables[0]).getVal();
    if (keyFormat != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }

    // get algorithm - only EC keys expected
    tmpVariables[0] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.EC) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // get digest - only SHA256 supported
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short) 0);
      if (tmpVariables[0] != KMType.SHA2_256) {
        KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
      }
    } else {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Purpose should be VERIFY
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short) 0);
      if (tmpVariables[0] != KMType.VERIFY) {
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    } else {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    tmpVariables[0] = KMArray.cast(args).get((short) 2);
    // persist OEM Root Public Key.
    kmDataStore.persistOEMRootPublicKey(
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length());
  }

  private static void processProvisionRkpDeviceUniqueKeyPair(APDU apdu) {
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    short arr = KMArray.instance((short) 1);
    short coseKeyExp = KMCoseKey.exp();
    KMArray.cast(arr).add((short) 0, coseKeyExp); //[ CoseKey ]
    arr = receiveIncoming(apdu, arr);
    // Get cose key.
    short coseKey = KMArray.cast(arr).get((short) 0);
    short pubKeyLen = KMCoseKey.cast(coseKey).getEcdsa256PublicKey(scratchPad, (short) 0);
    short privKeyLen = KMCoseKey.cast(coseKey).getPrivateKey(scratchPad, pubKeyLen);
    //Store the Device unique Key.
    kmDataStore.createRkpDeviceUniqueKeyPair(scratchPad, (short) 0, pubKeyLen, scratchPad,
        pubKeyLen, privKeyLen);
    short bcc = generateBcc(false, scratchPad);
    short len = KMKeymasterApplet.encodeToApduBuffer(bcc, scratchPad, (short) 0,
        MAX_COSE_BUF_SIZE);
    kmDataStore.persistBootCertificateChain(scratchPad, (short) 0, len);
    kmDataStore.setProvisionStatus(PROVISION_STATUS_DEVICE_UNIQUE_KEYPAIR);
    sendResponse(apdu, KMError.OK);
  }

  private void processProvisionRkpAdditionalCertChain(APDU apdu) {
    // X509 certificate chain is received as shown below:
    /**
     *     x509CertChain = bstr .cbor UdsCerts
     *
     *     AdditionalDKSignatures = {
     *         * SignerName => DKCertChain
     *     }
     *     ; SignerName is a string identifier that indicates both the signing authority as
     *     ; well as the format of the DKCertChain
     *     SignerName = tstr
     *
     *     DKCertChain = [
     *         2* X509Certificate       ; Root -> ... -> Leaf. "Root" is the vendor self-signed
     *                                  ; cert, "Leaf" contains DK_pub. There may also be
     *                                  ; intermediate certificates between Root and Leaf.
     *     ]
     *     ; A bstr containing a DER-encoded X.509 certificate (RSA, NIST P-curve, or edDSA)
     *     X509Certificate = bstr
     */
    // Store the cbor encoded UdsCerts as it is in the persistent memory so cbor decoding is
    // required here.
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = repository.allocReclaimableMemory(bufferLength);
    short index = bufferStartOffset;
    byte[] buffer = repository.getHeap();
    while (recvLen > 0 && ((short) (index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    short byteHeaderLen = decoder.readCertificateChainHeaderLen(buffer, bufferStartOffset,
        bufferLength);
    kmDataStore.persistAdditionalCertChain(buffer, (short) (bufferStartOffset + byteHeaderLen),
        (short) (bufferLength - byteHeaderLen));
    kmDataStore.setProvisionStatus(PROVISION_STATUS_ADDITIONAL_CERT_CHAIN);
    // reclaim memory
    repository.reclaimMemory(bufferLength);
    sendResponse(apdu, KMError.OK);
  }

  private void processProvisionAttestIdsCmd(APDU apdu) {
    short keyparams = KMKeyParameters.exp();
    short cmd = KMArray.instance((short) 1);
    KMArray.cast(cmd).add((short) 0, keyparams);
    short args = receiveIncoming(apdu, cmd);

    short attData = KMArray.cast(args).get((short) 0);
    // persist attestation Ids - if any is missing then exception occurs
    setAttestationIds(attData);
  }

  public void setAttestationIds(short attIdVals) {
    KMKeyParameters instParam = KMKeyParameters.cast(attIdVals);
    KMArray vals = KMArray.cast(instParam.getVals());
    short index = 0;
    short length = vals.length();
    short key;
    short type;
    short obj;
    while (index < length) {
      obj = vals.get(index);
      key = KMTag.getKey(obj);
      type = KMTag.getTagType(obj);

      if (KMType.BYTES_TAG != type) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      obj = KMByteTag.cast(obj).getValue();
      if (KMByteBlob.cast(obj).length() > KMConfigurations.MAX_ATTESTATION_IDS_SIZE) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
      }
      kmDataStore.setAttestationId(key, KMByteBlob.cast(obj).getBuffer(),
          KMByteBlob.cast(obj).getStartOff(), KMByteBlob.cast(obj).length());
      index++;
    }
  }

  private void processProvisionPreSharedSecretCmd(APDU apdu) {
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, blob);
    short args = receiveIncoming(apdu, argsProto);

    short val = KMArray.cast(args).get((short) 0);

    if (val != KMType.INVALID_VALUE
        && KMByteBlob.cast(val).length() != SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Persist shared Hmac.
    kmDataStore.createPresharedKey(
        KMByteBlob.cast(val).getBuffer(),
        KMByteBlob.cast(val).getStartOff(),
        KMByteBlob.cast(val).length());

  }

  //This function masks the error code with POWER_RESET_MASK_FLAG
  // in case if card reset event occurred. The clients of the Applet
  // has to extract the power reset status from the error code and
  // process accordingly.
  private static short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (((KMAndroidSEProvider) seProvider).isPowerReset()) {
      powerResetStatus = POWER_RESET_MASK_FLAG;
    }

    Util.setShort(KMInteger.cast(int32Ptr).getBuffer(),
        KMInteger.cast(int32Ptr).getStartOff(),
        powerResetStatus);

    Util.setShort(KMInteger.cast(int32Ptr).getBuffer(),
        (short) (KMInteger.cast(int32Ptr).getStartOff() + 2),
        err);
    // reset power reset status flag to its default value.
    //repository.restorePowerResetStatus(); //TODO
    return int32Ptr;
  }

  private void processGetProvisionStatusCmd(APDU apdu) {
    byte[] scratchpad = apdu.getBuffer();
    short pStatus = kmDataStore.getProvisionStatus();
    Util.setShort(scratchpad, (short)0, pStatus);
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(resp).add((short) 1, KMInteger.instance(scratchpad, (short)0, (short)2));
    sendOutgoing(apdu, resp);
  }

  private boolean isProvisioningComplete() {
    short pStatus = kmDataStore.getProvisionStatus();
    short pCompleteStatus =
        PROVISION_STATUS_DEVICE_UNIQUE_KEYPAIR | PROVISION_STATUS_PRESHARED_SECRET
            | PROVISION_STATUS_ATTEST_IDS | PROVISION_STATUS_OEM_PUBLIC_KEY |
            PROVISION_STATUS_SECURE_BOOT_MODE;
    if (kmDataStore.isProvisionLocked() || (pCompleteStatus == (pStatus & pCompleteStatus))) {
      return true;
    }
    return false;
  }

  @Override
  public void onCleanup() {
  }

  @Override
  public void onConsolidate() {
  }
  
  private boolean isUpgradeAllowed(short oldVersion) {
    boolean upgradeAllowed = false;
    // Downgrade of the Applet is not allowed.
    if (KM_APPLET_PACKAGE_VERSION >= oldVersion) { 
      upgradeAllowed = true;
    }
    return upgradeAllowed;
  }

  @Override
  public void onRestore(Element element) {
    element.initRead();
    byte magicNumber = element.readByte();
    if (magicNumber != KM_MAGIC_NUMBER) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short oldPackageVersion = element.readShort();
    // Validate version.
    if (!isUpgradeAllowed(oldPackageVersion)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    kmDataStore.onRestore(element, oldPackageVersion, KM_APPLET_PACKAGE_VERSION); 
  }

  @Override
  public Element onSave() {
	short primitiveCount = 3;
	primitiveCount += kmDataStore.getBackupPrimitiveByteCount();
	short objectCount = kmDataStore.getBackupObjectCount();
	// Create element.
    Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE,
        primitiveCount, objectCount);
	
    element.write(KM_MAGIC_NUMBER);
    element.write(packageVersion);
    kmDataStore.onSave(element);
    return element;	
  }

  private short validateApdu(APDU apdu) {
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

    // Validate CLA
    if (!apdu.isValidCLA()) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    // Validate P1P2.
    if (P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      sendResponse(apdu, KMError.INVALID_P1P2);
      return KMType.INVALID_VALUE;
    }
    return apduBuffer[ISO7816.OFFSET_INS];
  }

}
