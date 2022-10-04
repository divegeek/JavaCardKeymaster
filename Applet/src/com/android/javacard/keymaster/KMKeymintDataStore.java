package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;

import com.android.javacard.seprovider.KMAESKey;
import com.android.javacard.seprovider.KMAttestationKey;
import com.android.javacard.seprovider.KMComputedHmacKey;
import com.android.javacard.seprovider.KMDataStoreConstants;
import com.android.javacard.seprovider.KMDeviceUniqueKeyPair;
import com.android.javacard.seprovider.KMECDeviceUniqueKey;
import com.android.javacard.seprovider.KMECPrivateKey;
import com.android.javacard.seprovider.KMError;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMHmacKey;
import com.android.javacard.seprovider.KMMasterKey;
import com.android.javacard.seprovider.KMPreSharedKey;
import com.android.javacard.seprovider.KMRkpMacKey;
import com.android.javacard.seprovider.KMSEProvider;
import com.android.javacard.seprovider.KMType;
import com.android.javacard.seprovider.KMUpgradable;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class KMKeymintDataStore implements KMUpgradable {
	
  // Data table configuration
  public static final short KM_APPLET_PACKAGE_VERSION_1 = 0x0100;
  public static final short KM_APPLET_PACKAGE_VERSION_2 = 0x0200;
  public static final short KM_APPLET_PACKAGE_VERSION_3 = 0x0300;
  public static final short OLD_DATA_INDEX_SIZE = 19;
  public static final short DATA_INDEX_SIZE = 17;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;
  public static final short DATA_MEM_SIZE = 300;

  // Old Data table offsets
  private static final byte OLD_PROVISIONED_STATUS_OFFSET = 18;
  
  // Data table offsets
  public static final byte HMAC_NONCE = 0;
  public static final byte BOOT_OS_VERSION = 1;
  public static final byte BOOT_OS_PATCH_LEVEL = 2;
  public static final byte VENDOR_PATCH_LEVEL = 3;
  public static final byte DEVICE_LOCKED_TIME = 4;
  public static final byte DEVICE_LOCKED = 5;
  public static final byte DEVICE_LOCKED_PASSWORD_ONLY = 6;

  // Total 8 auth tags, so the next offset is AUTH_TAG_1 + 8
  public static final byte AUTH_TAG_1 = 7;
  public static final byte DEVICE_STATUS_FLAG = 15;
  public static final byte EARLY_BOOT_ENDED_FLAG = 16;  
  
  // Data Item sizes
  public static final short HMAC_SEED_NONCE_SIZE = 32;
  public static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short OS_VERSION_SIZE = 4;
  public static final short OS_PATCH_SIZE = 4;
  public static final short VENDOR_PATCH_SIZE = 4;
  public static final short DEVICE_LOCK_TS_SIZE = 8;
  public static final short MAX_BLOB_STORAGE = 8;
  public static final short AUTH_TAG_LENGTH = 16;
  public static final short AUTH_TAG_COUNTER_SIZE = 4;
  public static final short AUTH_TAG_ENTRY_SIZE = (AUTH_TAG_LENGTH + AUTH_TAG_COUNTER_SIZE + 1);
  private static final short MASTER_KEY_SIZE = 16;
  private static final short SHARED_SECRET_KEY_SIZE = 32;
  private static final byte DEVICE_STATUS_FLAG_SIZE = 1;
  
  private static final short ADDITIONAL_CERT_CHAIN_MAX_SIZE = 2500;//First 2 bytes for length.
  private static final short BCC_MAX_SIZE = 512;

 //Device boot states. Applet starts executing the
 // core commands once all the states are set. The commands
 // that are allowed irrespective of these states are:
 // All the provision commands
 // INS_GET_HW_INFO_CMD
 // INS_ADD_RNG_ENTROPY_CMD
 // INS_COMPUTE_SHARED_HMAC_CMD
 // INS_GET_HMAC_SHARING_PARAM_CMD
 public static final byte SET_BOOT_PARAMS_SUCCESS = 0x01;
 public static final byte SET_SYSTEM_PROPERTIES_SUCCESS = 0x02;
 public static final byte NEGOTIATED_SHARED_SECRET_SUCCESS = 0x04;

  // Data - originally was in repository
  private byte[] attIdBrand;
  private byte[] attIdDevice;
  private byte[] attIdProduct;
  private byte[] attIdSerial;
  private byte[] attIdImei;
  private byte[] attIdMeId;
  private byte[] attIdManufacturer;
  private byte[] attIdModel;

  // Boot parameters
  private byte[] verifiedHash;
  private byte[] bootKey;
  private byte[] bootPatchLevel;
  private boolean deviceBootLocked;
  private short bootState;
  // Challenge for Root of trust
  private byte[] challenge;

  // Secure Boot Mode
  public byte secureBootMode;
  
  private short dataIndex;
  private byte[] dataTable;
  private KMSEProvider seProvider;
  private KMRepository repository;
  private byte[] additionalCertChain;
  private byte[] bcc;
  private KMMasterKey masterKey;
  private KMDeviceUniqueKeyPair testDeviceUniqueKeyPair;
  private KMDeviceUniqueKeyPair deviceUniqueKeyPair;
  private KMPreSharedKey preSharedKey;
  private KMComputedHmacKey computedHmacKey;
  private KMRkpMacKey rkpMacKey;
  private byte[] oemRootPublicKey;
  private short provisionStatus;
  private static KMKeymintDataStore kmDataStore;

  public static KMKeymintDataStore instance() {
    return kmDataStore;
  }
  
  public KMKeymintDataStore(KMSEProvider provider, KMRepository repo) {
    seProvider = provider;
    repository = repo;
    boolean isUpgrading = provider.isUpgrading();
    initDataTable();
    //Initialize the device locked status
    if (!isUpgrading) {
      additionalCertChain = new byte[ADDITIONAL_CERT_CHAIN_MAX_SIZE];
      bcc = new byte[BCC_MAX_SIZE];
      oemRootPublicKey = new byte[65];
    }
    setDeviceLockPasswordOnly(false);
    setDeviceLock(false);
    kmDataStore = this;
  }
  
  private void initDataTable() {
    if (dataTable == null) {
      dataTable = new byte[DATA_MEM_SIZE];
      dataIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
    }  
  }
  
  private short dataAlloc(short length) {
    if (((short) (dataIndex + length)) > dataTable.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    dataIndex += length;
    return (short) (dataIndex - length);
  }

  private void clearDataEntry(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen != 0) {
      short dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      JCSystem.beginTransaction();
      Util.arrayFillNonAtomic(dataTable, dataPtr, dataLen, (byte) 0);
      JCSystem.commitTransaction();
    }
  }

  private void writeDataEntry(short id, byte[] buf, short offset, short len) {
    short dataPtr;
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen == 0) {
      dataPtr = dataAlloc(len);
      JCSystem.beginTransaction();
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET), dataPtr);
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH), len);
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
      JCSystem.commitTransaction();
    } else {
      if (len != dataLen) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      JCSystem.beginTransaction();
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
      JCSystem.commitTransaction();
    }
  }

  private short readDataEntry(short id, byte[] buf, short offset) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (len != 0) {
      Util.arrayCopyNonAtomic(
          dataTable,
          Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)),
          buf,
          offset,
          len);
    }
    return len;
  }
  
  private short readDataEntry(byte[] dataTable, short id, byte[] buf, short offset) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (len != 0) {
      Util.arrayCopyNonAtomic(
          dataTable,
          Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)),
          buf,
          offset,
          len);
    }
    return len;
  }

  private short dataLength(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
  }
  
  public short readData(short id) {
    short len = dataLength(id);
    if (len != 0) {
      short blob = KMByteBlob.instance(dataLength(id));
      readDataEntry(id, KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
      return blob;
    }
    return KMType.INVALID_VALUE;
  }
  
  public short getHmacNonce() {
    return readData(HMAC_NONCE);
  }

  private static final byte[] zero = {0, 0, 0, 0, 0, 0, 0, 0};

  public short getOsVersion() {
    short blob = readData(BOOT_OS_VERSION);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
  }

  public short getVendorPatchLevel() {
    short blob = readData(VENDOR_PATCH_LEVEL);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
  }

  public short getOsPatch() {
    short blob = readData(BOOT_OS_PATCH_LEVEL);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
  }

  private boolean readBoolean(short id) {
    short blob = readData(id);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return (byte) ((repository.getHeap())[KMByteBlob.cast(blob).getStartOff()]) == 0x01;
  }

  public boolean getDeviceLock() {
    return readBoolean(DEVICE_LOCKED);
  }

  public boolean getDeviceLockPasswordOnly() {
    return readBoolean(DEVICE_LOCKED_PASSWORD_ONLY);
  }

  public boolean getEarlyBootEndedStatus() {
    return readBoolean(EARLY_BOOT_ENDED_FLAG);
  }

  public short getDeviceTimeStamp() {
    short blob = readData(DEVICE_LOCKED_TIME);
    if (blob == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return KMInteger.uint_64(KMByteBlob.cast(blob).getBuffer(),
          KMByteBlob.cast(blob).getStartOff());
  }

  public void setOsVersion(byte[] buf, short start, short len) {
    if (len != OS_VERSION_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_OS_VERSION, buf, start, len);
  }

  public void setVendorPatchLevel(byte[] buf, short start, short len) {
    if (len != VENDOR_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(VENDOR_PATCH_LEVEL, buf, start, len);
  }

  private void writeBoolean(short id, boolean flag) {
    short start = repository.alloc((short) 1);
    if (flag) {
      (repository.getHeap())[start] = (byte) 0x01;
    } else {
      (repository.getHeap())[start] = (byte) 0x00;
    }
    writeDataEntry(id, repository.getHeap(), start, (short) 1);
  }

  public void setDeviceLock(boolean flag) {
    writeBoolean(DEVICE_LOCKED, flag);
  }

  public void setDeviceLockPasswordOnly(boolean flag) {
    writeBoolean(DEVICE_LOCKED_PASSWORD_ONLY, flag);
  }

  public void setDeviceLockTimestamp(byte[] buf, short start, short len) {
    if (len != DEVICE_LOCK_TS_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(DEVICE_LOCKED_TIME, buf, start, len);
  }

  public void setEarlyBootEndedStatus(boolean flag) {
    writeBoolean(EARLY_BOOT_ENDED_FLAG, flag);
  }
  
  public void clearDeviceBootStatus() {
	clearDataEntry(DEVICE_STATUS_FLAG);
  }

  public void setDeviceBootStatus(byte initStatus) {
    short offset = repository.allocReclaimableMemory(DEVICE_STATUS_FLAG_SIZE);
	byte[] buf = repository.getHeap();
	getDeviceBootStatus(buf, offset);
	buf[offset] |= initStatus;
    writeDataEntry(DEVICE_STATUS_FLAG, buf, offset, DEVICE_STATUS_FLAG_SIZE);
    repository.reclaimMemory(DEVICE_STATUS_FLAG_SIZE);
  }

  public boolean isDeviceReady() {
    boolean result = false;
    short offset = repository.allocReclaimableMemory(DEVICE_STATUS_FLAG_SIZE);
    byte[] buf = repository.getHeap();
    getDeviceBootStatus(buf, offset);
    byte bootCompleteStatus = (SET_BOOT_PARAMS_SUCCESS | SET_SYSTEM_PROPERTIES_SUCCESS |
        NEGOTIATED_SHARED_SECRET_SUCCESS);
    if (bootCompleteStatus == (buf[offset] & bootCompleteStatus)) {
      result = true;
    }
    repository.reclaimMemory(DEVICE_STATUS_FLAG_SIZE);
    return result;
  }

  public short getDeviceBootStatus(byte[] scratchpad, short offset) {
    scratchpad[offset] = 0;
    return readDataEntry(DEVICE_STATUS_FLAG, scratchpad, offset);
  }

  public void clearDeviceLockTimeStamp() {
    clearDataEntry(DEVICE_LOCKED_TIME);
  }

  public void setOsPatch(byte[] buf, short start, short len) {
    if (len != OS_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_OS_PATCH_LEVEL, buf, start, len);
  }

  private boolean isAuthTagSlotAvailable(short tagId, byte[] buf, short offset) {
    readDataEntry(tagId, buf, offset);
    return (0 == buf[offset]);
  }
  
  public void initHmacNonce(byte[] nonce, short offset, short len) {
    if (len != HMAC_SEED_NONCE_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(HMAC_NONCE, nonce, offset, len);
  }

  public void clearHmacNonce() {
    clearDataEntry(HMAC_NONCE);
  }
  
  public boolean persistAuthTag(short authTag) {

    if (KMByteBlob.cast(authTag).length() != AUTH_TAG_LENGTH) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    short authTagEntry = repository.alloc(AUTH_TAG_ENTRY_SIZE);
    short scratchPadOff = repository.alloc(AUTH_TAG_ENTRY_SIZE);
    byte[] scratchPad = repository.getHeap();
    writeAuthTagState(repository.getHeap(), authTagEntry, (byte) 1);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(authTag).getBuffer(),
        KMByteBlob.cast(authTag).getStartOff(),
        repository.getHeap(), (short) (authTagEntry + 1), AUTH_TAG_LENGTH);
    Util.setShort(repository.getHeap(), (short) (authTagEntry + AUTH_TAG_LENGTH + 1 + 2),
        (short) 1);
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      if ((dataLength((short) (index + AUTH_TAG_1)) == 0) ||
          isAuthTagSlotAvailable((short) (index + AUTH_TAG_1), scratchPad, scratchPadOff)) {

        writeDataEntry((short) (index + AUTH_TAG_1), repository.getHeap(), authTagEntry, AUTH_TAG_ENTRY_SIZE);
        return true;
      }
      index++;
    }
    return false;
  }

  public void removeAllAuthTags() {
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      clearDataEntry((short) (index + AUTH_TAG_1));
      index++;
    }
  }

  public boolean isAuthTagPersisted(short authTag) {
    return (KMType.INVALID_VALUE != findTag(authTag));
  }

  private short findTag(short authTag) {
    if (KMByteBlob.cast(authTag).length() != AUTH_TAG_LENGTH) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    short index = 0;
    short found;
    short offset = repository.alloc(AUTH_TAG_ENTRY_SIZE);
    while (index < MAX_BLOB_STORAGE) {
      if (dataLength((short) (index + AUTH_TAG_1)) != 0) {
        readDataEntry((short) (index + AUTH_TAG_1),
        		repository.getHeap(), offset);
        found =
            Util.arrayCompare(
            		repository.getHeap(),
                (short) (offset + 1),
                KMByteBlob.cast(authTag).getBuffer(),
                KMByteBlob.cast(authTag).getStartOff(),
                AUTH_TAG_LENGTH);
        if (found == 0) {
          return (short) (index + AUTH_TAG_1);
        }
      }
      index++;
    }
    return KMType.INVALID_VALUE;
  }

  public short getRateLimitedKeyCount(short authTag, byte[] out, short outOff) {
    short tag = findTag(authTag);
    short blob;
    if (tag != KMType.INVALID_VALUE) {
      blob = readData(tag);
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(blob).getBuffer(),
          (short) (KMByteBlob.cast(blob).getStartOff() + AUTH_TAG_LENGTH + 1),
          out,
          outOff,
          AUTH_TAG_COUNTER_SIZE);
      return AUTH_TAG_COUNTER_SIZE;
    }
    return (short) 0;
  }

  public void setRateLimitedKeyCount(short authTag, byte[] buf, short off, short len) {
    short tag = findTag(authTag);
    if (tag != KMType.INVALID_VALUE) {
      short dataPtr = readData(tag);
      Util.arrayCopyNonAtomic(
          buf,
          off,
          KMByteBlob.cast(dataPtr).getBuffer(),
          (short) (KMByteBlob.cast(dataPtr).getStartOff() + AUTH_TAG_LENGTH + 1),
          len);
      writeDataEntry(tag,
          KMByteBlob.cast(dataPtr).getBuffer(),
          KMByteBlob.cast(dataPtr).getStartOff(),
          KMByteBlob.cast(dataPtr).length());
    }
  }
  
  public void persistAdditionalCertChain(byte[] buf, short offset, short len) {
    // Input buffer contains encoded additional certificate chain as shown below.
    //    AdditionalDKSignatures = {
    //      + SignerName => DKCertChain
    //    }
    //    SignerName = tstr
    //    DKCertChain = [
    //      2* Certificate // Root -> Leaf. Root is the vendo r
    //            // self-signed cert, leaf contains DK_pu b
    //    ]
    //    Certificate = COSE_Sign1 of a public key
    if ((short) (len + 2) > ADDITIONAL_CERT_CHAIN_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.setShort(additionalCertChain, (short) 0, (short) len);
    Util.arrayCopyNonAtomic(buf, offset, additionalCertChain,
        (short) 2, len);
    JCSystem.commitTransaction();
  }

  public short getAdditionalCertChainLength() {
    return Util.getShort(additionalCertChain, (short) 0);
  }

  public byte[] getAdditionalCertChain() {
    return additionalCertChain;
  }

  public byte[] getBootCertificateChain() {
    return bcc;
  }

  public void persistBootCertificateChain(byte[] buf, short offset, short len) {
    if ((short) (len + 2) > BCC_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.setShort(bcc, (short) 0, (short) len);
    Util.arrayCopyNonAtomic(buf, offset, bcc,
        (short) 2, len);
    JCSystem.commitTransaction();
  }
  
  private void writeAuthTagState(byte[] buf, short offset, byte state) {
    buf[offset] = state;
  }
  
  public KMMasterKey createMasterKey(short keySizeBits) {
    if (masterKey == null) {
	  masterKey = seProvider.createMasterKey(masterKey, keySizeBits);
    }
    return (KMMasterKey) masterKey;
  }

  public KMMasterKey getMasterKey() {
    return masterKey;
  }

  public void createPresharedKey(byte[] keyData, short offset, short length) {
    if (length != SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if (preSharedKey == null) {
      preSharedKey = seProvider.createPreSharedKey(preSharedKey, keyData, offset, length);
    }
  }
  
  public KMPreSharedKey getPresharedKey() {
    if (preSharedKey == null) {
      KMException.throwIt(KMError.INVALID_DATA);
    } 
    return preSharedKey;
  }
  
  public void createComputedHmacKey(byte[] keyData, short offset, short length) {
    if (length != COMPUTED_HMAC_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if (computedHmacKey == null) {
      computedHmacKey = seProvider.createComputedHmacKey(computedHmacKey, keyData, offset, length);
    } else {
      seProvider.createComputedHmacKey(computedHmacKey, keyData, offset, length);
    }
  }  
  
  public KMComputedHmacKey getComputedHmacKey() {
    if (computedHmacKey == null) {
      KMException.throwIt(KMError.INVALID_DATA);		
    }  
    return computedHmacKey;
  }
  
  public KMDeviceUniqueKeyPair createRkpTestDeviceUniqueKeyPair(byte[] pubKey, short pubKeyOff, short pubKeyLen,
      byte[] privKey, short privKeyOff, short privKeyLen) {
    if (testDeviceUniqueKeyPair == null) {
      testDeviceUniqueKeyPair = seProvider.createRkpDeviceUniqueKeyPair(testDeviceUniqueKeyPair, pubKey, pubKeyOff,
          pubKeyLen, privKey,
          privKeyOff, privKeyLen);
    } else {
      seProvider.createRkpDeviceUniqueKeyPair(testDeviceUniqueKeyPair, pubKey, pubKeyOff, pubKeyLen, privKey,
          privKeyOff,
          privKeyLen);
    }
    return testDeviceUniqueKeyPair;
  }

  public KMDeviceUniqueKeyPair createRkpDeviceUniqueKeyPair(byte[] pubKey, short pubKeyOff, short pubKeyLen,
      byte[] privKey, short privKeyOff,
      short privKeyLen) {
    if (deviceUniqueKeyPair == null) {
      deviceUniqueKeyPair = seProvider.createRkpDeviceUniqueKeyPair(deviceUniqueKeyPair, pubKey, pubKeyOff,
          pubKeyLen, privKey,
          privKeyOff, privKeyLen);
    } else {
      seProvider.createRkpDeviceUniqueKeyPair(deviceUniqueKeyPair, pubKey, pubKeyOff, pubKeyLen, privKey,
          privKeyOff, privKeyLen);
    }
    return deviceUniqueKeyPair;
  }
  
  public KMDeviceUniqueKeyPair getRkpDeviceUniqueKeyPair(boolean testMode) {
    return ((KMDeviceUniqueKeyPair) (testMode ? testDeviceUniqueKeyPair : deviceUniqueKeyPair));
  }
  
  public void createRkpMacKey(byte[] keydata, short offset, short length) {
    if (rkpMacKey == null) {
    	rkpMacKey = seProvider.createRkpMacKey(rkpMacKey, keydata, offset, length);
    } else {
      seProvider.createRkpMacKey(rkpMacKey, keydata, offset, length);
    }
  }
  
  public KMRkpMacKey getRkpMacKey() {
    if (rkpMacKey == null) {
      KMException.throwIt(KMError.INVALID_DATA);		
    }  
    return rkpMacKey;
  }
	
  public short getAttestationId(short tag, byte[] buffer, short start) {
    byte[] attestId = null;
    switch (tag) {
      // Attestation Id Brand
      case KMType.ATTESTATION_ID_BRAND:
    	attestId = attIdBrand;
    	break;
      // Attestation Id Device
      case KMType.ATTESTATION_ID_DEVICE:
    	attestId = attIdDevice;
    	break;
      // Attestation Id Product
      case KMType.ATTESTATION_ID_PRODUCT:
    	attestId = attIdProduct;
    	break;
      // Attestation Id Serial
      case KMType.ATTESTATION_ID_SERIAL:
    	attestId = attIdSerial;
    	break;
      // Attestation Id IMEI
      case KMType.ATTESTATION_ID_IMEI:
    	attestId = attIdImei;
    	break;
      // Attestation Id MEID
      case KMType.ATTESTATION_ID_MEID:
    	attestId = attIdMeId;
    	break;
      // Attestation Id Manufacturer
      case KMType.ATTESTATION_ID_MANUFACTURER:
    	attestId = attIdManufacturer;
    	break;
      // Attestation Id Model
      case KMType.ATTESTATION_ID_MODEL:
    	attestId = attIdModel;
    	break;
    }
    if(attestId == null) {
      KMException.throwIt(KMError.CANNOT_ATTEST_IDS);
    }
    Util.arrayCopyNonAtomic(attestId, (short) 0, buffer, start, (short) attestId.length);
    return (short) attestId.length;
  }
  
  public void setAttestationId(short tag, byte[] buffer, short start, short length) {
    switch (tag) {
      // Attestation Id Brand
      case KMType.ATTESTATION_ID_BRAND:
    	JCSystem.beginTransaction();   	  
        attIdBrand = new byte[length];
        Util.arrayCopyNonAtomic(buffer, (short) start, attIdBrand, (short) 0, length);
        JCSystem.commitTransaction();       
        break;
      // Attestation Id Device
      case KMType.ATTESTATION_ID_DEVICE:
    	JCSystem.beginTransaction();
    	attIdDevice = new byte[length];
    	Util.arrayCopyNonAtomic(buffer, (short) start, attIdDevice, (short) 0, length);
        JCSystem.commitTransaction();
        break;
      // Attestation Id Product
      case KMType.ATTESTATION_ID_PRODUCT:
    	JCSystem.beginTransaction();
    	attIdProduct = new byte[length];
    	Util.arrayCopyNonAtomic(buffer, (short) start, attIdProduct, (short) 0, length);
    	JCSystem.commitTransaction();
        break;
      // Attestation Id Serial
      case KMType.ATTESTATION_ID_SERIAL:
    	JCSystem.beginTransaction();
    	attIdSerial = new byte[length];
    	Util.arrayCopyNonAtomic(buffer, (short) start, attIdSerial, (short) 0, length);
    	JCSystem.commitTransaction();
        break;
      // Attestation Id IMEI
      case KMType.ATTESTATION_ID_IMEI:
    	JCSystem.beginTransaction();
    	attIdImei = new byte[length];
    	Util.arrayCopyNonAtomic(buffer, (short) start, attIdImei, (short) 0, length);
    	JCSystem.commitTransaction();        
        break;
      // Attestation Id MEID
      case KMType.ATTESTATION_ID_MEID:
    	JCSystem.beginTransaction();
    	attIdMeId = new byte[length];
    	Util.arrayCopyNonAtomic(buffer, (short) start, attIdMeId, (short) 0, length);
    	JCSystem.commitTransaction();
        break;
      // Attestation Id Manufacturer
      case KMType.ATTESTATION_ID_MANUFACTURER:
    	JCSystem.beginTransaction();
    	attIdManufacturer = new byte[length];
        Util.arrayCopyNonAtomic(buffer, (short) start, attIdManufacturer, (short) 0, length);
        JCSystem.commitTransaction();
        break;
      // Attestation Id Model
      case KMType.ATTESTATION_ID_MODEL:
    	JCSystem.beginTransaction();
    	attIdModel = new byte[length];
    	Util.arrayCopyNonAtomic(buffer, (short) start, attIdModel, (short) 0, length);
    	JCSystem.commitTransaction();
        break;
    }
  }
 
  public void deleteAttestationIds() {
    attIdBrand = null;
    attIdDevice = null;
    attIdProduct = null;
    attIdSerial = null;
    attIdImei = null;
    attIdMeId = null;
    attIdManufacturer = null;
    attIdModel = null;
    // Trigger garbage collection.
    JCSystem.requestObjectDeletion();
  }
  
  public short getVerifiedBootHash(byte[] buffer, short start) {
    if (verifiedHash == null) {
      KMException.throwIt(KMError.INVALID_DATA);		
    }
    Util.arrayCopyNonAtomic(verifiedHash, (short) 0, buffer, start, (short) verifiedHash.length);
    return (short) verifiedHash.length;
  }

  public short getBootKey(byte[] buffer, short start) {
    if (bootKey == null) {
      KMException.throwIt(KMError.INVALID_DATA);		
    }
    Util.arrayCopyNonAtomic(bootKey, (short) 0, buffer, start, (short) bootKey.length);
    return (short) bootKey.length;
  }

  public short getBootState() {
    return bootState;
  }

  public boolean isDeviceBootLocked() {
    return deviceBootLocked;
  }

  public short getBootPatchLevel() {
    if (bootPatchLevel == null) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return KMInteger.uint_32(bootPatchLevel, (short) 0);
  }

  public void setVerifiedBootHash(byte[] buffer, short start, short length) {
    if (verifiedHash == null) {
      verifiedHash = new byte[32];
    }
    if (length != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopy(buffer, start, verifiedHash, (short) 0, (short) 32);
  }

  public void setBootKey(byte[] buffer, short start, short length) {
    if (bootKey == null) {
      bootKey = new byte[32];
    }
    if (length != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopy(buffer, start, bootKey, (short) 0, (short) 32);
  }

  public void setBootState(short state) {
    bootState = state;
  }

  public void setDeviceLocked(boolean state) {
    deviceBootLocked = state;
  }

  public void setBootPatchLevel(byte[] buffer, short start, short length) {
    if (bootPatchLevel == null) {
      bootPatchLevel = new byte[4];
    }
    if (length > 4 || length < 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopy(buffer, start, bootPatchLevel, (short) 0, (short) length);
  }

  public void setChallenge(byte[] buf, short start, short length) {
    if (challenge == null) {
      challenge = new byte[16];
    }
    if (length != 16) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    Util.arrayCopy(buf, start, challenge, (short) 0, (short) length);
  }

  public short getChallenge(byte[] buffer, short start) {
    if (challenge == null) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    Util.arrayCopyNonAtomic(challenge, (short) 0, buffer, start,
        (short) challenge.length);
    return (short) challenge.length;
  }

  public boolean isProvisionLocked() {
    if (0 != (provisionStatus & KMKeymasterApplet.PROVISION_STATUS_PROVISIONING_LOCKED)) {
	  return true;
    }
    return false;
  }
  
  public void setProvisionStatus(short pStatus) {
    JCSystem.beginTransaction();
    provisionStatus |= pStatus;
    JCSystem.commitTransaction();
  }
  
  public short getProvisionStatus() {
    return provisionStatus;
  }
  
  public void unlockProvision() {
    JCSystem.beginTransaction();
    provisionStatus &= ~KMKeymasterApplet.PROVISION_STATUS_PROVISIONING_LOCKED;
    JCSystem.commitTransaction();
  }

  public void persistOEMRootPublicKey(byte[] inBuff, short inOffset, short inLength) {
    if (inLength != 65) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if(oemRootPublicKey == null) {
      oemRootPublicKey = new byte[65];
    }
    Util.arrayCopy(inBuff, inOffset, oemRootPublicKey, (short) 0, inLength);
  }

  public byte[] getOEMRootPublicKey() {
    if(oemRootPublicKey == null) {
      KMException.throwIt(KMError.INVALID_DATA);	
    }
    return oemRootPublicKey;
  }

  @Override
  public void onSave(Element element) {
    // Prmitives
    element.write(provisionStatus);
    element.write(secureBootMode);
    // Objects
    element.write(attIdBrand);
    element.write(attIdDevice);
    element.write(attIdProduct);
    element.write(attIdSerial);
    element.write(attIdImei);
    element.write(attIdMeId);
    element.write(attIdManufacturer);
    element.write(attIdModel);
    element.write(additionalCertChain);
    element.write(bcc);
    element.write(oemRootPublicKey);
    
    // Key Objects
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY, masterKey);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY, preSharedKey);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR, deviceUniqueKeyPair);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY, rkpMacKey);
  }

  @Override
  public void onRestore(Element element, short oldVersion, short currentVersion) {
    if (oldVersion <= KM_APPLET_PACKAGE_VERSION_1) {
      // 1.0 to 3.0 Upgrade happens here.
      handlePreviousVersionUpgrade(element);
      return;
    } else if (oldVersion == KM_APPLET_PACKAGE_VERSION_2) {
      handleUpgrade(element, oldVersion);
      JCSystem.beginTransaction();
      // While upgrading Secure Boot Mode flag from 2.0 to 3.0, implementations
      // have to update the secureBootMode with the correct input.
      secureBootMode = 0;
      provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_SECURE_BOOT_MODE;
      // Applet package Versions till 2 had CoseSign1 for additionalCertificateChain.
      // From package version 3, the additionalCertificateChain is in X.509 format. 
      // So Unreference the old address and allocate new persistent memory.
      additionalCertChain = new byte[ADDITIONAL_CERT_CHAIN_MAX_SIZE];
      JCSystem.commitTransaction();
      // Request for ObjectDeletion for unreferenced address of additionalCertChain.
      JCSystem.requestObjectDeletion();
      return;
    }
    handleUpgrade(element, oldVersion);
  }

  private void handlePreviousVersionUpgrade(Element element) {
    // Read Primitives
    //restore old data table index
    short oldDataIndex = element.readShort(); 
    element.readBoolean(); // pop deviceBootLocked
    element.readShort(); // pop bootState 
	
    // Read Objects
    //restore old data table
    byte[] oldDataTable = (byte[]) element.readObject();

    attIdBrand = (byte[]) element.readObject();
    attIdDevice = (byte[]) element.readObject();
    attIdProduct = (byte[]) element.readObject();
    attIdSerial = (byte[]) element.readObject();
    attIdImei = (byte[]) element.readObject();
    attIdMeId = (byte[]) element.readObject();
    attIdManufacturer = (byte[]) element.readObject();
    attIdModel = (byte[]) element.readObject();
    element.readObject(); // pop verifiedHash
    element.readObject(); //pop bootKey
    element.readObject(); // pop bootPatchLevel
    additionalCertChain = (byte[]) element.readObject();
    bcc = (byte[]) element.readObject();

    // Read Key Objects
    masterKey = (KMMasterKey) seProvider.onRestore(element);
    seProvider.onRestore(element); // pop computedHmacKey
    preSharedKey = (KMPreSharedKey) seProvider.onRestore(element);
    deviceUniqueKeyPair = (KMDeviceUniqueKeyPair) seProvider.onRestore(element);
    rkpMacKey = (KMRkpMacKey) seProvider.onRestore(element);
    handleProvisionStatusUpgrade(oldDataTable, oldDataIndex);
  }
  
  private void handleUpgrade(Element element, short oldVersion) {
    // Read Primitives
    provisionStatus =  element.readShort();
    if (oldVersion >= KM_APPLET_PACKAGE_VERSION_3) {
      secureBootMode = element.readByte();
    }
    // Read Objects
    attIdBrand = (byte[]) element.readObject();
    attIdDevice = (byte[]) element.readObject();
    attIdProduct = (byte[]) element.readObject();
    attIdSerial = (byte[]) element.readObject();
    attIdImei = (byte[]) element.readObject();
    attIdMeId = (byte[]) element.readObject();
    attIdManufacturer = (byte[]) element.readObject();
    attIdModel = (byte[]) element.readObject();
    additionalCertChain = (byte[]) element.readObject();
    bcc = (byte[]) element.readObject();
    oemRootPublicKey = (byte[]) element.readObject();
    // Read Key Objects
    masterKey = (KMMasterKey) seProvider.onRestore(element);
    preSharedKey = (KMPreSharedKey) seProvider.onRestore(element);
    deviceUniqueKeyPair = (KMDeviceUniqueKeyPair) seProvider.onRestore(element);
    rkpMacKey = (KMRkpMacKey) seProvider.onRestore(element);
  }

  public void getProvisionStatus(byte[] dataTable, byte[] scratchpad, short offset) {
    Util.setShort(scratchpad, offset, (short)0);
    readDataEntry(dataTable, OLD_PROVISIONED_STATUS_OFFSET, scratchpad, offset);
  }

  void handleProvisionStatusUpgrade(byte[] dataTable, short dataTableIndex){
    short dInex = repository.allocReclaimableMemory((short)2);
    byte data[] = repository.getHeap();
    getProvisionStatus(dataTable, data, dInex);
    short pStatus = (short)( data[dInex] & 0x00ff);
    if( KMKeymasterApplet.PROVISION_STATUS_PROVISIONING_LOCKED 
          == (pStatus & KMKeymasterApplet.PROVISION_STATUS_PROVISIONING_LOCKED)) {
      pStatus |= KMKeymasterApplet.PROVISION_STATUS_SE_LOCKED
          | KMKeymasterApplet.PROVISION_STATUS_SECURE_BOOT_MODE;
    }
    JCSystem.beginTransaction();
    // While upgrading Secure Boot Mode flag from 1.0 to 3.0, implementations
    // have to update the secureBootMode with the correct input.
    secureBootMode = 0;
    provisionStatus = pStatus;
    // Applet package Versions till 2 had CoseSign1 for additionalCertificateChain.
    // From package version 3, the additionalCertificateChain is in X.509 format. 
    // So Unreference the old address and allocate new persistent memory.
    additionalCertChain = new byte[ADDITIONAL_CERT_CHAIN_MAX_SIZE];
    JCSystem.commitTransaction();
    repository.reclaimMemory((short)2);
    // Request object deletion for unreferenced address for additionalCertChain
    JCSystem.requestObjectDeletion();
  }
  
  @Override
  public short getBackupPrimitiveByteCount() {
    // provisionStatus - 2 bytes
    // secureBootMode - 1 byte
    return (short) (3 +
        seProvider.getBackupPrimitiveByteCount(KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY) +
        seProvider.getBackupPrimitiveByteCount(KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY) +
        seProvider.getBackupPrimitiveByteCount( KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR) + 
            		seProvider.getBackupPrimitiveByteCount(KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY));
  }

  @Override
  public short getBackupObjectCount() {
    // AttestationIds - 8 
    // AdditionalCertificateChain - 1
    // BCC - 1
    // oemRootPublicKey - 1
    return (short) (11 +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY) +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY) +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR) +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY));
  }
  
}
