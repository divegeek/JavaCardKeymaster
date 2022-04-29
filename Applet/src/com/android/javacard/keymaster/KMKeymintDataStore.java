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
  public static final short DATA_INDEX_SIZE = 19;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;

  //TODO reduced data table size from 2048 to 300.
  public static final short DATA_MEM_SIZE = 300;

  // Data table offsets
  public static final byte COMPUTED_HMAC_KEY = 0;
  public static final byte HMAC_NONCE = 1;
  public static final byte BOOT_OS_VERSION = 2;
  public static final byte BOOT_OS_PATCH_LEVEL = 3;
  public static final byte VENDOR_PATCH_LEVEL = 4;
  public static final byte DEVICE_LOCKED_TIME = 5;
  public static final byte DEVICE_LOCKED = 6;
  public static final byte DEVICE_LOCKED_PASSWORD_ONLY = 7;
  // Total 8 auth tags, so the next offset is AUTH_TAG_1 + 8
  public static final byte AUTH_TAG_1 = 8;
  public static final byte BOOT_ENDED_FLAG = 15;
  public static final byte EARLY_BOOT_ENDED_FLAG = 16;
  private static final byte PROVISIONED_LOCKED = 17;
  private static final byte PROVISIONED_STATUS = 18;
  
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
  
  private static final short ADDITIONAL_CERT_CHAIN_MAX_SIZE = 512;//First 2 bytes for length.
  private static final short BCC_MAX_SIZE = 512;

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
  
  private byte[] dataTable;
  private short dataIndex;
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
  
  public KMKeymintDataStore(KMSEProvider provider, KMRepository repo) {
    seProvider = provider;
    repository = repo;
    boolean isUpgrading = provider.isUpgrading();
    initDataTable(isUpgrading);
    //Initialize the device locked status
    if (!isUpgrading) {
      additionalCertChain = new byte[ADDITIONAL_CERT_CHAIN_MAX_SIZE];
      bcc = new byte[BCC_MAX_SIZE];
      setDeviceLock(false);
      setDeviceLockPasswordOnly(false);
    }
//    initializeCertificateDataBuffer(isUpgrading, factoryAttestSupport);
  }
  
  private void initDataTable(boolean isUpgrading) {
    if (!isUpgrading) {
      if (dataTable == null) {
        dataTable = new byte[DATA_MEM_SIZE];
        dataIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
      }
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
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getVendorPatchLevel() {
    short blob = readData(VENDOR_PATCH_LEVEL);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getOsPatch() {
    short blob = readData(BOOT_OS_PATCH_LEVEL);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_32(
          KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
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

  public boolean getBootEndedStatus() {
    return readBoolean(BOOT_ENDED_FLAG);
  }

  public short getDeviceTimeStamp() {
    short blob = readData(DEVICE_LOCKED_TIME);
    if (blob != KMType.INVALID_VALUE) {
      return KMInteger.uint_64(KMByteBlob.cast(blob).getBuffer(),
          KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_64(zero, (short) 0);
    }
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
 
  public void setBootEndedStatus(boolean flag) {
    writeBoolean(BOOT_ENDED_FLAG, flag);
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
	return rkpMacKey;
  }
	
  public short getAttestationId(short tag, byte[] buffer, short start) {
    switch (tag) {
      // Attestation Id Brand
      case KMType.ATTESTATION_ID_BRAND:
        Util.arrayCopyNonAtomic(attIdBrand, (short) 0, buffer, start, (short) attIdBrand.length);
        return (short) attIdBrand.length;
      // Attestation Id Device
      case KMType.ATTESTATION_ID_DEVICE:
        Util.arrayCopyNonAtomic(attIdDevice, (short) 0, buffer, start, (short) attIdDevice.length);
        return (short) attIdDevice.length;
      // Attestation Id Product
      case KMType.ATTESTATION_ID_PRODUCT:
        Util.arrayCopyNonAtomic(attIdProduct, (short) 0, buffer, start,
            (short) attIdProduct.length);
        return (short) attIdProduct.length;
      // Attestation Id Serial
      case KMType.ATTESTATION_ID_SERIAL:
        Util.arrayCopyNonAtomic(attIdSerial, (short) 0, buffer, start, (short) attIdSerial.length);
        return (short) attIdSerial.length;
      // Attestation Id IMEI
      case KMType.ATTESTATION_ID_IMEI:
        Util.arrayCopyNonAtomic(attIdImei, (short) 0, buffer, start, (short) attIdImei.length);
        return (short) attIdImei.length;
      // Attestation Id MEID
      case KMType.ATTESTATION_ID_MEID:
        Util.arrayCopyNonAtomic(attIdMeId, (short) 0, buffer, start, (short) attIdMeId.length);
        return (short) attIdMeId.length;
      // Attestation Id Manufacturer
      case KMType.ATTESTATION_ID_MANUFACTURER:
        Util.arrayCopyNonAtomic(attIdManufacturer, (short) 0, buffer, start,
            (short) attIdManufacturer.length);
        return (short) attIdManufacturer.length;
      // Attestation Id Model
      case KMType.ATTESTATION_ID_MODEL:
        Util.arrayCopyNonAtomic(attIdModel, (short) 0, buffer, start, (short) attIdModel.length);
        return (short) attIdModel.length;
    }
    return (short) 0;
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
  }
  
  public short getVerifiedBootHash(byte[] buffer, short start) {
    Util.arrayCopyNonAtomic(verifiedHash, (short) 0, buffer, start, (short) verifiedHash.length);
    return (short) verifiedHash.length;
  }

  public short getBootKey(byte[] buffer, short start) {
    Util.arrayCopyNonAtomic(bootKey, (short) 0, buffer, start, (short) bootKey.length);
    return (short) bootKey.length;
  }

  public short getBootState() {
    return bootState;
  }

  public boolean isDeviceBootLocked() {
    return deviceBootLocked;
  }

  public short getBootPatchLevel(byte[] buffer, short start) {
    Util.arrayCopyNonAtomic(bootPatchLevel, (short) 0, buffer, start,
        (short) bootPatchLevel.length);
    return (short) bootPatchLevel.length;
  }

  public void setVerifiedBootHash(byte[] buffer, short start, short length) {
    if (verifiedHash == null) {
      verifiedHash = new byte[32];
    }
    if (length != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopyNonAtomic(buffer, start, verifiedHash, (short) 0, (short) 32);
  }

  public void setBootKey(byte[] buffer, short start, short length) {
    if (bootKey == null) {
      bootKey = new byte[32];
    }
    if (length != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopyNonAtomic(buffer, start, bootKey, (short) 0, (short) 32);
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
    Util.arrayCopyNonAtomic(buffer, start, bootPatchLevel, (short) 0, (short) length);
  }
  
  public void setProvisionLocked() {
    writeBoolean(PROVISIONED_LOCKED, true);
  }

  public boolean isProvisionLocked() {
    try {
    return readBoolean(PROVISIONED_LOCKED);
    } catch (KMException e) {
      if (KMException.reason() != KMError.INVALID_DATA)
        KMException.throwIt(KMException.reason());
    }
    return false;
  }
  
  public void setProvisionStatus(byte provisionStatus) {
    short offset = repository.alloc((short) 1);
    byte[] buf = repository.getHeap();
    getProvisionStatus(buf, offset);
    buf[offset] |= provisionStatus;
    writeDataEntry(PROVISIONED_STATUS, buf, offset, (short) 1);
  }
  
  public void getProvisionStatus(byte[] scratchpad, short offset) {
    scratchpad[offset] = 0;
    readDataEntry(PROVISIONED_STATUS, scratchpad, offset);
  }

  @Override
  public void onSave(Element element) {
    // Prmitives
    element.write(dataIndex);
    element.write(deviceBootLocked);
    element.write(bootState);
    // Objects
    element.write(dataTable);
    element.write(attIdBrand);
    element.write(attIdDevice);
    element.write(attIdProduct);
    element.write(attIdSerial);
    element.write(attIdImei);
    element.write(attIdMeId);
    element.write(attIdManufacturer);
    element.write(attIdModel);
    element.write(verifiedHash);
    element.write(bootKey);
    element.write(bootPatchLevel);
    element.write(additionalCertChain);
    element.write(bcc);
    // Key Objects
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY, masterKey);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_COMPUTED_HMAC_KEY,
        computedHmacKey);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY, preSharedKey);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR, deviceUniqueKeyPair);
    seProvider.onSave(element, KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY, rkpMacKey);
  }

  @Override
  public void onRestore(Element element) {
  // Read Primitives
    dataIndex = element.readShort();
    deviceBootLocked = element.readBoolean();
    bootState = element.readShort();
    // Read Objects
    dataTable = (byte[]) element.readObject();
    attIdBrand = (byte[]) element.readObject();
    attIdDevice = (byte[]) element.readObject();
    attIdProduct = (byte[]) element.readObject();
    attIdSerial = (byte[]) element.readObject();
    attIdImei = (byte[]) element.readObject();
    attIdMeId = (byte[]) element.readObject();
    attIdManufacturer = (byte[]) element.readObject();
    attIdModel = (byte[]) element.readObject();
    verifiedHash = (byte[]) element.readObject();
    bootKey = (byte[]) element.readObject();
    bootPatchLevel = (byte[]) element.readObject();
    additionalCertChain = (byte[]) element.readObject();
    bcc = (byte[]) element.readObject();
    // Read Key Objects
    masterKey = (KMMasterKey) seProvider.onResore(element);
    computedHmacKey = (KMComputedHmacKey) seProvider.onResore(element);
    preSharedKey = (KMPreSharedKey) seProvider.onResore(element);
    deviceUniqueKeyPair = (KMDeviceUniqueKeyPair) seProvider.onResore(element);
    rkpMacKey = (KMRkpMacKey) seProvider.onResore(element);
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    // dataIndex - 2 bytes
    // deviceLocked - 1 byte
    // deviceState = 2 bytes
    return (short) (5 +
        seProvider.getBackupPrimitiveByteCount(KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY) +
        seProvider.getBackupPrimitiveByteCount(
            KMDataStoreConstants.INTERFACE_TYPE_COMPUTED_HMAC_KEY) +
        seProvider.getBackupPrimitiveByteCount(KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY) +
        seProvider.getBackupPrimitiveByteCount( KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR) + 
            		seProvider.getBackupPrimitiveByteCount(KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY));
  }

  @Override
  public short getBackupObjectCount() {
	// dataTable - 1
    // AttestationIds - 8 
    // bootParameters - 3
	// AdditionalCertificateChain - 1
	// BCC - 1
    return (short) (14 +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_COMPUTED_HMAC_KEY) +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY) +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY) +
        seProvider.getBackupObjectCount(KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR) +
            		seProvider.getBackupObjectCount(
            		        KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY));
  }
  
}
