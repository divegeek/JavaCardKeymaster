package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMCose;
import com.android.javacard.keymaster.KMCoseHeaders;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMHmacSharingParameters;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMKeymintDataStore;
import com.android.javacard.keymaster.KMMap;
import com.android.javacard.keymaster.KMNInteger;
import com.android.javacard.keymaster.KMSemanticTag;
import com.android.javacard.keymaster.KMSimpleValue;
import com.android.javacard.keymaster.KMTextString;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.seprovider.KMECDeviceUniqueKey;
import com.android.javacard.seprovider.KMSEProvider;
import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javax.smartcardio.Card;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;

public class KMProvision {

  // Provision Instructions
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 1;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 2;
  private static final byte INS_OEM_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 4;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 5;
  private static final byte INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 6;
  private static final byte INS_PROVISION_RKP_ADDITIONAL_CERT_CHAIN_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 7;
  private static final byte INS_SET_BOOT_ENDED_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 8; //unused
  private static final byte INS_SE_FACTORY_PROVISIONING_LOCK_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 9;
  private static final byte INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 10;
  private static final byte INS_OEM_UNLOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 11;
  // Top 32 commands are reserved for provisioning.
  private static final byte INS_END_KM_PROVISION_CMD = 0x20;

  private static final byte KEYMINT_CMD_APDU_START = 0x20;
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = KEYMINT_CMD_APDU_START + 10; //0x2A
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = KEYMINT_CMD_APDU_START + 13; //0x2D
  private static final byte INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21; //0x35
  private static final byte INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26; //0x3A
  // The instructions from 0x43 to 0x4C will be reserved for KeyMint 1.0 for any future use.
  // KeyMint 2.0 Instructions
  private static final byte INS_GET_ROT_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 45; // 0x4D
  private static final byte INS_GET_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 46; // 0x4E
  private static final byte INS_SEND_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 47; // 0x4F

  private static final byte[] kEcPrivKey = {
      (byte) 0x21, (byte) 0xe0, (byte) 0x86, (byte) 0x43, (byte) 0x2a,
      (byte) 0x15, (byte) 0x19, (byte) 0x84, (byte) 0x59, (byte) 0xcf,
      (byte) 0x36, (byte) 0x3a, (byte) 0x50, (byte) 0xfc, (byte) 0x14,
      (byte) 0xc9, (byte) 0xda, (byte) 0xad, (byte) 0xf9, (byte) 0x35,
      (byte) 0xf5, (byte) 0x27, (byte) 0xc2, (byte) 0xdf, (byte) 0xd7,
      (byte) 0x1e, (byte) 0x4d, (byte) 0x6d, (byte) 0xbc, (byte) 0x42,
      (byte) 0xe5, (byte) 0x44};
  private static final byte[] kEcPubKey = {
      (byte) 0x04, (byte) 0xeb, (byte) 0x9e, (byte) 0x79, (byte) 0xf8,
      (byte) 0x42, (byte) 0x63, (byte) 0x59, (byte) 0xac, (byte) 0xcb,
      (byte) 0x2a, (byte) 0x91, (byte) 0x4c, (byte) 0x89, (byte) 0x86,
      (byte) 0xcc, (byte) 0x70, (byte) 0xad, (byte) 0x90, (byte) 0x66,
      (byte) 0x93, (byte) 0x82, (byte) 0xa9, (byte) 0x73, (byte) 0x26,
      (byte) 0x13, (byte) 0xfe, (byte) 0xac, (byte) 0xcb, (byte) 0xf8,
      (byte) 0x21, (byte) 0x27, (byte) 0x4c, (byte) 0x21, (byte) 0x74,
      (byte) 0x97, (byte) 0x4a, (byte) 0x2a, (byte) 0xfe, (byte) 0xa5,
      (byte) 0xb9, (byte) 0x4d, (byte) 0x7f, (byte) 0x66, (byte) 0xd4,
      (byte) 0xe0, (byte) 0x65, (byte) 0x10, (byte) 0x66, (byte) 0x35,
      (byte) 0xbc, (byte) 0x53, (byte) 0xb7, (byte) 0xa0, (byte) 0xa3,
      (byte) 0xa6, (byte) 0x71, (byte) 0x58, (byte) 0x3e, (byte) 0xdb,
      (byte) 0x3e, (byte) 0x11, (byte) 0xae, (byte) 0x10, (byte) 0x14};

  // OEM lock / unlock verification constants.
  private static final byte[] OEM_LOCK_PROVISION_VERIFICATION_LABEL = { // "OEM Provisioning Lock"
      0x4f, 0x45, 0x4d, 0x20, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e,
      0x67, 0x20, 0x4c, 0x6f, 0x63, 0x6b
  };
  private static final byte[] OEM_UNLOCK_PROVISION_VERIFICATION_LABEL = { // "Enable RMA"
      0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x52, 0x4d, 0x41
  };

  public static final int OS_VERSION = 1;
  public static final int OS_PATCH_LEVEL = 1;
  public static final int VENDOR_PATCH_LEVEL = 1;
  public static final int BOOT_PATCH_LEVEL = 1;
  // RKP Device Unique Public and Private Keys.
  public static byte[] RKP_DK_PUB = new byte[65];
  public static byte[] RKP_DK_PRIV = new byte[32];

  //----------------------------------------------------------------------------------------------
  //  Provision functions
  //----------------------------------------------------------------------------------------------
  public static ResponseAPDU setAndroidOSSystemProperties(CardSimulator simulator,
      KMEncoder encoder,
      KMDecoder decoder, short osVersion,
      short osPatchLevel, short vendorPatchLevel) {
    // Argument 1 OS Version
    short versionPtr = KMInteger.uint_16(osVersion);
    // short versionTagPtr = KMIntegerTag.instance(KMType.UINT_TAG,
    // KMType.OS_VERSION,versionPatchPtr);
    // Argument 2 OS Patch level
    short patchPtr = KMInteger.uint_16(osPatchLevel);
    short vendorpatchPtr = KMInteger.uint_16((short) vendorPatchLevel);
    // Arguments
    short arrPtr = KMArray.instance((short) 3);
    KMArray vals = KMArray.cast(arrPtr);
    vals.add((short) 0, versionPtr);
    vals.add((short) 1, patchPtr);
    vals.add((short) 2, vendorpatchPtr);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_INIT_STRONGBOX_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU setBootParams(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder,
      short bootPatchLevel) {
    // Argument 0 boot patch level
    short bootpatchPtr = KMInteger.uint_16((short) bootPatchLevel);
    // Argument 1 Verified Boot Key
    byte[] bootKeyHash = "00011122233344455566677788899900".getBytes();
    short bootKeyPtr = KMByteBlob.instance(bootKeyHash, (short) 0,
        (short) bootKeyHash.length);
    // Argument 2 Verified Boot Hash
    short bootHashPtr = KMByteBlob.instance(bootKeyHash, (short) 0,
        (short) bootKeyHash.length);
    // Argument 3 Verified Boot State
    short bootStatePtr = KMEnum.instance(KMType.VERIFIED_BOOT_STATE,
        KMType.VERIFIED_BOOT);
    // Argument 4 Device Locked
    short deviceLockedPtr = KMEnum.instance(KMType.DEVICE_LOCKED,
        KMType.DEVICE_LOCKED_FALSE);
    // Arguments
    short arrPtr = KMArray.instance((short) 5);
    KMArray vals = KMArray.cast(arrPtr);
    vals.add((short) 0, bootpatchPtr);
    vals.add((short) 1, bootKeyPtr);
    vals.add((short) 2, bootHashPtr);
    vals.add((short) 3, bootStatePtr);
    vals.add((short) 4, deviceLockedPtr);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_SET_BOOT_PARAMS_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionAdditionalCertChain(CardSimulator simulator,
      KMSEProvider cryptoProvider, KMEncoder encoder, KMDecoder decoder) {
    short[] lengths = new short[2];
    byte[] rootPriv = new byte[128];
    byte[] rootPub = new byte[128];
    byte[] scratchpad = new byte[500];
    short[] coseScratchpad = new short[20];
    cryptoProvider.createAsymmetricKey(KMType.EC, rootPriv, (short) 0, (short) 128,
        rootPub, (short) 0, (short) 128, lengths);
    short coseKey =
        KMTestUtils.constructCoseKey(
            KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
            KMType.INVALID_VALUE,
            KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
            KMInteger.uint_8(KMCose.COSE_KEY_OP_SIGN),
            KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
            rootPub, (short) 0, lengths[1],
            rootPriv, (short) 0, lengths[0],
            false
        );
    short payload = encoder.encode(coseKey, scratchpad, (short) 0, (short) 500);
    payload = KMByteBlob.instance(scratchpad, (short) 0, payload);
    // Protected Header
    short protectedHeaderPtr = KMCose.constructHeaders(coseScratchpad,
        KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    protectedHeaderPtr = encoder.encode(protectedHeaderPtr, scratchpad, (short) 0, (short) 500);
    protectedHeaderPtr = KMByteBlob.instance(scratchpad, (short) 0, protectedHeaderPtr);

    // Unprotected Headers.
    short emptyArr = KMArray.instance((short) 0);
    short unprotectedHeader = KMCoseHeaders.instance(emptyArr);

    short aad = KMByteBlob.instance((short) 0);
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    KMECDeviceUniqueKey ecUniqueKey = new KMECDeviceUniqueKey(ecKeyPair);
    ecUniqueKey.setS(rootPriv, (short) 0, lengths[0]);
    ecUniqueKey.setW(rootPub, (short) 0, lengths[1]);
    short root = KMTestUtils.constructCoseSign1(cryptoProvider, encoder,
        protectedHeaderPtr, unprotectedHeader, payload, aad,
        ecUniqueKey);
    coseKey =
        KMTestUtils.constructCoseKey(
            KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
            KMType.INVALID_VALUE,
            KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
            KMInteger.uint_8(KMCose.COSE_KEY_OP_SIGN),
            KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
            RKP_DK_PUB, (short) 0, (short) RKP_DK_PUB.length,
            RKP_DK_PRIV, (short) 0, (short) RKP_DK_PRIV.length,
            false
        );
    payload = encoder.encode(coseKey, scratchpad, (short) 0, (short) 500);
    payload = KMByteBlob.instance(scratchpad, (short) 0, payload);
    short leaf = KMTestUtils.constructCoseSign1(cryptoProvider, encoder, protectedHeaderPtr,
        unprotectedHeader, payload, aad,
        ecUniqueKey);
    short additionalCertChain = KMArray.instance((short) 2);
    KMArray.cast(additionalCertChain).add((short) 0, root);
    KMArray.cast(additionalCertChain).add((short) 1, leaf);
    short map = KMMap.instance((short) 1);
    byte[] signerName = "TestSigner".getBytes();
    KMMap.cast(map)
        .add((short) 0, KMTextString.instance(signerName, (short) 0, (short) signerName.length),
            additionalCertChain);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder,
        (byte) INS_PROVISION_RKP_ADDITIONAL_CERT_CHAIN_CMD, map);
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionDeviceUniqueKeyPair(CardSimulator simulator,
      KMSEProvider cryptoProvider, KMEncoder encoder,
      KMDecoder decoder) {
    short[] lengths = new short[2];
    byte[] privKey = new byte[128];
    byte[] pubKey = new byte[128];
    cryptoProvider.createAsymmetricKey(KMType.EC, privKey, (short) 0, (short) 128,
        pubKey, (short) 0, (short) 128, lengths);
    short coseKey =
        KMTestUtils.constructCoseKey(
            KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
            KMType.INVALID_VALUE,
            KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
            KMInteger.uint_8(KMCose.COSE_KEY_OP_SIGN),
            KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
            pubKey, (short) 0, lengths[1],
            privKey, (short) 0, lengths[0],
            false
        );
    Assert.assertEquals(lengths[1], 65);
    Assert.assertTrue("Private key length should not be > 32", (lengths[0] <= 32));
    Util.arrayCopyNonAtomic(privKey, (short) 0, RKP_DK_PRIV, (short) (32 - lengths[0]), lengths[0]);
    Util.arrayCopyNonAtomic(pubKey, (short) 0, RKP_DK_PUB, (short) 0, lengths[1]);
    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, coseKey);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder,
        (byte) INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD, arr);
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionOEMRootPublicKey(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    // KeyParameters.
    short arrPtr = KMArray.instance((short) 4);
    short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short byteBlob2 = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob2).add((short) 0, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob2);
    KMArray.cast(arrPtr).add((short) 0, ecCurve);
    KMArray.cast(arrPtr).add((short) 1, digest);
    KMArray.cast(arrPtr).add((short) 2,
        KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    KMArray.cast(arrPtr).add((short) 3, purpose);
    short keyParams = KMKeyParameters.instance(arrPtr);
    // Note: VTS uses PKCS8 KeyFormat RAW
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);

    // Key
    short signKeyPtr = KMByteBlob.instance(kEcPubKey, (short) 0, (short) kEcPubKey.length);

    short finalArrayPtr = KMArray.instance((short) 3);
    KMArray.cast(finalArrayPtr).add((short) 0, keyParams);
    KMArray.cast(finalArrayPtr).add((short) 1, keyFormatPtr);
    KMArray.cast(finalArrayPtr).add((short) 2, signKeyPtr);

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD,
        finalArrayPtr);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionSharedSecret(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    byte[] sharedKeySecret = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0};
    short arrPtr = KMArray.instance((short) 1);
    short byteBlob = KMByteBlob.instance(sharedKeySecret, (short) 0,
        (short) sharedKeySecret.length);
    KMArray.cast(arrPtr).add((short) 0, byteBlob);

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_PROVISION_PRESHARED_SECRET_CMD,
        arrPtr);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionAttestIds(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    short arrPtr = KMArray.instance((short) 8);

    byte[] buf = "Attestation Id".getBytes();

    KMArray.cast(arrPtr).add((short) 0,
        KMByteTag.instance(KMType.ATTESTATION_ID_BRAND,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 1,
        KMByteTag.instance(KMType.ATTESTATION_ID_PRODUCT,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 2,
        KMByteTag.instance(KMType.ATTESTATION_ID_DEVICE,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 3,
        KMByteTag.instance(KMType.ATTESTATION_ID_MODEL,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 4,
        KMByteTag.instance(KMType.ATTESTATION_ID_IMEI,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 5,
        KMByteTag.instance(KMType.ATTESTATION_ID_MEID,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 6,
        KMByteTag.instance(KMType.ATTESTATION_ID_MANUFACTURER,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 7,
        KMByteTag.instance(KMType.ATTESTATION_ID_SERIAL,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short outerArrPtr = KMArray.instance((short) 1);
    KMArray.cast(outerArrPtr).add((short) 0, keyParams);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_PROVISION_ATTEST_IDS_CMD,
        outerArrPtr);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionLocked(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    // Sign the Lock message
    byte[] signature = new byte[120];
    ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setS(kEcPrivKey, (short) 0, (short) kEcPrivKey.length);
    Signature ecSigner = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    ecSigner.init(key, Signature.MODE_SIGN);
    short len =
        ecSigner.sign(
            OEM_LOCK_PROVISION_VERIFICATION_LABEL,
            (short) 0,
            (short) OEM_LOCK_PROVISION_VERIFICATION_LABEL.length,
            signature,
            (short) 0);

    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMByteBlob.instance(signature, (short) 0, len));

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_OEM_LOCK_PROVISIONING_CMD,
        arr);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionOemUnLock(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    // Sign the Lock message
    byte[] signature = new byte[120];
    ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setS(kEcPrivKey, (short) 0, (short) kEcPrivKey.length);
    Signature ecSigner = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    ecSigner.init(key, Signature.MODE_SIGN);
    short len =
        ecSigner.sign(
            OEM_UNLOCK_PROVISION_VERIFICATION_LABEL,
            (short) 0,
            (short) OEM_UNLOCK_PROVISION_VERIFICATION_LABEL.length,
            signature,
            (short) 0);

    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMByteBlob.instance(signature, (short) 0, len));

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_OEM_UNLOCK_PROVISIONING_CMD,
        arr);
    return simulator.transmitCommand(apdu);
  }

  public static ResponseAPDU provisionSeLocked(CardSimulator simulator, KMDecoder decoder) {
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_SE_FACTORY_PROVISIONING_LOCK_CMD,
        0x50, 0x00);
    // print(commandAPDU.getBytes());
    return simulator.transmitCommand(commandAPDU);
  }

  public static void computeSharedSecret(CardSimulator simulator, KMSEProvider cryptoProvider,
      KMEncoder encoder, KMDecoder decoder) {
    short ret = getHmacSharingParams(simulator, decoder);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    KMHmacSharingParameters params = KMHmacSharingParameters.cast(KMArray.cast(ret).get((short) 1));
    short seed = params.getSeed();
    short nonce = params.getNonce();

    short params1 = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(params1).setSeed(KMByteBlob.instance((short) 0));
    short num = KMByteBlob.instance((short) 32);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(nonce).getBuffer(),
        KMByteBlob.cast(nonce).getStartOff(),
        KMByteBlob.cast(num).getBuffer(),
        KMByteBlob.cast(num).getStartOff(),
        KMByteBlob.cast(num).length());

    KMHmacSharingParameters.cast(params1).setNonce(num);
    short params2 = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(params2).setSeed(KMByteBlob.instance((short) 0));
    num = KMByteBlob.instance((short) 32);
    cryptoProvider.newRandomNumber(
        KMByteBlob.cast(num).getBuffer(),
        KMByteBlob.cast(num).getStartOff(),
        KMByteBlob.cast(num).length());
    KMHmacSharingParameters.cast(params2).setNonce(num);
    short arr = KMArray.instance((short) 2);
    KMArray.cast(arr).add((short) 0, params1);
    KMArray.cast(arr).add((short) 1, params2);
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, arr);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_COMPUTE_SHARED_HMAC_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] resp = response.getBytes();
    arr = KMArray.instance((short) 2);
    KMArray.cast(arr).add((short) 0, KMInteger.exp());
    KMArray.cast(arr).add((short) 1, KMByteBlob.exp());
    short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
  }

  public static void provisionCmd(CardSimulator simulator,
      KMSEProvider cryptoProvider, KMEncoder encoder,
      KMDecoder decoder) {
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionAdditionalCertChain(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionSeLocked(simulator, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionAttestIds(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionOEMRootPublicKey(simulator, encoder, decoder)));
    //setBootParams(simulator, encoder, decoder, (short) BOOT_PATCH_LEVEL);
    // set android system properties
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        setAndroidOSSystemProperties(simulator, encoder, decoder, (short) OS_VERSION,
            (short) OS_PATCH_LEVEL,
            (short) VENDOR_PATCH_LEVEL)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionLocked(simulator, encoder, decoder)));
    // negotiate shared secret.
    computeSharedSecret(simulator, cryptoProvider, encoder, decoder);
    byte[] challenge = getRootOfTrustChallenge(simulator, encoder, decoder);
    sendRootOfTrust(simulator, cryptoProvider, encoder, decoder, challenge);
    sendEarlyBootEnded(simulator, decoder);
  }

  public static void sendEarlyBootEnded(CardSimulator simulator, KMDecoder decoder) {
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_EARLY_BOOT_ENDED_CMD, 0x50, 0x00);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] resp = response.getBytes();
    short arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMInteger.exp());
    short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
  }

  public static short getHmacSharingParams(CardSimulator simulator, KMDecoder decoder) {
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_GET_HMAC_SHARING_PARAM_CMD, 0x50, 0x00);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    KMDecoder dec = new KMDecoder();
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMHmacSharingParameters.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  public static void sendRootOfTrust(CardSimulator simulator, KMSEProvider cryptoProvider,
      KMEncoder encoder,
      KMDecoder decoder, byte[] challenge) {
    short[] scratchBuffer = new short[20];
    byte[] scratchPad = new byte[500];
    // Payload
    short payload = constructRotPayload(encoder);
    // Protected Header
    short headerPtr = KMCose.constructHeaders(scratchBuffer,
        KMInteger.uint_8(KMCose.COSE_ALG_HMAC_256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE);
    // Encode the protected header as byte blob.
    short len = encoder.encode(headerPtr, scratchPad, (short) 0, (short) 500);
    short protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, len);
    // Unprotected Header
    short unprotectedHeader = KMArray.instance((short) 0);
    unprotectedHeader = KMCoseHeaders.instance(unprotectedHeader);

    // Construct Mac_Structure
    short macStructure =
        KMCose.constructCoseMacStructure(protectedHeader,
            KMByteBlob.instance(challenge, (short) 0, (short) challenge.length),
            payload);
    len = encoder.encode(macStructure, scratchPad, (short) 0, (short) 500);
    short signLen = cryptoProvider.hmacSign(KMKeymintDataStore.instance().getComputedHmacKey(),
        scratchPad, (short) 0, len, scratchPad, len);
    short tag = KMByteBlob.instance(scratchPad, len, signLen);

    // Construct Cose_Mac0
    short arr = KMArray.instance((short) 4);
    KMArray.cast(arr).add((short) 0, protectedHeader);
    KMArray.cast(arr).add((short) 1, unprotectedHeader);
    KMArray.cast(arr).add((short) 2, payload);
    KMArray.cast(arr).add((short) 3, tag);

    short sTag = KMSemanticTag.instance(KMInteger.uint_16(KMSemanticTag.COSE_MAC_SEMANTIC_TAG),
        arr);
    arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, sTag);
    System.out.println("SEND ROOT OF TRUST");
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder,
        (byte) INS_SEND_ROT_DATA_CMD, arr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] resp = response.getBytes();
    arr = KMArray.instance((short) 1);
    KMArray.cast(arr).add((short) 0, KMInteger.exp());
    short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
  }

  public static short constructRotPayload(KMEncoder encoder) {
    byte[] temp = "00011122233344455566677788899900".getBytes();
    short arr = KMArray.instance((short) 5);
    short bootHashPtr = KMByteBlob.instance(temp, (short) 0, (short) temp.length);
    short bootKeyPtr = KMByteBlob.instance(temp, (short) 0, (short) temp.length);
    short deviceLockedPtr = KMSimpleValue.instance(KMSimpleValue.FALSE);
    short bootStatePtr = KMInteger.uint_8(KMType.VERIFIED_BOOT);
    short bootPatchPtr = KMInteger.uint_16((short) BOOT_PATCH_LEVEL);

    KMArray.cast(arr).add((short) 0, bootKeyPtr);
    KMArray.cast(arr).add((short) 1, deviceLockedPtr);
    KMArray.cast(arr).add((short) 2, bootStatePtr);
    KMArray.cast(arr).add((short) 3, bootHashPtr);
    KMArray.cast(arr).add((short) 4, bootPatchPtr);
    short sTag = KMSemanticTag.instance(KMInteger.uint_16(KMSemanticTag.ROT_SEMANTIC_TAG), arr);
    byte[] scratchPad = new byte[256];
    short len = encoder.encode(sTag, scratchPad, (short) 0, (short) 256);
    return KMByteBlob.instance(scratchPad, (short) 0, len);
  }

  public static byte[] getRootOfTrustChallenge(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    short arr = KMArray.instance((short) 0);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder,
        (byte) INS_GET_ROT_CHALLENGE_CMD, arr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] resp = response.getBytes();
    arr = KMArray.instance((short) 2);
    KMArray.cast(arr).add((short) 0, KMInteger.exp());
    KMArray.cast(arr).add((short) 1, KMByteBlob.exp());
    short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
    byte[] challenge = new byte[16];
    short challengePtr = KMArray.cast(ptr).get((short) 1);
    Assert.assertEquals("Length of Challenge should be 16 bytes.", 16,
        KMByteBlob.cast(challengePtr).length());
    Util.arrayCopyNonAtomic(KMByteBlob.cast(challengePtr).getBuffer(),
        KMByteBlob.cast(challengePtr).getStartOff(),
        challenge, (short) 0, KMByteBlob.cast(challengePtr).length());
    return challenge;
  }
}
