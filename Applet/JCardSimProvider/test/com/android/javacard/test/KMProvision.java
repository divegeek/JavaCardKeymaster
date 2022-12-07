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
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymintDataStore;
import com.android.javacard.keymaster.KMMap;
import com.android.javacard.keymaster.KMNInteger;
import com.android.javacard.keymaster.KMSemanticTag;
import com.android.javacard.keymaster.KMSimpleValue;
import com.android.javacard.keymaster.KMTextString;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.seprovider.KMSEProvider;
import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;

public class KMProvision {

  // Provision Instructions
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 7;
  //0x08 was reserved for INS_INIT_STRONGBOX_CMD
  //0x09 was reserved for INS_SET_BOOT_ENDED_CMD earlier. it is unused now.
  private static final byte INS_SE_FACTORY_PROVISIONING_LOCK_CMD = INS_KEYMINT_PROVIDER_APDU_START + 10;
  private static final byte INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD = INS_KEYMINT_PROVIDER_APDU_START + 11;
  private static final byte INS_OEM_UNLOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 12;
  private static final byte INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 13;
  private static final byte INS_PROVISION_RKP_UDS_CERT_CHAIN_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 14;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 15;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 16;
  private static final byte INS_OEM_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 17;
  private static final byte INS_PROVISION_SECURE_BOOT_MODE_CMD = INS_KEYMINT_PROVIDER_APDU_START + 18;
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

  private static final byte[] kEcAttestRootCert = {
      (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0xad, (byte) 0x30, (byte) 0x82, (byte) 0x02,
      (byte) 0x53, (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02,
      (byte) 0x14, (byte) 0x77, (byte) 0x76, (byte) 0x38, (byte) 0x73, (byte) 0x7f, (byte) 0x38,
      (byte) 0xe6, (byte) 0x9e, (byte) 0xd9, (byte) 0x75, (byte) 0x5e, (byte) 0x67, (byte) 0xab,
      (byte) 0x0f, (byte) 0x0e, (byte) 0x3d, (byte) 0xe3, (byte) 0xb4, (byte) 0x94, (byte) 0xb3,
      (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
      (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x81,
      (byte) 0xa3, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53,
      (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c,
      (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e, (byte) 0x69, (byte) 0x61,
      (byte) 0x31, (byte) 0x14, (byte) 0x30, (byte) 0x12, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0b, (byte) 0x53, (byte) 0x61, (byte) 0x6e,
      (byte) 0x66, (byte) 0x72, (byte) 0x61, (byte) 0x6e, (byte) 0x73, (byte) 0x69, (byte) 0x63,
      (byte) 0x6f, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x06, (byte) 0x47, (byte) 0x6f,
      (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31, (byte) 0x19, (byte) 0x30,
      (byte) 0x17, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x0c,
      (byte) 0x10, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69,
      (byte) 0x64, (byte) 0x20, (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x75, (byte) 0x72,
      (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x13,
      (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20,
      (byte) 0x63, (byte) 0x61, (byte) 0x20, (byte) 0x73, (byte) 0x74, (byte) 0x72, (byte) 0x6f,
      (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f, (byte) 0x78, (byte) 0x31, (byte) 0x1f,
      (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
      (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x09, (byte) 0x01, (byte) 0x16,
      (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61, (byte) 0x77, (byte) 0x6e, (byte) 0x40,
      (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x2e,
      (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30, (byte) 0x1e, (byte) 0x17, (byte) 0x0d,
      (byte) 0x32, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x38, (byte) 0x30,
      (byte) 0x36, (byte) 0x35, (byte) 0x37, (byte) 0x33, (byte) 0x38, (byte) 0x5a, (byte) 0x17,
      (byte) 0x0d, (byte) 0x34, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33,
      (byte) 0x30, (byte) 0x36, (byte) 0x35, (byte) 0x37, (byte) 0x33, (byte) 0x38, (byte) 0x5a,
      (byte) 0x30, (byte) 0x81, (byte) 0xa3, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02,
      (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a, (byte) 0x43,
      (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e,
      (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x14, (byte) 0x30, (byte) 0x12, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0b, (byte) 0x53,
      (byte) 0x61, (byte) 0x6e, (byte) 0x66, (byte) 0x72, (byte) 0x61, (byte) 0x6e, (byte) 0x73,
      (byte) 0x69, (byte) 0x63, (byte) 0x6f, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x06,
      (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31,
      (byte) 0x19, (byte) 0x30, (byte) 0x17, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x0b, (byte) 0x0c, (byte) 0x10, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72,
      (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x53, (byte) 0x65, (byte) 0x63,
      (byte) 0x75, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x31, (byte) 0x1c,
      (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03,
      (byte) 0x0c, (byte) 0x13, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
      (byte) 0x65, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x20, (byte) 0x73, (byte) 0x74,
      (byte) 0x72, (byte) 0x6f, (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f, (byte) 0x78,
      (byte) 0x31, (byte) 0x1f, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09, (byte) 0x2a,
      (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x09,
      (byte) 0x01, (byte) 0x16, (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61, (byte) 0x77,
      (byte) 0x6e, (byte) 0x40, (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
      (byte) 0x65, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30, (byte) 0x59,
      (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
      (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
      (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07,
      (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0x9c, (byte) 0xc8, (byte) 0x1a,
      (byte) 0xcf, (byte) 0xc8, (byte) 0x8a, (byte) 0xb9, (byte) 0x2f, (byte) 0x1f, (byte) 0x87,
      (byte) 0xb6, (byte) 0xb1, (byte) 0x34, (byte) 0x8e, (byte) 0x75, (byte) 0x38, (byte) 0x1d,
      (byte) 0x3a, (byte) 0xed, (byte) 0xcd, (byte) 0xf0, (byte) 0x8f, (byte) 0x91, (byte) 0x55,
      (byte) 0x0d, (byte) 0x1a, (byte) 0x6d, (byte) 0x6f, (byte) 0xf0, (byte) 0x70, (byte) 0x2d,
      (byte) 0x55, (byte) 0x4a, (byte) 0x30, (byte) 0xb9, (byte) 0xbe, (byte) 0xab, (byte) 0x30,
      (byte) 0xc7, (byte) 0xb3, (byte) 0xa2, (byte) 0x2d, (byte) 0xfc, (byte) 0xcc, (byte) 0x84,
      (byte) 0x0a, (byte) 0xc9, (byte) 0xbf, (byte) 0xb9, (byte) 0x31, (byte) 0x5a, (byte) 0xb7,
      (byte) 0x8c, (byte) 0xa0, (byte) 0x72, (byte) 0x21, (byte) 0xdd, (byte) 0x27, (byte) 0xac,
      (byte) 0xfe, (byte) 0xcd, (byte) 0x34, (byte) 0x11, (byte) 0x82, (byte) 0xa3, (byte) 0x63,
      (byte) 0x30, (byte) 0x61, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x1d, (byte) 0x0e, (byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x81,
      (byte) 0x6c, (byte) 0xe6, (byte) 0x5a, (byte) 0x30, (byte) 0xf8, (byte) 0xe2, (byte) 0xaf,
      (byte) 0x7f, (byte) 0xef, (byte) 0x04, (byte) 0x23, (byte) 0x50, (byte) 0xdc, (byte) 0x4e,
      (byte) 0xa4, (byte) 0x48, (byte) 0xe2, (byte) 0x05, (byte) 0x62, (byte) 0x30, (byte) 0x1f,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04, (byte) 0x18,
      (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x81, (byte) 0x6c, (byte) 0xe6,
      (byte) 0x5a, (byte) 0x30, (byte) 0xf8, (byte) 0xe2, (byte) 0xaf, (byte) 0x7f, (byte) 0xef,
      (byte) 0x04, (byte) 0x23, (byte) 0x50, (byte) 0xdc, (byte) 0x4e, (byte) 0xa4, (byte) 0x48,
      (byte) 0xe2, (byte) 0x05, (byte) 0x62, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x1d, (byte) 0x13, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x04,
      (byte) 0x05, (byte) 0x30, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x30,
      (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01,
      (byte) 0x01, (byte) 0xff, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01,
      (byte) 0x86, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
      (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03,
      (byte) 0x48, (byte) 0x00, (byte) 0x30, (byte) 0x45, (byte) 0x02, (byte) 0x21, (byte) 0x00,
      (byte) 0xaf, (byte) 0x64, (byte) 0xe6, (byte) 0xa3, (byte) 0x6c, (byte) 0xae, (byte) 0xd3,
      (byte) 0x38, (byte) 0x02, (byte) 0xa1, (byte) 0x1e, (byte) 0x0e, (byte) 0x98, (byte) 0xa1,
      (byte) 0x91, (byte) 0xa8, (byte) 0x92, (byte) 0xe6, (byte) 0xf8, (byte) 0x79, (byte) 0x1a,
      (byte) 0x9f, (byte) 0x83, (byte) 0xd1, (byte) 0xb3, (byte) 0x23, (byte) 0x74, (byte) 0xd3,
      (byte) 0x3d, (byte) 0xb5, (byte) 0x4f, (byte) 0xc4, (byte) 0x02, (byte) 0x20, (byte) 0x74,
      (byte) 0xba, (byte) 0xeb, (byte) 0x9d, (byte) 0x57, (byte) 0x35, (byte) 0x09, (byte) 0x80,
      (byte) 0x20, (byte) 0x63, (byte) 0xb7, (byte) 0x0b, (byte) 0x15, (byte) 0xb6, (byte) 0xe5,
      (byte) 0xc1, (byte) 0x72, (byte) 0xa6, (byte) 0x8a, (byte) 0x4e, (byte) 0x9e, (byte) 0x57,
      (byte) 0x83, (byte) 0xd8, (byte) 0x63, (byte) 0xa7, (byte) 0x3c, (byte) 0x1a, (byte) 0x7d,
      (byte) 0x20, (byte) 0x85, (byte) 0xc6
  };


  private static final byte[] kEcAttestCert = {
      (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x94, (byte) 0x30, (byte) 0x82, (byte) 0x02,
      (byte) 0x3b, (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02,
      (byte) 0x02, (byte) 0x10, (byte) 0x00, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08,
      (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03,
      (byte) 0x02, (byte) 0x30, (byte) 0x81, (byte) 0xa3, (byte) 0x31, (byte) 0x0b, (byte) 0x30,
      (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13,
      (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a,
      (byte) 0x43, (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72,
      (byte) 0x6e, (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x14, (byte) 0x30, (byte) 0x12,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0b,
      (byte) 0x53, (byte) 0x61, (byte) 0x6e, (byte) 0x66, (byte) 0x72, (byte) 0x61, (byte) 0x6e,
      (byte) 0x73, (byte) 0x69, (byte) 0x63, (byte) 0x6f, (byte) 0x31, (byte) 0x0f, (byte) 0x30,
      (byte) 0x0d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c,
      (byte) 0x06, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65,
      (byte) 0x31, (byte) 0x19, (byte) 0x30, (byte) 0x17, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x0b, (byte) 0x0c, (byte) 0x10, (byte) 0x41, (byte) 0x6e, (byte) 0x64,
      (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x53, (byte) 0x65,
      (byte) 0x63, (byte) 0x75, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x31,
      (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x03, (byte) 0x0c, (byte) 0x13, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67,
      (byte) 0x6c, (byte) 0x65, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x20, (byte) 0x73,
      (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f,
      (byte) 0x78, (byte) 0x31, (byte) 0x1f, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09,
      (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01,
      (byte) 0x09, (byte) 0x01, (byte) 0x16, (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61,
      (byte) 0x77, (byte) 0x6e, (byte) 0x40, (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67,
      (byte) 0x6c, (byte) 0x65, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30,
      (byte) 0x1e, (byte) 0x17, (byte) 0x0d, (byte) 0x32, (byte) 0x31, (byte) 0x30, (byte) 0x31,
      (byte) 0x32, (byte) 0x38, (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x30, (byte) 0x30,
      (byte) 0x39, (byte) 0x5a, (byte) 0x17, (byte) 0x0d, (byte) 0x33, (byte) 0x31, (byte) 0x30,
      (byte) 0x31, (byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x30,
      (byte) 0x30, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x81, (byte) 0x9a, (byte) 0x31,
      (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13,
      (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08,
      (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66,
      (byte) 0x6f, (byte) 0x72, (byte) 0x6e, (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x0f,
      (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a,
      (byte) 0x0c, (byte) 0x06, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
      (byte) 0x65, (byte) 0x31, (byte) 0x19, (byte) 0x30, (byte) 0x17, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x0c, (byte) 0x10, (byte) 0x41, (byte) 0x6e,
      (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x53,
      (byte) 0x65, (byte) 0x63, (byte) 0x75, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x79,
      (byte) 0x31, (byte) 0x29, (byte) 0x30, (byte) 0x27, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x20, (byte) 0x47, (byte) 0x6f, (byte) 0x6f,
      (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x74,
      (byte) 0x65, (byte) 0x72, (byte) 0x6d, (byte) 0x65, (byte) 0x64, (byte) 0x69, (byte) 0x61,
      (byte) 0x74, (byte) 0x65, (byte) 0x20, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x73,
      (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f,
      (byte) 0x78, (byte) 0x31, (byte) 0x1f, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09,
      (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01,
      (byte) 0x09, (byte) 0x01, (byte) 0x16, (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61,
      (byte) 0x77, (byte) 0x6e, (byte) 0x40, (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67,
      (byte) 0x6c, (byte) 0x65, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30,
      (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
      (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08,
      (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01,
      (byte) 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0xfb, (byte) 0xc5,
      (byte) 0x8d, (byte) 0x57, (byte) 0x3f, (byte) 0x53, (byte) 0x3e, (byte) 0x6e, (byte) 0x62,
      (byte) 0x10, (byte) 0xd1, (byte) 0x66, (byte) 0x7a, (byte) 0x00, (byte) 0xf5, (byte) 0x8a,
      (byte) 0xd9, (byte) 0xa8, (byte) 0x61, (byte) 0x8f, (byte) 0x99, (byte) 0xcf, (byte) 0xae,
      (byte) 0x32, (byte) 0xf5, (byte) 0xb9, (byte) 0xab, (byte) 0xa4, (byte) 0x58, (byte) 0x1f,
      (byte) 0xa9, (byte) 0x47, (byte) 0x01, (byte) 0x39, (byte) 0x5d, (byte) 0xf5, (byte) 0x18,
      (byte) 0x82, (byte) 0x4e, (byte) 0x16, (byte) 0x44, (byte) 0x1a, (byte) 0xdf, (byte) 0xfc,
      (byte) 0xf4, (byte) 0xa0, (byte) 0xbd, (byte) 0x93, (byte) 0x42, (byte) 0x4a, (byte) 0x92,
      (byte) 0x41, (byte) 0x3b, (byte) 0x2b, (byte) 0x87, (byte) 0x04, (byte) 0xc0, (byte) 0x88,
      (byte) 0x37, (byte) 0xdb, (byte) 0x4c, (byte) 0x24, (byte) 0xe0, (byte) 0x18, (byte) 0xa3,
      (byte) 0x66, (byte) 0x30, (byte) 0x64, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x1d, (byte) 0x0e, (byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14,
      (byte) 0xf9, (byte) 0xda, (byte) 0x05, (byte) 0x74, (byte) 0xa2, (byte) 0x35, (byte) 0x5b,
      (byte) 0x00, (byte) 0xa2, (byte) 0x92, (byte) 0x08, (byte) 0x7e, (byte) 0x72, (byte) 0x87,
      (byte) 0xb4, (byte) 0x57, (byte) 0xf3, (byte) 0x01, (byte) 0x04, (byte) 0x46, (byte) 0x30,
      (byte) 0x1f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04,
      (byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x81, (byte) 0x6c,
      (byte) 0xe6, (byte) 0x5a, (byte) 0x30, (byte) 0xf8, (byte) 0xe2, (byte) 0xaf, (byte) 0x7f,
      (byte) 0xef, (byte) 0x04, (byte) 0x23, (byte) 0x50, (byte) 0xdc, (byte) 0x4e, (byte) 0xa4,
      (byte) 0x48, (byte) 0xe2, (byte) 0x05, (byte) 0x62, (byte) 0x30, (byte) 0x12, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x13, (byte) 0x01, (byte) 0x01, (byte) 0xff,
      (byte) 0x04, (byte) 0x08, (byte) 0x30, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xff,
      (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, (byte) 0x0e, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x04,
      (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x86, (byte) 0x30, (byte) 0x0a,
      (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
      (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x47, (byte) 0x00, (byte) 0x30,
      (byte) 0x44, (byte) 0x02, (byte) 0x20, (byte) 0x2e, (byte) 0xbb, (byte) 0x46, (byte) 0xd4,
      (byte) 0x40, (byte) 0xab, (byte) 0x55, (byte) 0xb3, (byte) 0xb6, (byte) 0xb6, (byte) 0x1b,
      (byte) 0x54, (byte) 0xe6, (byte) 0x3e, (byte) 0xed, (byte) 0x54, (byte) 0x30, (byte) 0xb7,
      (byte) 0xb7, (byte) 0x72, (byte) 0x10, (byte) 0x56, (byte) 0x34, (byte) 0x2d, (byte) 0x0b,
      (byte) 0xdb, (byte) 0x5c, (byte) 0x7f, (byte) 0xee, (byte) 0x51, (byte) 0x9a, (byte) 0x85,
      (byte) 0x02, (byte) 0x20, (byte) 0x17, (byte) 0x24, (byte) 0x2a, (byte) 0xdf, (byte) 0xf5,
      (byte) 0x33, (byte) 0xaf, (byte) 0x40, (byte) 0xa8, (byte) 0x6d, (byte) 0xd0, (byte) 0x58,
      (byte) 0x0c, (byte) 0x78, (byte) 0xfb, (byte) 0x86, (byte) 0xef, (byte) 0x07, (byte) 0xa6,
      (byte) 0x71, (byte) 0xcc, (byte) 0x55, (byte) 0xfc, (byte) 0x6a, (byte) 0x0b, (byte) 0x84,
      (byte) 0x28, (byte) 0x88, (byte) 0xa2, (byte) 0xca, (byte) 0x19, (byte) 0xe0};

  private static final byte[] X509Issuer = {
      (byte) 0x30, (byte) 0x81, (byte) 0x88, (byte) 0x31, (byte) 0x0b,
      (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55,
      (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08,
      (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c,
      (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e,
      (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x15, (byte) 0x30,
      (byte) 0x13, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x0a, (byte) 0x0c, (byte) 0x0c, (byte) 0x47, (byte) 0x6f,
      (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x2c,
      (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x63, (byte) 0x2e,
      (byte) 0x31, (byte) 0x10, (byte) 0x30, (byte) 0x0e, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x0c,
      (byte) 0x07, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72,
      (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x31, (byte) 0x3b,
      (byte) 0x30, (byte) 0x39, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x32, (byte) 0x41,
      (byte) 0x6e, (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69,
      (byte) 0x64, (byte) 0x20, (byte) 0x4b, (byte) 0x65, (byte) 0x79,
      (byte) 0x73, (byte) 0x74, (byte) 0x6f, (byte) 0x72, (byte) 0x65,
      (byte) 0x20, (byte) 0x53, (byte) 0x6f, (byte) 0x66, (byte) 0x74,
      (byte) 0x77, (byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20,
      (byte) 0x41, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73,
      (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f,
      (byte) 0x6e, (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x74,
      (byte) 0x65, (byte) 0x72, (byte) 0x6d, (byte) 0x65, (byte) 0x64,
      (byte) 0x69, (byte) 0x61, (byte) 0x74, (byte) 0x65};
  private static final byte[] expiryTime = {(byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x31,
      (byte) 0x30, (byte) 0x38, (byte) 0x30, (byte) 0x30, (byte) 0x34, (byte) 0x36, (byte) 0x30,
      (byte) 0x39, (byte) 0x5a};
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

  public static ResponseAPDU provisionUdsCertChain(CardSimulator simulator,
      KMEncoder encoder, KMDecoder decoder) {
    short innerArrPtr = KMArray.instance((short) 2);

    short byteBlobPtr1 = KMByteBlob.instance(kEcAttestRootCert, (short) 0, (short) kEcAttestRootCert.length);
    short byteBlobPtr2 = KMByteBlob.instance(kEcAttestCert, (short) 0, (short) kEcAttestCert.length);

    KMArray.cast(innerArrPtr).add((short) 0, byteBlobPtr1);
    KMArray.cast(innerArrPtr).add((short) 1, byteBlobPtr2);
    short map = KMMap.instance((short) 1);
    byte[] signerName = "TestSigner".getBytes();
    KMMap.cast(map)
        .add((short) 0, KMTextString.instance(signerName, (short) 0, (short) signerName.length),
            innerArrPtr);
    byte[] output = new byte[2048];
    short encodedLen = encoder.encode(map, output, (short) 0, (short) 2048);
    short encodedData = KMByteBlob.instance(output, (short) 0, encodedLen);

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder,
        (byte) INS_PROVISION_RKP_UDS_CERT_CHAIN_CMD, encodedData);
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
            privKey, (short) 0, lengths[0]);
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

  public static ResponseAPDU provisionSecureBootMode(CardSimulator simulator, KMEncoder encoder,
      KMDecoder decoder) {
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, KMInteger.uint_8((byte) 0));

    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_PROVISION_SECURE_BOOT_MODE_CMD,
        arrPtr);
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
    short arrPtr = KMArray.instance((short) 9);

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
            KMByteTag.instance(KMType.ATTESTATION_ID_SECOND_IMEI,
                KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 6,
        KMByteTag.instance(KMType.ATTESTATION_ID_MEID,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 7,
        KMByteTag.instance(KMType.ATTESTATION_ID_MANUFACTURER,
            KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
    KMArray.cast(arrPtr).add((short) 8,
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
      KMTestUtils.APDU_P1, KMTestUtils.APDU_P2);
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
        provisionUdsCertChain(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionSeLocked(simulator, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        provisionSecureBootMode(simulator, encoder, decoder)));
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
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_EARLY_BOOT_ENDED_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2);
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
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_GET_HMAC_SHARING_PARAM_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2);
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
