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

package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMBoolTag;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMJCardSimApplet;
import com.android.javacard.keymaster.KMJCardSimulator;
import com.android.javacard.keymaster.KMSEProvider;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMHardwareAuthToken;
import com.android.javacard.keymaster.KMHmacSharingParameters;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMRepository;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.keymaster.KMVerificationToken;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Assert;
import org.junit.Test;

public class KMFunctionalTest {

  private static final byte INS_BEGIN_KM_CMD = 0x00;
  private static final byte INS_PROVISION_ATTESTATION_KEY_CMD = INS_BEGIN_KM_CMD + 1; //0x01
  private static final byte INS_PROVISION_ATTESTATION_CERT_CHAIN_CMD = INS_BEGIN_KM_CMD + 2; //0x02
  private static final byte INS_PROVISION_ATTESTATION_CERT_PARAMS_CMD = INS_BEGIN_KM_CMD + 3; //0x03
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_BEGIN_KM_CMD + 4; //0x04
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD = INS_BEGIN_KM_CMD + 5; //0x05
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_BEGIN_KM_CMD + 6; //0x06
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD + 7; //0x07
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD + 8; //0x08
  // Top 32 commands are reserved for provisioning.
  private static final byte INS_END_KM_PROVISION_CMD = 0x20;

  private static final byte INS_GENERATE_KEY_CMD = INS_END_KM_PROVISION_CMD + 1;  //0x21
  private static final byte INS_IMPORT_KEY_CMD = INS_END_KM_PROVISION_CMD + 2;    //0x22
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = INS_END_KM_PROVISION_CMD + 3; //0x23
  private static final byte INS_EXPORT_KEY_CMD = INS_END_KM_PROVISION_CMD + 4; //0x24
  private static final byte INS_ATTEST_KEY_CMD = INS_END_KM_PROVISION_CMD + 5; //0x25
  private static final byte INS_UPGRADE_KEY_CMD = INS_END_KM_PROVISION_CMD + 6; //0x26
  private static final byte INS_DELETE_KEY_CMD = INS_END_KM_PROVISION_CMD + 7; //0x27
  private static final byte INS_DELETE_ALL_KEYS_CMD = INS_END_KM_PROVISION_CMD + 8; //0x28
  private static final byte INS_ADD_RNG_ENTROPY_CMD = INS_END_KM_PROVISION_CMD + 9; //0x29
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = INS_END_KM_PROVISION_CMD + 10; //0x2A
  private static final byte INS_DESTROY_ATT_IDS_CMD = INS_END_KM_PROVISION_CMD + 11;  //0x2B
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = INS_END_KM_PROVISION_CMD + 12; //0x2C
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = INS_END_KM_PROVISION_CMD + 13; //0x2D
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = INS_END_KM_PROVISION_CMD + 14; //0x2E
  private static final byte INS_GET_HW_INFO_CMD = INS_END_KM_PROVISION_CMD + 15; //0x2F
  private static final byte INS_BEGIN_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 16;  //0x30
  private static final byte INS_UPDATE_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 17;  //0x31
  private static final byte INS_FINISH_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 18; //0x32
  private static final byte INS_ABORT_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 19; //0x33
  private static final byte INS_DEVICE_LOCKED_CMD = INS_END_KM_PROVISION_CMD + 20;//0x34
  private static final byte INS_EARLY_BOOT_ENDED_CMD = INS_END_KM_PROVISION_CMD + 21; //0x35
  private static final byte INS_GET_CERT_CHAIN_CMD = INS_END_KM_PROVISION_CMD + 22; //0x36

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

  private static final byte[] kEcAttestCert = {
      0x30, (byte) 0x82, (byte) 0x02, (byte) 0x78, (byte) 0x30, (byte) 0x82,
      (byte) 0x02, (byte) 0x1e, (byte) 0xa0, (byte) 0x03, (byte) 0x02,
      (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x10, 0x01,
      (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
      (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04,
      (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x81, (byte) 0x98, 0x31,
      (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02,
      (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, 0x11,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08,
      (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c,
      (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e, 0x69,
      (byte) 0x61, (byte) 0x31, (byte) 0x16, (byte) 0x30, (byte) 0x14,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07,
      (byte) 0x0c, (byte) 0x0d, (byte) 0x4d, (byte) 0x6f, (byte) 0x75, 0x6e,
      (byte) 0x74, (byte) 0x61, (byte) 0x69, (byte) 0x6e, (byte) 0x20,
      (byte) 0x56, (byte) 0x69, (byte) 0x65, (byte) 0x77, (byte) 0x31,
      (byte) 0x15, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x03, 0x55,
      (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x0c, (byte) 0x47,
      (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65,
      (byte) 0x2c, (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x63, 0x2e,
      (byte) 0x31, (byte) 0x10, (byte) 0x30, (byte) 0x0e, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x0c,
      (byte) 0x07, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72, 0x6f,
      (byte) 0x69, (byte) 0x64, (byte) 0x31, (byte) 0x33, (byte) 0x30,
      (byte) 0x31, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x03, (byte) 0x0c, (byte) 0x2a, (byte) 0x41, (byte) 0x6e, 0x64,
      (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20,
      (byte) 0x4b, (byte) 0x65, (byte) 0x79, (byte) 0x73, (byte) 0x74,
      (byte) 0x6f, (byte) 0x72, (byte) 0x65, (byte) 0x20, (byte) 0x53, 0x6f,
      (byte) 0x66, (byte) 0x74, (byte) 0x77, (byte) 0x61, (byte) 0x72,
      (byte) 0x65, (byte) 0x20, (byte) 0x41, (byte) 0x74, (byte) 0x74,
      (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x61, (byte) 0x74, 0x69,
      (byte) 0x6f, (byte) 0x6e, (byte) 0x20, (byte) 0x52, (byte) 0x6f,
      (byte) 0x6f, (byte) 0x74, (byte) 0x30, (byte) 0x1e, (byte) 0x17,
      (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x31, 0x31,
      (byte) 0x31, (byte) 0x30, (byte) 0x30, (byte) 0x34, (byte) 0x36,
      (byte) 0x30, (byte) 0x39, (byte) 0x5a, (byte) 0x17, (byte) 0x0d,
      (byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x31, (byte) 0x30, 0x38,
      (byte) 0x30, (byte) 0x30, (byte) 0x34, (byte) 0x36, (byte) 0x30,
      (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x81, (byte) 0x88,
      (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02,
      (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30,
      (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, 0x08,
      (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c,
      (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e,
      (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x15, (byte) 0x30, 0x13,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a,
      (byte) 0x0c, (byte) 0x0c, (byte) 0x47, (byte) 0x6f, (byte) 0x6f,
      (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x2c, (byte) 0x20, 0x49,
      (byte) 0x6e, (byte) 0x63, (byte) 0x2e, (byte) 0x31, (byte) 0x10,
      (byte) 0x30, (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x04, (byte) 0x0b, (byte) 0x0c, (byte) 0x07, (byte) 0x41, 0x6e,
      (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64,
      (byte) 0x31, (byte) 0x3b, (byte) 0x30, (byte) 0x39, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, 0x32,
      (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72, (byte) 0x6f,
      (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x4b, (byte) 0x65,
      (byte) 0x79, (byte) 0x73, (byte) 0x74, (byte) 0x6f, (byte) 0x72, 0x65,
      (byte) 0x20, (byte) 0x53, (byte) 0x6f, (byte) 0x66, (byte) 0x74,
      (byte) 0x77, (byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20,
      (byte) 0x41, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73, 0x74,
      (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
      (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x74, (byte) 0x65,
      (byte) 0x72, (byte) 0x6d, (byte) 0x65, (byte) 0x64, (byte) 0x69, 0x61,
      (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x59, (byte) 0x30,
      (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
      (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, 0x06,
      (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce,
      (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07, (byte) 0x03,
      (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0xeb, (byte) 0x9e, 0x79,
      (byte) 0xf8, (byte) 0x42, (byte) 0x63, (byte) 0x59, (byte) 0xac,
      (byte) 0xcb, (byte) 0x2a, (byte) 0x91, (byte) 0x4c, (byte) 0x89,
      (byte) 0x86, (byte) 0xcc, (byte) 0x70, (byte) 0xad, (byte) 0x90, 0x66,
      (byte) 0x93, (byte) 0x82, (byte) 0xa9, (byte) 0x73, (byte) 0x26,
      (byte) 0x13, (byte) 0xfe, (byte) 0xac, (byte) 0xcb, (byte) 0xf8,
      (byte) 0x21, (byte) 0x27, (byte) 0x4c, (byte) 0x21, (byte) 0x74,
      (byte) 0x97, (byte) 0x4a, (byte) 0x2a, (byte) 0xfe, (byte) 0xa5,
      (byte) 0xb9, (byte) 0x4d, (byte) 0x7f, (byte) 0x66, (byte) 0xd4,
      (byte) 0xe0, (byte) 0x65, (byte) 0x10, (byte) 0x66, (byte) 0x35,
      (byte) 0xbc, 0x53, (byte) 0xb7, (byte) 0xa0, (byte) 0xa3, (byte) 0xa6,
      (byte) 0x71, (byte) 0x58, (byte) 0x3e, (byte) 0xdb, (byte) 0x3e,
      (byte) 0x11, (byte) 0xae, (byte) 0x10, (byte) 0x14, (byte) 0xa3,
      (byte) 0x66, 0x30, (byte) 0x64, (byte) 0x30, (byte) 0x1d, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0e, (byte) 0x04,
      (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x3f, (byte) 0xfc,
      (byte) 0xac, (byte) 0xd6, (byte) 0x1a, (byte) 0xb1, (byte) 0x3a,
      (byte) 0x9e, (byte) 0x81, (byte) 0x20, (byte) 0xb8, (byte) 0xd5,
      (byte) 0x25, (byte) 0x1c, (byte) 0xc5, (byte) 0x65, (byte) 0xbb,
      (byte) 0x1e, (byte) 0x91, (byte) 0xa9, (byte) 0x30, (byte) 0x1f,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23,
      (byte) 0x04, (byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x80,
      (byte) 0x14, (byte) 0xc8, (byte) 0xad, (byte) 0xe9, (byte) 0x77,
      (byte) 0x4c, (byte) 0x45, (byte) 0xc3, (byte) 0xa3, (byte) 0xcf,
      (byte) 0x0d, (byte) 0x16, (byte) 0x10, (byte) 0xe4, (byte) 0x79,
      (byte) 0x43, (byte) 0x3a, (byte) 0x21, (byte) 0x5a, 0x30, (byte) 0xcf,
      (byte) 0x30, (byte) 0x12, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      (byte) 0x1d, (byte) 0x13, (byte) 0x01, (byte) 0x01, (byte) 0xff,
      (byte) 0x04, (byte) 0x08, (byte) 0x30, (byte) 0x06, 0x01, (byte) 0x01,
      (byte) 0xff, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30,
      (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d,
      (byte) 0x0f, (byte) 0x01, (byte) 0x01, (byte) 0xff, 0x04, (byte) 0x04,
      (byte) 0x03, (byte) 0x02, (byte) 0x02, (byte) 0x84, (byte) 0x30,
      (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
      (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, 0x03, (byte) 0x02,
      (byte) 0x03, (byte) 0x48, (byte) 0x00, (byte) 0x30, (byte) 0x45,
      (byte) 0x02, (byte) 0x20, (byte) 0x4b, (byte) 0x8a, (byte) 0x9b,
      (byte) 0x7b, (byte) 0xee, (byte) 0x82, (byte) 0xbc, (byte) 0xc0,
      (byte) 0x33, (byte) 0x87, (byte) 0xae, (byte) 0x2f, (byte) 0xc0,
      (byte) 0x89, (byte) 0x98, (byte) 0xb4, (byte) 0xdd, (byte) 0xc3,
      (byte) 0x8d, (byte) 0xab, (byte) 0x27, (byte) 0x2a, (byte) 0x45,
      (byte) 0x9f, (byte) 0x69, (byte) 0x0c, (byte) 0xc7, (byte) 0xc3,
      (byte) 0x92, (byte) 0xd4, (byte) 0x0f, (byte) 0x8e, (byte) 0x02,
      (byte) 0x21, (byte) 0x00, (byte) 0xee, (byte) 0xda, (byte) 0x01,
      (byte) 0x5d, (byte) 0xb6, (byte) 0xf4, (byte) 0x32, (byte) 0xe9,
      (byte) 0xd4, (byte) 0x84, (byte) 0x3b, (byte) 0x62, (byte) 0x4c,
      (byte) 0x94, (byte) 0x04, (byte) 0xef, (byte) 0x3a, (byte) 0x7c,
      (byte) 0xcc, (byte) 0xbd, 0x5e, (byte) 0xfb, (byte) 0x22, (byte) 0xbb,
      (byte) 0xe7, (byte) 0xfe, (byte) 0xb9, (byte) 0x77, (byte) 0x3f,
      (byte) 0x59, (byte) 0x3f, (byte) 0xfb,};

  private static final byte[] kEcAttestRootCert = {
      0x30, (byte) 0x82, (byte) 0x02, (byte) 0x8b, (byte) 0x30,
      (byte) 0x82, (byte) 0x02, (byte) 0x32, (byte) 0xa0, (byte) 0x03,
      (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x09,
      (byte) 0x00, (byte) 0xa2, (byte) 0x05, (byte) 0x9e, (byte) 0xd1,
      (byte) 0x0e, (byte) 0x43, (byte) 0x5b, (byte) 0x57, (byte) 0x30,
      (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
      (byte) 0x48, (byte) 0xce, 0x3d, (byte) 0x04, (byte) 0x03,
      (byte) 0x02, (byte) 0x30, (byte) 0x81, (byte) 0x98, (byte) 0x31,
      (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x06, 0x13, (byte) 0x02,
      (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30,
      (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x08, (byte) 0x0c, (byte) 0x0a, (byte) 0x43, 0x61,
      (byte) 0x6c, (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72,
      (byte) 0x6e, (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x16,
      (byte) 0x30, (byte) 0x14, (byte) 0x06, (byte) 0x03, (byte) 0x55,
      0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0d, (byte) 0x4d,
      (byte) 0x6f, (byte) 0x75, (byte) 0x6e, (byte) 0x74, (byte) 0x61,
      (byte) 0x69, (byte) 0x6e, (byte) 0x20, (byte) 0x56, (byte) 0x69,
      (byte) 0x65, 0x77, (byte) 0x31, (byte) 0x15, (byte) 0x30,
      (byte) 0x13, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x0a, (byte) 0x0c, (byte) 0x0c, (byte) 0x47, (byte) 0x6f,
      (byte) 0x6f, (byte) 0x67, 0x6c, (byte) 0x65, (byte) 0x2c,
      (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x63, (byte) 0x2e,
      (byte) 0x31, (byte) 0x10, (byte) 0x30, (byte) 0x0e, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, 0x0b, (byte) 0x0c,
      (byte) 0x07, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72,
      (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x31, (byte) 0x33,
      (byte) 0x30, (byte) 0x31, (byte) 0x06, (byte) 0x03, 0x55,
      (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x2a, (byte) 0x41,
      (byte) 0x6e, (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69,
      (byte) 0x64, (byte) 0x20, (byte) 0x4b, (byte) 0x65, (byte) 0x79,
      0x73, (byte) 0x74, (byte) 0x6f, (byte) 0x72, (byte) 0x65,
      (byte) 0x20, (byte) 0x53, (byte) 0x6f, (byte) 0x66, (byte) 0x74,
      (byte) 0x77, (byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20,
      (byte) 0x41, 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73,
      (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f,
      (byte) 0x6e, (byte) 0x20, (byte) 0x52, (byte) 0x6f, (byte) 0x6f,
      (byte) 0x74, (byte) 0x30, 0x1e, (byte) 0x17, (byte) 0x0d,
      (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x31, (byte) 0x31,
      (byte) 0x31, (byte) 0x30, (byte) 0x30, (byte) 0x34, (byte) 0x33,
      (byte) 0x35, (byte) 0x30, (byte) 0x5a, 0x17, (byte) 0x0d,
      (byte) 0x33, (byte) 0x36, (byte) 0x30, (byte) 0x31, (byte) 0x30,
      (byte) 0x36, (byte) 0x30, (byte) 0x30, (byte) 0x34, (byte) 0x33,
      (byte) 0x35, (byte) 0x30, (byte) 0x5a, (byte) 0x30, (byte) 0x81,
      (byte) 0x98, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06,
      (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31,
      0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a,
      (byte) 0x43, (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66,
      (byte) 0x6f, 0x72, (byte) 0x6e, (byte) 0x69, (byte) 0x61,
      (byte) 0x31, (byte) 0x16, (byte) 0x30, (byte) 0x14, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c,
      (byte) 0x0d, (byte) 0x4d, 0x6f, (byte) 0x75, (byte) 0x6e,
      (byte) 0x74, (byte) 0x61, (byte) 0x69, (byte) 0x6e, (byte) 0x20,
      (byte) 0x56, (byte) 0x69, (byte) 0x65, (byte) 0x77, (byte) 0x31,
      (byte) 0x15, (byte) 0x30, (byte) 0x13, 0x06, (byte) 0x03,
      (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x0c,
      (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
      (byte) 0x65, (byte) 0x2c, (byte) 0x20, (byte) 0x49, 0x6e,
      (byte) 0x63, (byte) 0x2e, (byte) 0x31, (byte) 0x10, (byte) 0x30,
      (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
      (byte) 0x0b, (byte) 0x0c, (byte) 0x07, (byte) 0x41, (byte) 0x6e,
      0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64,
      (byte) 0x31, (byte) 0x33, (byte) 0x30, (byte) 0x31, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c,
      (byte) 0x2a, 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72,
      (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x4b,
      (byte) 0x65, (byte) 0x79, (byte) 0x73, (byte) 0x74, (byte) 0x6f,
      (byte) 0x72, (byte) 0x65, 0x20, (byte) 0x53, (byte) 0x6f,
      (byte) 0x66, (byte) 0x74, (byte) 0x77, (byte) 0x61, (byte) 0x72,
      (byte) 0x65, (byte) 0x20, (byte) 0x41, (byte) 0x74, (byte) 0x74,
      (byte) 0x65, (byte) 0x73, (byte) 0x74, 0x61, (byte) 0x74,
      (byte) 0x69, (byte) 0x6f, (byte) 0x6e, 0x77, (byte) 0x1f,
      (byte) 0x44, (byte) 0x22, (byte) 0x6d, (byte) 0xbd, (byte) 0xb1,
      (byte) 0xaf, (byte) 0xfa, (byte) 0x16, (byte) 0xcb, (byte) 0xc7,
      (byte) 0xad, (byte) 0xc5, (byte) 0x77, (byte) 0xd2, (byte) 0x20,
      (byte) 0x52, (byte) 0x6f, (byte) 0x6f, (byte) 0x74, (byte) 0x30,
      (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07,
      0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
      (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
      (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03,
      (byte) 0x01, 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00,
      (byte) 0x04, (byte) 0xee, (byte) 0x5d, (byte) 0x5e, (byte) 0xc7,
      (byte) 0xe1, (byte) 0xc0, (byte) 0xdb, (byte) 0x6d, (byte) 0x03,
      (byte) 0xa6, (byte) 0x7e, (byte) 0xe6, (byte) 0xb6, (byte) 0x1b,
      (byte) 0xec, (byte) 0x4d, (byte) 0x6a, (byte) 0x5d, (byte) 0x6a,
      (byte) 0x68, (byte) 0x2e, (byte) 0x0f, (byte) 0xff, (byte) 0x7f,
      (byte) 0x49, (byte) 0x0e, (byte) 0x7d, 0x56, (byte) 0x9c,
      (byte) 0xaa, (byte) 0xb7, (byte) 0xb0, (byte) 0x2d, (byte) 0x54,
      (byte) 0x01, (byte) 0x5d, (byte) 0x3e, (byte) 0x43, (byte) 0x2b,
      (byte) 0x2a, (byte) 0x8e, (byte) 0xd7, (byte) 0x4e, (byte) 0xec,
      (byte) 0x48, (byte) 0x75, (byte) 0x41, (byte) 0xa4, (byte) 0xa3,
      (byte) 0x63, (byte) 0x30, (byte) 0x61, (byte) 0x30, (byte) 0x1d,
      (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0e,
      0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0xc8,
      (byte) 0xad, (byte) 0xe9, (byte) 0x77, (byte) 0x4c, (byte) 0x45,
      (byte) 0xc3, (byte) 0xa3, (byte) 0xcf, (byte) 0x0d, (byte) 0x16,
      (byte) 0x10, (byte) 0xe4, (byte) 0x79, (byte) 0x43, (byte) 0x3a,
      (byte) 0x21, (byte) 0x5a, (byte) 0x30, (byte) 0xcf, (byte) 0x30,
      (byte) 0x1f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d,
      (byte) 0x23, (byte) 0x04, 0x18, (byte) 0x30, (byte) 0x16,
      (byte) 0x80, (byte) 0x14, (byte) 0xc8, (byte) 0xad, (byte) 0xe9,
      (byte) 0x77, (byte) 0x4c, (byte) 0x45, (byte) 0xc3, (byte) 0xa3,
      (byte) 0xcf, (byte) 0x0d, (byte) 0x16, 0x10, (byte) 0xe4,
      (byte) 0x79, (byte) 0x43, (byte) 0x3a, (byte) 0x21, (byte) 0x5a,
      (byte) 0x30, (byte) 0xcf, (byte) 0x30, (byte) 0x0f, (byte) 0x06,
      (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x13, 0x01,
      (byte) 0x01, (byte) 0xff, (byte) 0x04, (byte) 0x05, (byte) 0x30,
      (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x30,
      (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d,
      0x0f, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x04,
      (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x02, (byte) 0x84,
      (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
      (byte) 0x86, 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04,
      (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x47, (byte) 0x00,
      (byte) 0x30, (byte) 0x44, (byte) 0x02, (byte) 0x20, (byte) 0x35,
      (byte) 0x21, (byte) 0xa3, (byte) 0xef, (byte) 0x8b, (byte) 0x34,
      (byte) 0x46, (byte) 0x1e, (byte) 0x9c, (byte) 0xd5, (byte) 0x60,
      (byte) 0xf3, (byte) 0x1d, (byte) 0x58, (byte) 0x89, (byte) 0x20,
      (byte) 0x6a, (byte) 0xdc, (byte) 0xa3, 0x65, (byte) 0x41,
      (byte) 0xf6, (byte) 0x0d, (byte) 0x9e, (byte) 0xce, (byte) 0x8a,
      (byte) 0x19, (byte) 0x8c, (byte) 0x66, (byte) 0x48, (byte) 0x60,
      (byte) 0x7b, (byte) 0x02, (byte) 0x20, (byte) 0x4d, 0x0b,
      (byte) 0xf3, (byte) 0x51, (byte) 0xd9, (byte) 0x30, (byte) 0x7c,
      (byte) 0x7d, (byte) 0x5b, (byte) 0xda, (byte) 0x35, (byte) 0x34,
      (byte) 0x1d, (byte) 0xa8, (byte) 0x47, (byte) 0x1b, (byte) 0x63,
      (byte) 0xa5, (byte) 0x85, (byte) 0x65, (byte) 0x3c, (byte) 0xad,
      (byte) 0x4f, (byte) 0x24, (byte) 0xa7, (byte) 0xe7, (byte) 0x4d,
      (byte) 0xaf, (byte) 0x41, (byte) 0x7d, (byte) 0xf1,
      (byte) 0xbf,};

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
  // AttestationApplicationId ::= SEQUENCE {
  //     *     packageInfoRecords SET OF PackageInfoRecord,
  //     *     signatureDigests   SET OF OCTET_STRING,
  //     * }
  //     *
  //     * PackageInfoRecord ::= SEQUENCE {
  //     *     packageName        OCTET_STRING,
  //     *     version            INTEGER,
  //     * }
  private static final byte[] attAppId = {0x30, 0x10, 0x31, 0x0B, 0x30, 0x04, 0x05, 'A', 'B', 'C',
      'D', 'E', 0x02, 0x01, 0x01, 0x31, 0x02, 0x04, 0x00};
  private static final byte[] attChallenge = {'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e'};
  private static final byte[] expiryTime = {(byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x31,
      (byte) 0x30, (byte) 0x38, (byte) 0x30, (byte) 0x30, (byte) 0x34, (byte) 0x36, (byte) 0x30,
      (byte) 0x39, (byte) 0x5a};
  private static final byte[] authKeyId = {(byte) 0x80, (byte) 0x14, (byte) 0xc8, (byte) 0xad,
      (byte) 0xe9, (byte) 0x77, (byte) 0x4c, (byte) 0x45, (byte) 0xc3, (byte) 0xa3, (byte) 0xcf,
      (byte) 0x0d, (byte) 0x16, (byte) 0x10, (byte) 0xe4, (byte) 0x79, (byte) 0x43, (byte) 0x3a,
      (byte) 0x21, (byte) 0x5a, (byte) 0x30, (byte) 0xcf};
  private static final int OS_VERSION = 1;
  private static final int OS_PATCH_LEVEL = 1;
  private static final int VENDOR_PATCH_LEVEL = 1;
  private static final int BOOT_PATCH_LEVEL = 1;

  private CardSimulator simulator;
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMSEProvider cryptoProvider;

  public KMFunctionalTest() {
    cryptoProvider = new KMJCardSimulator();
    simulator = new CardSimulator();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
  }

  private void init() {
    // Create simulator
    AID appletAID = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID);
    // provision attest key
    provisionCmd(simulator);
  }

  private void setBootParams(CardSimulator simulator, short osVersion,
      short osPatchLevel, short vendorPatchLevel, short bootPatchLevel) {
    // Argument 1 OS Version
    short versionPtr = KMInteger.uint_16(osVersion);
    // short versionTagPtr = KMIntegerTag.instance(KMType.UINT_TAG,
    // KMType.OS_VERSION,versionPatchPtr);
    // Argument 2 OS Patch level
    short patchPtr = KMInteger.uint_16(osPatchLevel);
    short vendorpatchPtr = KMInteger.uint_16((short) vendorPatchLevel);
    short bootpatchPtr = KMInteger.uint_16((short) bootPatchLevel);
    // Argument 3 Verified Boot Key
    byte[] bootKeyHash = "00011122233344455566677788899900".getBytes();
    short bootKeyPtr = KMByteBlob.instance(bootKeyHash, (short) 0,
        (short) bootKeyHash.length);
    // Argument 4 Verified Boot Hash
    short bootHashPtr = KMByteBlob.instance(bootKeyHash, (short) 0,
        (short) bootKeyHash.length);
    // Argument 5 Verified Boot State
    short bootStatePtr = KMEnum.instance(KMType.VERIFIED_BOOT_STATE,
        KMType.VERIFIED_BOOT);
    // Argument 6 Device Locked
    short deviceLockedPtr = KMEnum.instance(KMType.DEVICE_LOCKED,
        KMType.DEVICE_LOCKED_FALSE);
    // Arguments
    short arrPtr = KMArray.instance((short) 8);
    KMArray vals = KMArray.cast(arrPtr);
    vals.add((short) 0, versionPtr);
    vals.add((short) 1, patchPtr);
    vals.add((short) 2, vendorpatchPtr);
    vals.add((short) 3, bootpatchPtr);
    vals.add((short) 4, bootKeyPtr);
    vals.add((short) 5, bootHashPtr);
    vals.add((short) 6, bootStatePtr);
    vals.add((short) 7, deviceLockedPtr);
    CommandAPDU apdu = encodeApdu((byte) INS_SET_BOOT_PARAMS_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());

  }

  private void provisionSigningCertificate(CardSimulator simulator) {
    short byteBlobPtr = KMByteBlob.instance(
        (short) (kEcAttestCert.length + kEcAttestRootCert.length));
    Util.arrayCopyNonAtomic(kEcAttestCert, (short) 0,
        KMByteBlob.cast(byteBlobPtr).getBuffer(),
        KMByteBlob.cast(byteBlobPtr).getStartOff(),
        (short) kEcAttestCert.length);
    Util.arrayCopyNonAtomic(kEcAttestRootCert, (short) 0,
        KMByteBlob.cast(byteBlobPtr).getBuffer(),
        (short) (KMByteBlob.cast(byteBlobPtr).getStartOff()
            + kEcAttestCert.length),
        (short) kEcAttestRootCert.length);
    CommandAPDU apdu = encodeApdu(
        (byte) INS_PROVISION_ATTESTATION_CERT_CHAIN_CMD, byteBlobPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void provisionSigningKey(CardSimulator simulator) {
    // KeyParameters.
    short arrPtr = KMArray.instance((short) 4);
    short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short byteBlob2 = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob2).add((short) 0, KMType.ATTEST_KEY);
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
    short signKeyPtr = KMArray.instance((short) 2);
    KMArray.cast(signKeyPtr).add((short) 0, KMByteBlob.instance(kEcPrivKey,
        (short) 0, (short) kEcPrivKey.length));
    KMArray.cast(signKeyPtr).add((short) 1, KMByteBlob.instance(kEcPubKey,
        (short) 0, (short) kEcPubKey.length));
    byte[] keyBuf = new byte[120];
    short len = encoder.encode(signKeyPtr, keyBuf, (short) 0);
    short signKeyBstr = KMByteBlob.instance(keyBuf, (short) 0, len);

    short finalArrayPtr = KMArray.instance((short) 3);
    KMArray.cast(finalArrayPtr).add((short) 0, keyParams);
    KMArray.cast(finalArrayPtr).add((short) 1, keyFormatPtr);
    KMArray.cast(finalArrayPtr).add((short) 2, signKeyBstr);

    CommandAPDU apdu = encodeApdu((byte) INS_PROVISION_ATTESTATION_KEY_CMD,
        finalArrayPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void provisionCertificateParams(CardSimulator simulator) {

    short arrPtr = KMArray.instance((short) 2);
    short byteBlob1 = KMByteBlob.instance(X509Issuer, (short) 0,
        (short) X509Issuer.length);
    KMArray.cast(arrPtr).add((short) 0, byteBlob1);
    short byteBlob2 = KMByteBlob.instance(expiryTime, (short) 0,
        (short) expiryTime.length);
    KMArray.cast(arrPtr).add((short) 1, byteBlob2);

    CommandAPDU apdu = encodeApdu(
        (byte) INS_PROVISION_ATTESTATION_CERT_PARAMS_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void provisionSharedSecret(CardSimulator simulator) {
    byte[] sharedKeySecret = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0};
    short arrPtr = KMArray.instance((short) 1);
    short byteBlob = KMByteBlob.instance(sharedKeySecret, (short) 0,
        (short) sharedKeySecret.length);
    KMArray.cast(arrPtr).add((short) 0, byteBlob);

    CommandAPDU apdu = encodeApdu((byte) INS_PROVISION_PRESHARED_SECRET_CMD,
        arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void provisionAttestIds(CardSimulator simulator) {
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
    CommandAPDU apdu = encodeApdu((byte) INS_PROVISION_ATTEST_IDS_CMD,
        outerArrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void provisionLocked(CardSimulator simulator) {
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_LOCK_PROVISIONING_CMD,
        0x40, 0x00);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private void provisionCmd(CardSimulator simulator) {
    provisionSigningKey(simulator);
    provisionSigningCertificate(simulator);
    provisionCertificateParams(simulator);
    provisionSharedSecret(simulator);
    provisionAttestIds(simulator);
    // set bootup parameters
    setBootParams(simulator, (short) OS_VERSION, (short) OS_PATCH_LEVEL,
            (short) VENDOR_PATCH_LEVEL, (short) BOOT_PATCH_LEVEL);
    provisionLocked(simulator);
  }

  private void cleanUp() {
    AID appletAID = AIDUtil.create("A000000062");
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID);
  }


  private CommandAPDU encodeApdu(byte ins, short cmd) {
    byte[] buf = new byte[2500];
    buf[0] = (byte) 0x80;
    buf[1] = ins;
    buf[2] = (byte) 0x40;
    buf[3] = (byte) 0x00;
    buf[4] = 0;
    short len = encoder.encode(cmd, buf, (short) 7);
    Util.setShort(buf, (short) 5, len);
    byte[] apdu = new byte[7 + len];
    Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0, (short) (7 + len));
    //CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x10, 0x40, 0x00, buf, 0, actualLen);
    return new CommandAPDU(apdu);
  }

  @Test
  public void testAesImportKeySuccess() {
    init();
    byte[] aesKeySecret = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    short arrPtr = KMArray.instance((short) 5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ECB);
    short blockMode = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PKCS7);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, blockMode);
    KMArray.cast(arrPtr).add((short) 3, paddingMode);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short keyBlob = KMArray.instance((short) 1);
    KMArray.cast(keyBlob).add((short) 0, KMByteBlob.instance(aesKeySecret, (short) 0, (short) 16));
    byte[] blob = new byte[256];
    short len = encoder.encode(keyBlob, blob, (short) 0);
    keyBlob = KMByteBlob.instance(blob, (short) 0, len);
    arrPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short) 1, keyFormatPtr);
    arg.add((short) 2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte) INS_IMPORT_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PKCS7));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.ECB));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.AES);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testHmacImportKeySuccess() {
    init();
    byte[] hmacKeySecret = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    short arrPtr = KMArray.instance((short) 5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short minMacLength = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short) 256));
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, digest);
    KMArray.cast(arrPtr).add((short) 3, minMacLength);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short keyBlob = KMArray.instance((short) 1);
    KMArray.cast(keyBlob).add((short) 0, KMByteBlob.instance(hmacKeySecret, (short) 0, (short) 16));
    byte[] blob = new byte[256];
    short len = encoder.encode(keyBlob, blob, (short) 0);
    keyBlob = KMByteBlob.instance(blob, (short) 0, len);
    arrPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short) 1, keyFormatPtr);
    arg.add((short) 2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte) INS_IMPORT_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.HMAC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testRsaImportKeySuccess() {
    init();
    byte[] pub = new byte[]{0x00, 0x01, 0x00, 0x01};
    byte[] mod = new byte[256];
    byte[] priv = new byte[256];
    short[] lengths = new short[2];
    cryptoProvider
        .createAsymmetricKey(KMType.RSA, priv, (short) 0, (short) 256, mod, (short) 0, (short) 256,
            lengths);
    short arrPtr = KMArray.instance((short) 6);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 2048));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
        KMInteger.uint_32(pub, (short) 0));
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.RSA_PSS);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, digest);
    KMArray.cast(arrPtr).add((short) 3, rsaPubExpTag);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add((short) 5, padding);
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);// Note: VTS uses PKCS8
    short keyBlob = KMArray.instance((short) 2);
    KMArray.cast(keyBlob).add((short) 0, KMByteBlob.instance(priv, (short) 0, (short) 256));
    KMArray.cast(keyBlob).add((short) 1, KMByteBlob.instance(mod, (short) 0, (short) 256));
    byte[] blob = new byte[620];
    short len = encoder.encode(keyBlob, blob, (short) 0);
    keyBlob = KMByteBlob.instance(blob, (short) 0, len);
    arrPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short) 1, keyFormatPtr);
    arg.add((short) 2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte) INS_IMPORT_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 2048);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.RSA_PSS));
    tag = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getSignificantShort(),
        0x01);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 0x01);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.RSA);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testDeviceLocked() {
    init();
    byte[] hmacKey = new byte[32];
    cryptoProvider.newRandomNumber(hmacKey, (short) 0, (short) 32);
    KMRepository.instance().initComputedHmac(hmacKey, (short) 0, (short) 32);
    // generate aes key with unlocked_device_required
    short aesKey = generateAesDesKey(KMType.AES, (short) 128, null, null, true);
    short keyBlobPtr = KMArray.cast(aesKey).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    // encrypt something
    short inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    byte[] plainData = "Hello World 123!".getBytes();
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.ENCRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, false, false
    );
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        cipherData, (short) 0, (short) cipherData.length);
    // create verification token
    short verToken = KMVerificationToken.instance();
    KMVerificationToken.cast(verToken).setTimestamp(KMInteger.uint_16((short) 1));
    verToken = signVerificationToken(verToken);
    // device locked request
    deviceLock(verToken);
    // decrypt should fail
    inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    short beginResp = begin(KMType.DECRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(inParams), (short) 0);
    Assert.assertEquals(beginResp, KMError.DEVICE_LOCKED);
    short hwToken = KMHardwareAuthToken.instance();
    KMHardwareAuthToken.cast(hwToken).setTimestamp(KMInteger.uint_16((byte) 2));
    KMHardwareAuthToken.cast(hwToken)
        .setHwAuthenticatorType(KMEnum.instance(KMType.USER_AUTH_TYPE, (byte) KMType.PASSWORD));
    inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    hwToken = signHwToken(hwToken);
    ret = processMessage(cipherData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.DECRYPT,
        KMKeyParameters.instance(inParams), hwToken, null, false, false
    );
    ret = KMArray.cast(ret).get((short) 0);
    Assert.assertEquals(KMInteger.cast(ret).getShort(), KMError.OK);
    cleanUp();
  }

  private short signHwToken(short hwToken) {
    short len = 0;
    byte[] scratchPad = new byte[256];
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    short ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
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
/*    HMACKey key =
      cryptoProvider.createHMACKey(
        KMRepository.instance().getComputedHmacKey(),
        (short) 0,
        (short) KMRepository.instance().getComputedHmacKey().length);

 */
    byte[] mac = new byte[32];
    /*
    len =
      cryptoProvider.hmacSign(key, scratchPad, (short) 0, len,
        mac,
        (short)0);
     */
    short key = KMRepository.instance().getComputedHmacKey();
    cryptoProvider.hmacSign(
        KMByteBlob.cast(key).getBuffer(),
        KMByteBlob.cast(key).getStartOff(),
        KMByteBlob.cast(key).length(),
        scratchPad, (short) 0, len,
        mac,
        (short) 0);
    KMHardwareAuthToken.cast(hwToken)
        .setMac(KMByteBlob.instance(mac, (short) 0, (short) mac.length));
    return hwToken;
  }

  private void deviceLock(short verToken) {
    short req = KMArray.instance((short) 2);
    KMArray.cast(req).add((short) 0, KMInteger.uint_8((byte) 1));
    KMArray.cast(req).add((short) 1, verToken);
    CommandAPDU apdu = encodeApdu((byte) INS_DEVICE_LOCKED_CMD, req);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 1);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(respBuf[0], KMError.OK);
  }

  private short signVerificationToken(short verToken) {
    byte[] scratchPad = new byte[256];
    byte[] authVer = "Auth Verification".getBytes();
    //print(authVer,(short)0,(short)authVer.length);
    // concatenation length will be 37 + length of verified parameters list  - which is typically empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    short params = KMVerificationToken.cast(verToken).getParametersVerified();
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopy(authVer, (short) 0, scratchPad, (short) 0, (short) authVer.length);
    short len = (short) authVer.length;
    // concatenate challenge - 8 bytes
    short ptr = KMVerificationToken.cast(verToken).getChallenge();
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
   /* HMACKey key =
      cryptoProvider.createHMACKey(
        KMRepository.instance().getComputedHmacKey(),
        (short) 0,
        (short) KMRepository.instance().getComputedHmacKey().length);

    */
    ptr = KMVerificationToken.cast(verToken).getMac();
    byte[] mac = new byte[32];
    /*len =
      cryptoProvider.hmacSign(key, scratchPad, (short) 0, len,
        mac,
        (short)0);
     */
    short key = KMRepository.instance().getComputedHmacKey();
    cryptoProvider.hmacSign(KMByteBlob.cast(key).getBuffer(),
        KMByteBlob.cast(key).getStartOff(),
        KMByteBlob.cast(key).length(),
        scratchPad, (short) 0, len,
        mac,
        (short) 0);
    KMVerificationToken.cast(verToken)
        .setMac(KMByteBlob.instance(mac, (short) 0, (short) mac.length));
    return verToken;
  }

  @Test
  public void testEcImportKeySuccess() {
    init();
    byte[] pub = new byte[128];
    byte[] priv = new byte[128];
    short[] lengths = new short[2];
    cryptoProvider
        .createAsymmetricKey(KMType.EC, priv, (short) 0, (short) 128, pub, (short) 0, (short) 128,
            lengths);
    short pubBlob = KMByteBlob.instance(pub, (short) 0, lengths[1]);
    short privBlob = KMByteBlob.instance(priv, (short) 0, lengths[0]);
    short arrPtr = KMArray.instance((short) 5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 256));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, digest);
    KMArray.cast(arrPtr).add((short) 3, ecCurve);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);// Note: VTS uses PKCS8
    short keyBlob = KMArray.instance((short) 2);
    KMArray.cast(keyBlob).add((short) 0, privBlob);
    KMArray.cast(keyBlob).add((short) 1, pubBlob);
    byte[] blob = new byte[128];
    short len = encoder.encode(keyBlob, blob, (short) 0);
    keyBlob = KMByteBlob.instance(blob, (short) 0, len);
    arrPtr = KMArray.instance((short) 3);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short) 1, keyFormatPtr);
    arg.add((short) 2, keyBlob);
    CommandAPDU apdu = encodeApdu((byte) INS_IMPORT_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short blobArr = extractKeyBlobArray(KMArray.cast(ret).get((short) 1));
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ECCURVE, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.P_256);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.EC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  private short extractKeyBlobArray(byte[] buf, short off, short buflen) {
    short ret = KMArray.instance((short) 5);
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    short ptr = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR, ptr);
    KMArray.cast(ret).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    ret =
        decoder.decodeArray(
            ret,
            buf, off, buflen);
    short len = KMArray.cast(ret).length();
    ptr = KMArray.cast(ret).get((short) 4);
//    print(KMByteBlob.cast(ptr).getBuffer(),KMByteBlob.cast(ptr).getStartOff(),KMByteBlob.cast(ptr).length());
    return ret;
  }

  private short extractKeyBlobArray(short keyBlob) {
    return extractKeyBlobArray(KMByteBlob.cast(keyBlob).getBuffer(), KMByteBlob
        .cast(keyBlob).getStartOff(), KMByteBlob.cast(keyBlob).length());
  }

  @Test
  public void testRsaGenerateKeySuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 2048);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.DIGEST_NONE));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.RSA_PKCS1_1_5_ENCRYPT));
    tag = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getSignificantShort(),
        0x01);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 0x01);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.RSA);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  private short generateRsaKey(byte[] clientId, byte[] appData) {
    byte[] activeAndCreationDateTime = {0, 0, 0x01, 0x73, 0x51, 0x7C, (byte) 0xCC, 0x00};
    short tagCount = 11;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 2048));
    short byteBlob = KMByteBlob.instance((short) 3);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.SHA2_256);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.SHA1);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 5);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.RSA_PKCS1_1_5_ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.RSA_PKCS1_1_5_SIGN);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.RSA_OAEP);
    KMByteBlob.cast(byteBlob).add((short) 3, KMType.RSA_PSS);
    KMByteBlob.cast(byteBlob).add((short) 4, KMType.PADDING_NONE);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 5);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.VERIFY);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 3, KMType.DECRYPT);
    KMByteBlob.cast(byteBlob).add((short) 4, KMType.WRAP_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    byte[] pub = {0, 1, 0, 1};
    short rsaPubExpTag = KMIntegerTag
        .instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short) 0));
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.INCLUDE_UNIQUE_ID));
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.RESET_SINCE_ID_ROTATION));
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add(tagIndex++, padding);
    short dateTag = KMInteger.uint_64(activeAndCreationDateTime, (short) 0);
    KMArray.cast(arrPtr)
        .add(tagIndex++, KMIntegerTag.instance(KMType.DATE_TAG, KMType.ACTIVE_DATETIME, dateTag));
    KMArray.cast(arrPtr)
        .add(tagIndex++, KMIntegerTag.instance(KMType.DATE_TAG, KMType.CREATION_DATETIME, dateTag));

    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  private short generateAttestationKey() {
    // 15th July 2020 00.00.00
    byte[] activeAndCreationDateTime = {0, 0, 0x01, 0x73, 0x51, 0x7C, (byte) 0xCC, 0x00};
    short tagCount = 11;
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 2048));
    short byteBlob = KMByteBlob.instance((short) 3);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.SHA2_256);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.SHA1);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.RSA_PKCS1_1_5_SIGN);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ATTEST_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    byte[] pub = {0, 1, 0, 1};
    short rsaPubExpTag = KMIntegerTag
        .instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short) 0));
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.INCLUDE_UNIQUE_ID));
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.RESET_SINCE_ID_ROTATION));
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add(tagIndex++, padding);
    short dateTag = KMInteger.uint_64(activeAndCreationDateTime, (short) 0);
    KMArray.cast(arrPtr)
        .add(tagIndex++, KMIntegerTag.instance(KMType.ULONG_TAG, KMType.ACTIVE_DATETIME, dateTag));
    KMArray.cast(arrPtr).add(tagIndex++,
        KMIntegerTag.instance(KMType.ULONG_TAG, KMType.CREATION_DATETIME, dateTag));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  @Test
  public void testEcGenerateKeySuccess() {
    init();
    short ret = generateEcKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.DIGEST_NONE));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.EC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  public short generateEcKey(byte[] clientId, byte[] appData) {
    byte[] activeAndCreationDateTime = {0, 0, 0x01, 0x73, 0x51, 0x7C, (byte) 0xCC, 0x00};
    short tagCount = 6;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 256));
    short byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    short dateTag = KMInteger.uint_64(activeAndCreationDateTime, (short) 0);
    KMArray.cast(arrPtr)
        .add(tagIndex++, KMIntegerTag.instance(KMType.DATE_TAG, KMType.CREATION_DATETIME, dateTag));
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    return ret;
  }

  @Test
  public void testHmacGenerateKeySuccess() {
    init();
    short ret = generateHmacKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 160);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.HMAC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  public short generateHmacKey(byte[] clientId, byte[] appData) {
    short tagCount = 6;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short minMacLen = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)/*256*/160));
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, minMacLen);
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }

  public short generateAesDesKey(byte alg, short keysize, byte[] clientId, byte[] appData,
      boolean unlockReqd) {
    short tagCount = 7;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    if (unlockReqd) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
    short byteBlob = KMByteBlob.instance((short) 3);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ECB);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.CBC);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.CTR);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PKCS7);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, alg));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    if (unlockReqd) {
      KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.UNLOCKED_DEVICE_REQUIRED));
    }
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }

  public short generateAesGcmKey(short keysize, byte[] clientId, byte[] appData) {
    short tagCount = 8;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
    short macLength = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short) 96));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.GCM);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, macLength);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = KMArray.instance((short) 1);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    return ret;
  }

  @Test
  public void testComputeHmacParams() {
    init();
    // Get Hmac parameters
    short ret = getHmacSharingParams();
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
    CommandAPDU apdu = encodeApdu((byte) INS_COMPUTE_SHARED_HMAC_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);

    cleanUp();
  }

  @Test
  public void testGetHmacSharingParams() {
    init();
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_GET_HMAC_SHARING_PARAM_CMD, 0x40, 0x00);
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
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    KMHmacSharingParameters params = KMHmacSharingParameters.cast(KMArray.cast(ret).get((short) 1));
    short seed = params.getSeed();
    short nonce = params.getNonce();
    Assert.assertTrue(KMByteBlob.cast(seed).length() == 0);
    Assert.assertTrue(KMByteBlob.cast(nonce).length() == 32);
    //print(seed);
    //print(nonce);
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  public short getHmacSharingParams() {
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_GET_HMAC_SHARING_PARAM_CMD, 0x40, 0x00);
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

  @Test
  public void testImportWrappedKey() {
    init();
    byte[] wrappedKey = new byte[16];
    cryptoProvider.newRandomNumber(wrappedKey, (short) 0, (short) 16);
    byte[] encWrappedKey = new byte[16];
    byte[] transportKeyMaterial = new byte[32];
    cryptoProvider.newRandomNumber(transportKeyMaterial, (short) 0, (short) 32);
    byte[] nonce = new byte[12];
    cryptoProvider.newRandomNumber(nonce, (short) 0, (short) 12);
    byte[] authData = "Auth Data".getBytes();
    byte[] authTag = new byte[16];
    cryptoProvider.aesGCMEncrypt(transportKeyMaterial, (short) 0, (short) 32, wrappedKey,
        (short) 0, (short) 16, encWrappedKey, (short) 0,
        nonce, (short) 0, (short) 12, authData, (short) 0, (short) authData.length,
        authTag, (short) 0, (short) 16);
    byte[] maskingKey = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
        0, 1, 0, 1, 0, 1, 0};
    byte[] maskedTransportKey = new byte[32];
    for (int i = 0; i < maskingKey.length; i++) {
      maskedTransportKey[i] = (byte) (transportKeyMaterial[i] ^ maskingKey[i]);
    }
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] wrappingKeyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        wrappingKeyBlob, (short) 0, (short) wrappingKeyBlob.length);

    byte[] output = new byte[256];
    short outlen = rsaOaepEncryptMessage(wrappingKeyBlob, KMType.SHA2_256,
        maskedTransportKey, (short) 0, (short) maskedTransportKey.length,
        output, (short) 0);
    Assert.assertTrue((outlen == 256));
    byte[] encTransportKey = new byte[outlen];
    Util.arrayCopyNonAtomic(output, (short) 0, encTransportKey, (short) 0,
        outlen);
    //Clean the heap.
    KMRepository.instance().clean();
    short tagCount = 7;
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ECB);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.CBC);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PKCS7);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short nullParams = KMArray.instance((short) 0);
    nullParams = KMKeyParameters.instance(nullParams);
    short arr = KMArray.instance((short) 12);
    KMArray.cast(arr).add((short) 0, keyParams); // Key Params of wrapped key
    KMArray.cast(arr).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW)); // Key Format
    KMArray.cast(arr).add((short) 2, KMByteBlob.instance(encWrappedKey, (short) 0,
        (short) encWrappedKey.length)); // Wrapped Import Key Blob
    KMArray.cast(arr).add((short) 3,
        KMByteBlob.instance(authTag, (short) 0, (short) authTag.length)); // Auth Tag
    KMArray.cast(arr)
        .add((short) 4, KMByteBlob.instance(nonce, (short) 0, (short) nonce.length)); // IV - Nonce
    KMArray.cast(arr).add((short) 5, KMByteBlob.instance(encTransportKey, (short) 0,
        (short) encTransportKey.length)); // Encrypted Transport Key
    KMArray.cast(arr).add((short) 6, KMByteBlob.instance(wrappingKeyBlob, (short) 0,
        (short) wrappingKeyBlob.length)); // Wrapping Key KeyBlob
    KMArray.cast(arr).add((short) 7,
        KMByteBlob.instance(maskingKey, (short) 0, (short) maskingKey.length)); // Masking Key
    KMArray.cast(arr).add((short) 8, nullParams); // Un-wrapping Params
    KMArray.cast(arr).add((short) 9, KMByteBlob.instance(authData, (short) 0,
        (short) authData.length)); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.cast(arr).add((short) 10, KMInteger.uint_8((byte) 0)); // Password Sid
    KMArray.cast(arr).add((short) 11, KMInteger.uint_8((byte) 0)); // Biometric Sid
    CommandAPDU apdu = encodeApdu((byte) INS_IMPORT_WRAPPED_KEY_CMD, arr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, hwParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, hwParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PKCS7));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, hwParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.ECB));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.AES);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.SECURELY_IMPORTED);
    cleanUp();
  }

  @Test
  public void testGetKeyCharacteristicsWithIdDataSuccess() {
    init();
    byte[] clientId = "clientId".getBytes();
    byte[] appData = "appData".getBytes();
    short ret = generateRsaKey(clientId, appData);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    short keyBlob = KMArray.cast(ret).get((short) 1);

    short arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    KMArray.cast(arrPtr)
        .add((short) 1, KMByteBlob.instance(clientId, (short) 0, (short) clientId.length));
    KMArray.cast(arrPtr)
        .add((short) 2, KMByteBlob.instance(appData, (short) 0, (short) appData.length));
    CommandAPDU apdu = encodeApdu((byte) INS_GET_KEY_CHARACTERISTICS_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  @Test
  public void testGetKeyCharacteristicsSuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    short keyBlob = KMArray.cast(ret).get((short) 1);

    short arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    KMArray.cast(arrPtr).add((short) 1, KMByteBlob.instance((short) 0));
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.instance((short) 0));
    CommandAPDU apdu = encodeApdu((byte) INS_GET_KEY_CHARACTERISTICS_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  @Test
  public void testDeleteKeySuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    short len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob, (short) 0);
    ret = getKeyCharacteristics(keyBlobPtr);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    ret = deleteKey(KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length));
    Assert.assertEquals(ret, KMError.OK);
    cleanUp();
  }

  @Test
  public void testDeleteAllKeySuccess() {
    init();
    short ret1 = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(ret1).get((short) 1);
    byte[] keyBlob1 = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    short len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob1, (short) 0);
    short ret2 = generateRsaKey(null, null);
    keyBlobPtr = KMArray.cast(ret2).get((short) 1);
    byte[] keyBlob2 = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob2, (short) 0);
    CommandAPDU apdu = new CommandAPDU(0x80, INS_DELETE_ALL_KEYS_CMD, 0x40, 0x00);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(respBuf[0], KMError.OK);
    cleanUp();
  }

  private short deleteKey(short keyBlob) {
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    CommandAPDU apdu = encodeApdu((byte) INS_DELETE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    return respBuf[0];
  }

  private short abort(short opHandle) {
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, opHandle);
    CommandAPDU apdu = encodeApdu((byte) INS_ABORT_OPERATION_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    return respBuf[0];
  }

  public short getKeyCharacteristics(short keyBlob) {
    short arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    KMArray.cast(arrPtr).add((short) 1, KMByteBlob.instance((short) 0));
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.instance((short) 0));
    CommandAPDU apdu = encodeApdu((byte) INS_GET_KEY_CHARACTERISTICS_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if (len > 5) {
      ret = decoder.decode(ret, respBuf, (short) 0, len);
    } else {
      ret = KMByteBlob.instance(respBuf, (short) 0, len);
    }
    return ret;
  }

  @Test
  public void testWithAesGcmWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.GCM, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesEcbPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithAesCtrNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CTR, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesCtrNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CTR, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithAesEcbNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithDesEcbPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithDesEcbNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesCbcPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithAesCbcNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithDesCbcPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithDesCbcNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesEcbPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithAesCbcPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithAesEcbNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithAesCbcNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithDesCbcPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithDesCbcNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithDesEcbNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithDesEcbPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithRsa256Oaep() {
    init();
    testEncryptDecryptWithRsa(KMType.SHA2_256, KMType.RSA_OAEP);
    cleanUp();
  }

  @Test
  public void testWithRsaSha1Oaep() {
    init();
    testEncryptDecryptWithRsa(KMType.SHA1, KMType.RSA_OAEP);
    cleanUp();
  }

  @Test
  public void testWithRsaNonePkcs1() {
    init();
    testEncryptDecryptWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_ENCRYPT);
    cleanUp();
  }

  @Test
  public void testWithRsaNoneNoPad() {
    init();
    testEncryptDecryptWithRsa(KMType.DIGEST_NONE, KMType.PADDING_NONE);
    cleanUp();
  }

  // TODO Signing with no digest is not supported by crypto provider or javacard
  @Test
  public void testSignWithRsaNoneNoPad() {
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.PADDING_NONE, false, false);
    cleanUp();
  }

  @Test
  public void testSignWithRsaNonePkcs1() {
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_SIGN, false, false);
    cleanUp();
  }

  public short getPublicKey(byte[] keyBlob, short off, short len,
      byte[] pubKey, short pubKeyOff) {
    short keyBlobPtr = extractKeyBlobArray(keyBlob, off, len);
    short arrayLen = KMArray.cast(keyBlobPtr).length();
    if (arrayLen < 5) {
      return 0;
    }
    short pubKeyPtr = KMArray.cast(keyBlobPtr).get(
        KMKeymasterApplet.KEY_BLOB_PUB_KEY);
    Util.arrayCopy(KMByteBlob.cast(pubKeyPtr).getBuffer(),
        KMByteBlob.cast(pubKeyPtr).getStartOff(), pubKey, pubKeyOff,
        KMByteBlob.cast(pubKeyPtr).length());
    return KMByteBlob.cast(pubKeyPtr).length();
  }

  private String toHexString(byte[] num) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < num.length; i++) {
      sb.append(String.format("%02X", num[i]));
    }
    return sb.toString();
  }

  public short rsaEncryptMessage(byte[] keyBlob, short padding, short digest, byte[] input,
      short inputOff, short inputlen,
      byte[] output, short outputOff) {
    byte alg = Cipher.ALG_RSA_PKCS1;
    byte[] tmp = null;
    short inLen = inputlen;
    if (padding == KMType.PADDING_NONE) {
      alg = Cipher.ALG_RSA_NOPAD;
      // Length cannot be greater then key size according to JcardSim
      if (inLen >= 256) {
        return 0;
      }
      // make input equal to 255 bytes
      tmp = new byte[255];
      Util.arrayFillNonAtomic(tmp, (short) 0, (short) 255, (byte) 0);
      Util.arrayCopyNonAtomic(
          input,
          inputOff,
          tmp, (short) (255 - inLen), inLen);
      inLen = 255;
      inputOff = 0;
    } else if (padding == KMType.RSA_PKCS1_1_5_ENCRYPT) {
      tmp = input;
    } else {
      /*Fail */
      Assert.assertTrue(false);
    }
    byte[] pubKey = new byte[256];
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    RSAPublicKey rsaPubKey = (RSAPublicKey) rsaKeyPair.getPublic();
    if (0 == getPublicKey(keyBlob, (short) 0, (short) keyBlob.length, pubKey, (short) 0)) {
      return 0;
    }

    byte[] exponent = new byte[]{0x01, 0x00, 0x01};
    rsaPubKey.setModulus(pubKey, (short) 0, (short) pubKey.length);
    rsaPubKey.setExponent(exponent, (short) 0, (short) exponent.length);

    Cipher rsaCipher = Cipher.getInstance(alg, false);
    rsaCipher.init(rsaPubKey, Cipher.MODE_ENCRYPT);
    return rsaCipher.doFinal(tmp, inputOff, inLen, output, outputOff);
  }

  public short rsaOaepEncryptMessage(byte[] keyBlob, short digest, byte[] input, short inputOff,
      short inputlen,
      byte[] output, short outputOff) {
    byte[] mod = new byte[256];
    if (0 == getPublicKey(keyBlob, (short) 0, (short) keyBlob.length, mod, (short) 0)) {
      return 0;
    }
    byte[] exponent = new byte[]{0x01, 0x00, 0x01};

    // Convert byte arrays into keys
    String modString = toHexString(mod);
    String expString = toHexString(exponent);
    BigInteger modInt = new BigInteger(modString, 16);
    BigInteger expInt = new BigInteger(expString, 16);
    javax.crypto.Cipher rsaCipher = null;
    try {
      KeyFactory kf = KeyFactory.getInstance("RSA");
      // Create cipher with oaep padding
      OAEPParameterSpec oaepSpec = null;
      if (digest == KMType.SHA2_256) {
        oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
      } else {
        oaepSpec = new OAEPParameterSpec("SHA1", "MGF1",
            MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
      }
      rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding", "SunJCE");

      RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modInt, expInt);
      java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey) kf
          .generatePublic(pubSpec);
      rsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pubKey, oaepSpec);
      byte[] cipherOut = rsaCipher.doFinal(input, inputOff, inputlen);

      if (cipherOut != null) {
        Util.arrayCopyNonAtomic(cipherOut, (short) 0, output, outputOff, (short) cipherOut.length);
      }
      return (short) cipherOut.length;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    }
    return 0;
  }

  public boolean ecNoDigestVerifyMessage(byte[] input, short inputOff,
      short inputlen, byte[] sign, short signOff, short signLen,
      byte[] keyBlob) {
    KeyFactory kf;
    byte[] pubKey = new byte[128];
    short keyStart = 0;
    short keyLength = getPublicKey(keyBlob, (short) 0, (short) keyBlob.length,
        pubKey, (short) 0);
    if (keyLength == 0) {
      return false;
    }
    try {
      java.security.Signature sunSigner = java.security.Signature.getInstance(
          "NONEwithECDSA", "SunEC");
      kf = KeyFactory.getInstance("EC");
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC",
          "SunEC");
      // Supported curve secp256r1
      parameters.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecParameters = parameters
          .getParameterSpec(ECParameterSpec.class);

      // Check if the first byte is 04 and remove it.
      if (pubKey[keyStart] == 0x04) {
        // uncompressed format.
        keyStart++;
        keyLength--;
      }
      short i = 0;
      byte[] pubx = new byte[keyLength / 2];
      for (; i < keyLength / 2; i++) {
        pubx[i] = pubKey[keyStart + i];
      }
      byte[] puby = new byte[keyLength / 2];
      for (i = 0; i < keyLength / 2; i++) {
        puby[i] = pubKey[keyStart + keyLength / 2 + i];
      }
      BigInteger bIX = new BigInteger(pubx);
      BigInteger bIY = new BigInteger(puby);
      ECPoint point = new ECPoint(bIX, bIY);
      ECPublicKeySpec pubkeyspec = new ECPublicKeySpec(point, ecParameters);
      java.security.interfaces.ECPublicKey ecPubkey = (java.security.interfaces.ECPublicKey) kf
          .generatePublic(pubkeyspec);
      sunSigner.initVerify(ecPubkey);
      sunSigner.update(input, inputOff, inputlen);
      return sunSigner.verify(sign, signOff, signLen);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    } catch (InvalidParameterSpecException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (SignatureException e) {
      e.printStackTrace();
    }
    return false;
  }

  public boolean ecVerifyMessage(byte[] input, short inputOff, short inputlen,
      byte[] sign, short signOff, short signLen, byte[] keyBlob) {
    Signature ecVerifier;
    byte[] pubKey = new byte[128];
    short len = getPublicKey(keyBlob, (short) 0, (short) keyBlob.length,
        pubKey, (short) 0);
    if (len == 0) {
      return false;
    }
    ECPublicKey key = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setW(pubKey, (short) 0, len);
    ecVerifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    ecVerifier.init(key, Signature.MODE_VERIFY);
    return ecVerifier.verify(input, inputOff, inputlen, sign, signOff, signLen);
  }

  public boolean rsaVerifyMessage(byte[] input, short inputOff, short inputlen, byte[] sign,
      short signOff, short signLen,
      short digest, short padding, byte[] keyBlob) {
    if (digest == KMType.DIGEST_NONE || padding == KMType.PADDING_NONE) {
      return false;
    }
    byte[] pubKey = new byte[256];
    if (0 == getPublicKey(keyBlob, (short) 0, (short) keyBlob.length, pubKey, (short) 0)) {
      return false;
    }
    short alg = Signature.ALG_RSA_SHA_256_PKCS1_PSS;

    if (padding == KMType.RSA_PKCS1_1_5_SIGN) {
      alg = Signature.ALG_RSA_SHA_256_PKCS1;
    }

    Signature rsaVerifier = Signature.getInstance((byte) alg, false);
    RSAPublicKey key = (RSAPublicKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
    byte[] exponent = new byte[]{0x01, 0x00, 0x01};
    key.setExponent(exponent, (short) 0, (short) exponent.length);
    key.setModulus(pubKey, (short) 0, (short) pubKey.length);
    rsaVerifier.init(key, Signature.MODE_VERIFY);
    return rsaVerifier.verify(input, inputOff, inputlen, sign, signOff, signLen);
  }

  public byte[] EncryptMessage(byte[] input, short params, byte[] keyBlob) {
    short ret = begin(KMType.ENCRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(params), (short) 0);
    // Get the operation handle.
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMRepository.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
        (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

    ret = finish(opHandle,
        KMByteBlob.instance(input, (short) 0, (short) input.length), null,
        (short) 0, (short) 0, (short) 0, KMError.OK);
    short dataPtr = KMArray.cast(ret).get((short) 2);
    byte[] output = new byte[KMByteBlob.cast(dataPtr).length()];
    if (KMByteBlob.cast(dataPtr).length() > 0) {
      Util.arrayCopyNonAtomic(KMByteBlob.cast(dataPtr).getBuffer(), KMByteBlob
              .cast(dataPtr).getStartOff(), output, (short) 0,
          KMByteBlob.cast(dataPtr).length());
    }
    return output;
  }

  public byte[] DecryptMessage(byte[] input, short params, byte[] keyBlob) {
    short ret = begin(KMType.DECRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(params), (short) 0);
    // Get the operation handle.
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMRepository.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
        (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

    ret = finish(opHandle,
        KMByteBlob.instance(input, (short) 0, (short) input.length), null,
        (short) 0, (short) 0, (short) 0, KMError.OK);
    short dataPtr = KMArray.cast(ret).get((short) 2);
    byte[] output = new byte[KMByteBlob.cast(dataPtr).length()];
    if (KMByteBlob.cast(dataPtr).length() > 0) {
      Util.arrayCopyNonAtomic(KMByteBlob.cast(dataPtr).getBuffer(), KMByteBlob
              .cast(dataPtr).getStartOff(), output, (short) 0,
          KMByteBlob.cast(dataPtr).length());
    }
    return output;
  }

  public short generateRandom(short upperBound) {
    Random rand = new Random();
    short int_random = (short) rand.nextInt(upperBound);
    return int_random;
  }

  @Test
  public void testUnsupportedBlockMode() {
    init();
    short desKey = generateAesDesKey(KMType.DES, (short) 168, null, null, false);
    short desKeyPtr = KMArray.cast(desKey).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(desKeyPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(desKeyPtr).getBuffer(), KMByteBlob
            .cast(desKeyPtr).getStartOff(), keyBlob, (short) 0,
            (short) keyBlob.length);
    short desPkcs7Params = getAesDesParams(KMType.DES, (byte) KMType.CTR,
            KMType.PKCS7, new byte[12]);
    short ret = begin(KMType.ENCRYPT,
            KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
            KMKeyParameters.instance(desPkcs7Params), (short) 0);
    Assert.assertTrue(ret == KMError.UNSUPPORTED_BLOCK_MODE);
    cleanUp();
  }

  @Test
  public void testDesEcbPkcs7PaddingCorrupted() {
    init();
    short desKey = generateAesDesKey(KMType.DES, (short) 168, null, null, false);
    short desKeyPtr = KMArray.cast(desKey).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(desKeyPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(desKeyPtr).getBuffer(), KMByteBlob
            .cast(desKeyPtr).getStartOff(), keyBlob, (short) 0,
        (short) keyBlob.length);

    byte[] message = {
        0x61};
    short desPkcs7Params = getAesDesParams(KMType.DES, KMType.ECB,
        KMType.PKCS7, null);
    byte[] cipherText1 = EncryptMessage(message, desPkcs7Params, keyBlob);
    Assert.assertEquals(8, cipherText1.length);
    Assert.assertFalse(Arrays.equals(message, cipherText1));

    // Corrupt the cipher text.
    ++cipherText1[(cipherText1.length / 2)];

    // Decrypt operation
    // Begin
    desPkcs7Params = getAesDesParams(KMType.DES, KMType.ECB, KMType.PKCS7, null);

    short ret = begin(KMType.DECRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(desPkcs7Params), (short) 0);
    // Get the operation handle.
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMRepository.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
        (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

    // Finish
    short dataPtr = KMByteBlob.instance(cipherText1, (short) 0,
        (short) cipherText1.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
    ret = finish(opHandle, dataPtr, null, (short) 0, (short) 0, (short) 0,
        KMError.INVALID_ARGUMENT);
    cleanUp();
  }

  @Test
  public void testVtsRsaPkcs1Success() {
    init();
    byte[] message = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
        0x21}; // "Hello World!";
    for (int i = 0; i < 250; i++) {
      short key = generateRsaKey(null, null);
      short rsaKeyPtr = KMArray.cast(key).get((short) 1);
      byte[] keyBlob = new byte[KMByteBlob.cast(rsaKeyPtr).length()];
      Util.arrayCopyNonAtomic(KMByteBlob.cast(rsaKeyPtr).getBuffer(),
          KMByteBlob.cast(rsaKeyPtr).getStartOff(), keyBlob, (short) 0,
          (short) keyBlob.length);
      short pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);

      byte[] cipherText1 = new byte[256];
      short cipherText1Len = rsaEncryptMessage(keyBlob, KMType.RSA_PKCS1_1_5_ENCRYPT,
          KMType.DIGEST_NONE,
          message, (short) 0, (short) message.length,
          cipherText1, (short) 0);
      Assert.assertEquals((2048 / 8), cipherText1Len);

      pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);
      byte[] cipherText2 = new byte[256];
      short cipherText2Len = rsaEncryptMessage(keyBlob, KMType.RSA_PKCS1_1_5_ENCRYPT,
          KMType.DIGEST_NONE,
          message, (short) 0, (short) message.length,
          cipherText2, (short) 0);
      Assert.assertEquals((2048 / 8), cipherText2Len);

      // PKCS1 v1.5 randomizes padding so every result should be different.
      Assert.assertFalse(Arrays.equals(cipherText1, cipherText2));

      pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);
      byte[] plainText = DecryptMessage(cipherText1, pkcs1Params, keyBlob);
      Assert.assertTrue(Arrays.equals(message, plainText));

      // Decrypting corrupted ciphertext should fail.
      short offset_to_corrupt = generateRandom((short) cipherText1.length);

      byte corrupt_byte;
      do {
        corrupt_byte = (byte) generateRandom((short) 256);
      } while (corrupt_byte == cipherText1[offset_to_corrupt]);
      cipherText1[offset_to_corrupt] = corrupt_byte;

      pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);
      // Do Begin operation.
      short ret = begin(KMType.DECRYPT,
          KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
          KMKeyParameters.instance(pkcs1Params), (short) 0);

      // Get the operation handle.
      short opHandle = KMArray.cast(ret).get((short) 2);
      byte[] opHandleBuf = new byte[KMRepository.OPERATION_HANDLE_SIZE];
      KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
          (short) opHandleBuf.length);
      opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

      short dataPtr = KMByteBlob.instance(cipherText1, (short) 0,
          (short) cipherText1.length);
      // Finish should return UNKNOWN_ERROR.
      ret = finish(opHandle, dataPtr, null, (short) 0, (short) 0, (short) 0,
          KMError.UNKNOWN_ERROR);
    }
    cleanUp();
  }

  @Test
  public void testSignVerifyWithHmacSHA256WithUpdate() {
    init();
    testSignVerifyWithHmac(KMType.SHA2_256, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithHmacSHA256() {
    init();
    testSignVerifyWithHmac(KMType.SHA2_256, false);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithEcdsaSHA256WithUpdate() {
    init();
    testSignVerifyWithEcdsa(KMType.SHA2_256, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithEcdsaSHA256() {
    init();
    testSignVerifyWithEcdsa(KMType.SHA2_256, false);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN, false, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithRsaSHA256Pss() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS, false, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1WithUpdate() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN, true, true);
    cleanUp();
  }

  @Test
  public void testProvisionSuccess() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    provisionCmd(simulator);
    cleanUp();
  }

  @Test
  public void testAttestRsaKey() {
    init();
    short key = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(key).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    testAttestKey(keyBlob);
    cleanUp();
  }

  @Test
  public void testAttestEcKey() {
    init();
    short key = generateEcKey(null, null);
    short keyBlobPtr = KMArray.cast(key).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    testAttestKey(keyBlob);
    cleanUp();
  }

  public void testAttestKey(byte[] keyBlob) {
    short arrPtr = KMArray.instance((short) 2);
    KMArray.cast(arrPtr).add((short) 0, KMByteTag.instance(KMType.ATTESTATION_APPLICATION_ID,
        KMByteBlob.instance(attAppId, (short) 0, (short) attAppId.length)));
    KMArray.cast(arrPtr).add((short) 1, KMByteTag.instance(KMType.ATTESTATION_CHALLENGE,
        KMByteBlob.instance(attChallenge, (short) 0, (short) attChallenge.length)));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short args = KMArray.instance((short) 2);
    KMArray.cast(args)
        .add((short) 0, KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length));
    KMArray.cast(args).add((short) 1, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_ATTEST_KEY_CMD, args);
    //print(apdu.getBytes(),(short)0,(short)apdu.getBytes().length);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 2);
    short arrBlobs = KMArray.instance((short) 1);
    KMArray.cast(arrBlobs).add((short) 0, KMByteBlob.exp());
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, arrBlobs);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    //(respBuf,(short)0,(short)respBuf.length);
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    arrBlobs = KMArray.cast(ret).get((short) 1);
    short cert = KMArray.cast(arrBlobs).get((short) 0);
    //printCert(KMByteBlob.cast(cert).getBuffer(),KMByteBlob.cast(cert).getStartOff(),KMByteBlob.cast(cert).length());
  }

  @Test
  public void testUpgradeKey() {
    init();
    short ret = generateHmacKey(null, null);
    short keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    short osVersion = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_VERSION, hwParams);
    osVersion = KMIntegerTag.cast(osVersion).getValue();
    short osPatch = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, hwParams);
    osPatch = KMIntegerTag.cast(osPatch).getValue();
    Assert.assertEquals(KMInteger.cast(osVersion).getShort(), 1);
    Assert.assertEquals(KMInteger.cast(osPatch).getShort(), 1);
    short NO_UPGRADE = 0x01;
    short UPGRADE = 0x02;
    short[][] test_data = {
            {OS_VERSION, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL, NO_UPGRADE, KMError.OK },
            {OS_VERSION+1, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL, UPGRADE,  KMError.OK },
            {OS_VERSION, OS_PATCH_LEVEL+1, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL, UPGRADE,  KMError.OK },
            {OS_VERSION, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL+1, BOOT_PATCH_LEVEL, UPGRADE,  KMError.OK },
            {OS_VERSION, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL+1, UPGRADE,  KMError.OK },
            {OS_VERSION+1, OS_PATCH_LEVEL+1, VENDOR_PATCH_LEVEL+1, BOOT_PATCH_LEVEL+1, UPGRADE,  KMError.OK },
            {OS_VERSION+1, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL+1, BOOT_PATCH_LEVEL, UPGRADE,  KMError.OK },
            {OS_VERSION+1, OS_PATCH_LEVEL+1, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL, UPGRADE,  KMError.OK },
            {OS_VERSION, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL-1, NO_UPGRADE,  KMError.INVALID_ARGUMENT },
            {OS_VERSION-1/*0*/, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL, BOOT_PATCH_LEVEL, UPGRADE,  KMError.OK },
            {OS_VERSION, OS_PATCH_LEVEL, VENDOR_PATCH_LEVEL-1, BOOT_PATCH_LEVEL, NO_UPGRADE,  KMError.INVALID_ARGUMENT },
            {OS_VERSION, OS_PATCH_LEVEL+1, VENDOR_PATCH_LEVEL-1, BOOT_PATCH_LEVEL, NO_UPGRADE,  KMError.INVALID_ARGUMENT },
            {0, OS_PATCH_LEVEL+1, VENDOR_PATCH_LEVEL-1, BOOT_PATCH_LEVEL+1, NO_UPGRADE,  KMError.INVALID_ARGUMENT },
    };
    for (int i = 0; i < test_data.length; i++) {
      setBootParams(simulator, (short) test_data[i][0], (short) test_data[i][1],
              (short) test_data[i][2], (short) test_data[i][3]);
      ret = upgradeKey(
              KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
              null, null, test_data[i][5]);
      if (test_data[i][5] != KMError.OK)
        continue;
      keyBlobPtr = KMArray.cast(ret).get((short) 1);
      if (test_data[i][4] == UPGRADE)
        Assert.assertNotEquals(KMByteBlob.cast(keyBlobPtr).length(), 0);
      else
        Assert.assertEquals(KMByteBlob.cast(keyBlobPtr).length(), 0);
      if (KMByteBlob.cast(keyBlobPtr).length() != 0) {
        ret = getKeyCharacteristics(keyBlobPtr);
        keyCharacteristics = KMArray.cast(ret).get((short) 1);
        hwParams = KMKeyCharacteristics.cast(keyCharacteristics)
                .getHardwareEnforced();
        osVersion = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_VERSION,
                hwParams);
        osVersion = KMIntegerTag.cast(osVersion).getValue();
        osPatch = KMKeyParameters.findTag(KMType.UINT_TAG,
                KMType.OS_PATCH_LEVEL, hwParams);
        osPatch = KMIntegerTag.cast(osPatch).getValue();
        short ptr = KMKeyParameters.findTag(KMType.UINT_TAG,
                KMType.VENDOR_PATCH_LEVEL, hwParams);
        short vendorPatchLevel = KMIntegerTag.cast(ptr).getValue();
        ptr = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.BOOT_PATCH_LEVEL,
                hwParams);
        short bootPatchLevel = KMIntegerTag.cast(ptr).getValue();
        Assert.assertEquals(KMInteger.cast(osVersion).getShort(),
                test_data[i][0]);
        Assert.assertEquals(KMInteger.cast(osPatch).getShort(),
                test_data[i][1]);
        Assert.assertEquals(KMInteger.cast(vendorPatchLevel).getShort(),
                test_data[i][2]);
        Assert.assertEquals(KMInteger.cast(bootPatchLevel).getShort(),
                test_data[i][3]);
      }
    }
    cleanUp();
  }

  @Test
  public void testDestroyAttIds() {
    init();
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_DESTROY_ATT_IDS_CMD, 0x40, 0x00);
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(respBuf[0], 0);
    cleanUp();
  }

  private short upgradeKey(short keyBlobPtr, byte[] clientId, byte[] appData, short expectedErr) {
    short tagCount = 0;
    short clientIdTag = 0;
    short appDataTag = 0;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short keyParams = KMArray.instance(tagCount);
    short tagIndex = 0;
    if (clientId != null) {
      KMArray.cast(keyBlobPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(keyParams).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    keyParams = KMKeyParameters.instance(keyParams);
    short arr = KMArray.instance((short) 2);
    KMArray.cast(arr).add((short) 0, keyBlobPtr);
    KMArray.cast(arr).add((short) 1, keyParams);
    CommandAPDU apdu = encodeApdu((byte) INS_UPGRADE_KEY_CMD, arr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if (KMError.OK == expectedErr) {
      short ret = KMArray.instance((short) 2);
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
      ret = decoder.decode(ret, respBuf, (short) 0, len);
      Assert.assertEquals(expectedErr, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
      return ret;
    } else {
      short ret = KMInteger.exp();
      ret = decoder.decode(ret, respBuf, (short) 0, len);
      Assert.assertEquals(expectedErr, KMInteger.cast(ret).getShort());
      return ret;
    }
  }

  @Test
  public void testSignVerifyWithRsaSHA256PssWithUpdate() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS, true, true);
    cleanUp();
  }

  @Test
  public void testAbortOperation() {
    init();
    short aesDesKeyArr = generateAesDesKey(KMType.AES, (short) 128, null, null, false);
    ;
    short keyBlobPtr = KMArray.cast(aesDesKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    byte[] nonce = new byte[16];
    cryptoProvider.newRandomNumber(nonce, (short) 0, (short) 16);
    short inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, nonce);
    byte[] plainData = "Hello World 123!".getBytes();
    short ret = begin(KMType.ENCRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(inParams), (short) 0);
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMRepository.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0, (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
    abort(opHandle);
    short dataPtr = KMByteBlob.instance(plainData, (short) 0, (short) plainData.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
    ret = update(opHandle, dataPtr, (short) 0, (short) 0, (short) 0);
    Assert.assertEquals(KMError.INVALID_OPERATION_HANDLE, ret);
    cleanUp();
  }

  public void testEncryptDecryptWithAesDes(byte alg, byte blockMode, byte padding, boolean update) {
    short aesDesKeyArr;
    boolean aesGcmFlag = false;
    if (alg == KMType.AES) {
      if (blockMode == KMType.GCM) {
        aesDesKeyArr = generateAesGcmKey((short) 128, null, null);
        aesGcmFlag = true;
      } else {
        aesDesKeyArr = generateAesDesKey(alg, (short) 128, null, null, false);
      }
    } else {
      aesDesKeyArr = generateAesDesKey(alg, (short) 168, null, null, false);
    }
    short keyBlobPtr = KMArray.cast(aesDesKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    byte[] nonce = new byte[16];
    cryptoProvider.newRandomNumber(nonce, (short) 0, (short) 16);
    short inParams = getAesDesParams(alg, blockMode, padding, nonce);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Encrypt
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.ENCRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, aesGcmFlag
    );
    inParams = getAesDesParams(alg, blockMode, padding, nonce);
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    //print(keyBlobPtr);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        cipherData, (short) 0, (short) cipherData.length);
    ret = processMessage(cipherData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.DECRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, aesGcmFlag
    );
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    //print(plainData,(short)0,(short)plainData.length);
    //print(keyBlobPtr);
    short equal = Util.arrayCompare(plainData, (short) 0, KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(), (short) plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testEncryptDecryptWithRsa(byte digest, byte padding) {
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getRsaParams(digest, padding);
    byte[] plainData = "Hello World 123!".getBytes();
    byte[] cipherData = new byte[256];
    short cipherDataLen = 0;
    //Encrypt
    if (padding == KMType.RSA_OAEP) {
      cipherDataLen = rsaOaepEncryptMessage(keyBlob, digest, plainData,
          (short) 0, (short) plainData.length, cipherData, (short) 0);
    } else {
      cipherDataLen = rsaEncryptMessage(keyBlob, padding, digest, plainData,
          (short) 0, (short) plainData.length, cipherData, (short) 0);
    }
    Assert.assertTrue((cipherDataLen == 256));
    inParams = getRsaParams(digest, padding);
    short ret = processMessage(cipherData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.DECRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, false, false
    );
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    short len = KMByteBlob.cast(keyBlobPtr).length();
    short start = KMByteBlob.cast(keyBlobPtr).getStartOff();
    short equal = Util.arrayCompare(plainData, (short) 0, KMByteBlob.cast(keyBlobPtr).getBuffer(),
        (short) (start + len - plainData.length), (short) plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testSignVerifyWithRsa(byte digest, byte padding, boolean update, boolean verifyFlag) {
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getRsaParams(digest, padding);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Sign
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.SIGN,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, false
    );
    inParams = getRsaParams(digest, padding);
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        signatureData, (short) 0, (short) signatureData.length);
    if (verifyFlag == false) {
      Assert.assertEquals(signatureData.length, 256);
      return;
    }
    boolean verify = rsaVerifyMessage(plainData, (short) 0, (short) plainData.length,
        signatureData, (short) 0, (short) signatureData.length,
        digest, padding, keyBlob);
    Assert.assertTrue(verify);
  }

  public void testSignVerifyWithEcdsa(byte digest, boolean update) {
    short ecKeyArr = generateEcKey(null, null);
    short keyBlobPtr = KMArray.cast(ecKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getEcParams(digest);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Sign
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.SIGN,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, false
    );
    inParams = getEcParams(digest);
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        signatureData, (short) 0, (short) signatureData.length);
    boolean verify = false;
    if (digest == KMType.DIGEST_NONE) {
      verify = ecNoDigestVerifyMessage(plainData, (short) 0, (short) plainData.length,
          signatureData, (short) 0, (short) signatureData.length,
          keyBlob);
    } else {
      verify = ecVerifyMessage(plainData, (short) 0, (short) plainData.length,
          signatureData, (short) 0, (short) signatureData.length,
          keyBlob);
    }
    Assert.assertTrue(verify);
  }

  public void testSignVerifyWithHmac(byte digest, boolean update) {
    short hmacKeyArr = generateHmacKey(null, null);
    short keyBlobPtr = KMArray.cast(hmacKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getHmacParams(digest, true);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Sign
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.SIGN,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, false
    );
    inParams = getHmacParams(digest, false);
    keyBlobPtr = KMArray.cast(ret).get((short) 2);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        signatureData, (short) 0, (short) signatureData.length);
    ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.VERIFY,
        KMKeyParameters.instance(inParams),
        (short) 0, signatureData, update, false
    );
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
  }

  private short getAesDesParams(byte alg, byte blockMode, byte padding, byte[] nonce) {
    short inParams;
    if (blockMode == KMType.GCM) {
      inParams = KMArray.instance((short) 5);
      short byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, blockMode);
      KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, padding);
      KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
      short nonceLen = 12;
      byteBlob = KMByteBlob.instance(nonce, (short) 0, nonceLen);
      KMArray.cast(inParams).add((short) 2, KMByteTag.instance(KMType.NONCE, byteBlob));
      short macLen = KMInteger.uint_16((short) 128);
      macLen = KMIntegerTag.instance(KMType.UINT_TAG, KMType.MAC_LENGTH, macLen);
      KMArray.cast(inParams).add((short) 3, macLen);
      byte[] authData = "AuthData".getBytes();
      short associatedData = KMByteBlob.instance(authData, (short) 0, (short) authData.length);
      associatedData = KMByteTag.instance(KMType.ASSOCIATED_DATA, associatedData);
      KMArray.cast(inParams).add((short) 4, associatedData);
    } else if (blockMode == KMType.ECB) {
      inParams = KMArray.instance((short) 2);
      short byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, blockMode);
      KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, padding);
      KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
    } else {
      inParams = KMArray.instance((short) 3);
      short byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, blockMode);
      KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, padding);
      KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
      short nonceLen = 16;
      if (alg == KMType.DES) {
        nonceLen = 8;
      }
      byteBlob = KMByteBlob.instance(nonce, (short) 0, nonceLen);
      KMArray.cast(inParams).add((short) 2, KMByteTag.instance(KMType.NONCE, byteBlob));
    }
    return inParams;
  }

  private short getRsaParams(byte digest, byte padding) {
    short inParams = KMArray.instance((short) 2);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, digest);
    KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, padding);
    KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
    return inParams;
  }

  private short getEcParams(byte digest) {
    short inParams = KMArray.instance((short) 1);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, digest);
    KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    return inParams;
  }

  private short getHmacParams(byte digest, boolean sign) {
    short paramsize = (short) (sign ? 2 : 1);
    short inParams = KMArray.instance((short) paramsize);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, digest);
    KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    short macLength = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MAC_LENGTH, KMInteger.uint_16((short)/*256*/160));
    if (sign) {
      KMArray.cast(inParams).add((short) 1, macLength);
    }
    return inParams;
  }

  public short processMessage(
      byte[] data,
      short keyBlob,
      byte keyPurpose,
      short inParams,
      short hwToken,
      byte[] signature,
      boolean updateFlag,
      boolean aesGcmFlag) {
    short beginResp = begin(keyPurpose, keyBlob, inParams, hwToken);
    short opHandle = KMArray.cast(beginResp).get((short) 2);
    byte[] opHandleBuf = new byte[KMRepository.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0, (short) opHandleBuf.length);
    short dataPtr = KMByteBlob.instance(data, (short) 0, (short) data.length);
    short ret = KMType.INVALID_VALUE;
    byte[] outputData = new byte[128];
    short len = 0;
    inParams = 0;
    //Test
    short firstDataLen = 16;
    if (keyPurpose == KMType.DECRYPT) {
      firstDataLen = 32;
    }

    //Test

    if (updateFlag) {
      dataPtr = KMByteBlob.instance(data, (short) 0, (short) /*16*/firstDataLen);
      if (aesGcmFlag) {
        byte[] authData = "AuthData".getBytes();
        short associatedData = KMByteBlob.instance(authData, (short) 0, (short) authData.length);
        associatedData = KMByteTag.instance(KMType.ASSOCIATED_DATA, associatedData);
        inParams = KMArray.instance((short) 1);
        KMArray.cast(inParams).add((short) 0, associatedData);
        inParams = KMKeyParameters.instance(inParams);
      }
      opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
      ret = update(opHandle, dataPtr, inParams, (short) 0, (short) 0);
      dataPtr = KMArray.cast(ret).get((short) 3);
      if (KMByteBlob.cast(dataPtr).length() > 0) {
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(dataPtr).getBuffer(),
            KMByteBlob.cast(dataPtr).getStartOff(),
            outputData,
            (short) 0,
            KMByteBlob.cast(dataPtr).length());
        len = KMByteBlob.cast(dataPtr).length();
        dataPtr = KMByteBlob.instance(data, len, (short) (data.length - len));
      } else {
        dataPtr = KMByteBlob
            .instance(data, (short)/*16*/firstDataLen, (short) (data.length - /*16*/firstDataLen));
      }
    }

    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
    if (keyPurpose == KMType.VERIFY) {
      ret = finish(opHandle, dataPtr, signature, (short) 0, (short) 0, (short) 0, KMError.OK);
    } else {
      ret = finish(opHandle, dataPtr, null, (short) 0, (short) 0, (short) 0, KMError.OK);
    }
    if (len > 0) {
      dataPtr = KMArray.cast(ret).get((short) 2);
      if (KMByteBlob.cast(dataPtr).length() > 0) {
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(dataPtr).getBuffer(),
            KMByteBlob.cast(dataPtr).getStartOff(),
            outputData,
            len,
            KMByteBlob.cast(dataPtr).length());
        len = (short) (len + KMByteBlob.cast(dataPtr).length());
      }
      KMArray.cast(ret).add((short) 2, KMByteBlob.instance(outputData, (short) 0, len));
    }
    return ret;
  }

  public short begin(byte keyPurpose, short keyBlob, short keyParmas, short hwToken) {
    short arrPtr = KMArray.instance((short) 4);
    KMArray.cast(arrPtr).add((short) 0, KMEnum.instance(KMType.PURPOSE, keyPurpose));
    KMArray.cast(arrPtr).add((short) 1, keyBlob);
    KMArray.cast(arrPtr).add((short) 2, keyParmas);
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    KMArray.cast(arrPtr).add((short) 3, hwToken);
    CommandAPDU apdu = encodeApdu((byte) INS_BEGIN_OPERATION_CMD, arrPtr);
    //print(apdu.getBytes(),(short)0,(short)apdu.getBytes().length);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 3);
    short outParams = KMKeyParameters.exp();
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, outParams);
    KMArray.cast(ret).add((short) 2, KMInteger.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if (len > 5) {
      ret = decoder.decode(ret, respBuf, (short) 0, len);
      short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
      Assert.assertEquals(error, KMError.OK);
      return ret;
    } else {
      if (len == 3) {
        return respBuf[0];
      }
      if (len == 4) {
        return respBuf[1];
      }
      return Util.getShort(respBuf, (short) 0);
    }
  }

  public short translateExtendedErrorCodes(short err) {
    switch (err) {
      case KMError.SW_CONDITIONS_NOT_SATISFIED:
      case KMError.UNSUPPORTED_CLA:
      case KMError.INVALID_P1P2:
      case KMError.INVALID_DATA:
      case KMError.CRYPTO_ILLEGAL_USE:
      case KMError.CRYPTO_ILLEGAL_VALUE:
      case KMError.CRYPTO_INVALID_INIT:
      case KMError.CRYPTO_UNINITIALIZED_KEY:
      case KMError.GENERIC_UNKNOWN_ERROR:
        err = KMError.UNKNOWN_ERROR;
        break;
      case KMError.CRYPTO_NO_SUCH_ALGORITHM:
        err = KMError.UNSUPPORTED_ALGORITHM;
        break;
      case KMError.UNSUPPORTED_INSTRUCTION:
      case KMError.CMD_NOT_ALLOWED:
      case KMError.SW_WRONG_LENGTH:
        err = KMError.UNIMPLEMENTED;
        break;
      default:
        break;
    }
    return err;
  }

  public short finish(short operationHandle, short data, byte[] signature, short inParams,
      short hwToken, short verToken, short expectedErr) {
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if (verToken == 0) {
      verToken = KMVerificationToken.instance();
    }
    short signatureTag;
    if (signature == null) {
      signatureTag = KMByteBlob.instance((short) 0);
    } else {
      signatureTag = KMByteBlob.instance(signature, (short) 0, (short) signature.length);
    }
    if (inParams == 0) {
      short arr = KMArray.instance((short) 0);
      inParams = KMKeyParameters.instance(arr);
    }
    short arrPtr = KMArray.instance((short) 6);
    KMArray.cast(arrPtr).add((short) 0, operationHandle);
    KMArray.cast(arrPtr).add((short) 1, inParams);
    KMArray.cast(arrPtr).add((short) 2, data);
    KMArray.cast(arrPtr).add((short) 3, signatureTag);
    KMArray.cast(arrPtr).add((short) 4, hwToken);
    KMArray.cast(arrPtr).add((short) 5, verToken);
    CommandAPDU apdu = encodeApdu((byte) INS_FINISH_OPERATION_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    short ret;
    short error;
    if (expectedErr == KMError.OK) {
      ret = KMArray.instance((short) 3);
      short outParams = KMKeyParameters.exp();
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      KMArray.cast(ret).add((short) 1, outParams);
      KMArray.cast(ret).add((short) 2, KMByteBlob.exp());
    } else {
      ret = KMInteger.exp();
    }
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    if (expectedErr == KMError.OK) {
      error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    } else {
      error = KMInteger.cast(ret).getShort();
      error = translateExtendedErrorCodes(error);
    }
    Assert.assertEquals(error, expectedErr);
    return ret;
  }

  public short update(short operationHandle, short data, short inParams, short hwToken,
      short verToken) {
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if (verToken == 0) {
      verToken = KMVerificationToken.instance();
    }
    if (inParams == 0) {
      short arr = KMArray.instance((short) 0);
      inParams = KMKeyParameters.instance(arr);
    }
    short arrPtr = KMArray.instance((short) 5);
    KMArray.cast(arrPtr).add((short) 0, operationHandle);
    KMArray.cast(arrPtr).add((short) 1, inParams);
    KMArray.cast(arrPtr).add((short) 2, data);
    KMArray.cast(arrPtr).add((short) 3, hwToken);
    KMArray.cast(arrPtr).add((short) 4, verToken);
    CommandAPDU apdu = encodeApdu((byte) INS_UPDATE_OPERATION_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 4);
    short outParams = KMKeyParameters.exp();
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMInteger.exp());
    KMArray.cast(ret).add((short) 2, outParams);
    KMArray.cast(ret).add((short) 3, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if (len > 5) {
      ret = decoder.decode(ret, respBuf, (short) 0, len);
      short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
      Assert.assertEquals(error, KMError.OK);
    } else {
      ret = respBuf[1];
    }
    return ret;
  }

  private void print(short blob) {
    print(KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff(),
        KMByteBlob.cast(blob).length());
  }

  private void print(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format(" 0x%02X", buf[i]));
    }
    System.out.println(sb.toString());
  }

  private void printCert(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format("%02X", buf[i]));
    }
    System.out.println(sb.toString());
  }


/*
  @Test
  public void testApdu(){
    init();
    byte[] cmd = {(byte)0x80,0x11,0x40,0x00,0x00,0x00,0x4C,(byte)0x83,(byte)0xA5,0x1A,0x70,0x00,0x01,(byte)0xF7,0x01,0x1A,0x10,
      0x00,0x00,0x02,0x03,0x1A,0x30,0x00,0x00,0x03,0x19,0x01,0x00,0x1A,0x20,0x00,0x00,0x01,0x42,0x02,
      0x03,0x1A,0x20,0x00,0x00,0x05,0x41,0x04,0x03,0x58,0x24,(byte)0x82,0x58,0x20,0x73,0x7C,0x2E,(byte)0xCD,
      0x7B,(byte)0x8D,0x19,0x40,(byte)0xBF,0x29,0x30,(byte)0xAA,(byte)0x9B,0x4E,
      (byte)0xD3,(byte)0xFF,(byte)0x94,0x1E,(byte)0xED,0x09,0x36,0x6B,
      (byte)0xC0,0x32,(byte)0x99,(byte)0x98,0x64,(byte)0x81,(byte)0xF3,(byte)0xA4,(byte)0xD8,0x59,0x40};
    CommandAPDU cmdApdu = new CommandAPDU(cmd);
    ResponseAPDU resp = simulator.transmitCommand(cmdApdu);
    short ret = KMArray.instance((short) 3);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short)1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    byte[] respBuf = resp.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short)0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short)1)).length();
    short blobArr = extractKeyBlobArray(KMArray.cast(ret).get((short)1));
    short keyCharacteristics = KMArray.cast(ret).get((short)2);
    short hwParams = KMKeyCharacteristics.cast(keyCharacteristics).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getSoftwareEnforced();
    cleanUp();
  }
 */
}
