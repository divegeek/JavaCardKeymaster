package com.android.javacard.keymaster;

/**
 * KMError includes all the error codes from android keymaster hal specifications. The values are
 * positive unlike negative values in keymaster hal.
 */
public class KMError {
  public static short OK = 0;
  public static short ROOT_OF_TRUST_ALREADY_SET = 1;
  public static short UNSUPPORTED_PURPOSE = 2;
  public static short INCOMPATIBLE_PURPOSE = 3;
  public static short UNSUPPORTED_ALGORITHM = 4;
  public static short INCOMPATIBLE_ALGORITHM = 5;
  public static short UNSUPPORTED_KEY_SIZE = 6;
  public static short UNSUPPORTED_BLOCK_MODE = 7;
  public static short INCOMPATIBLE_BLOCK_MODE = 8;
  public static short UNSUPPORTED_MAC_LENGTH = 9;
  public static short UNSUPPORTED_PADDING_MODE = 10;
  public static short INCOMPATIBLE_PADDING_MODE = 11;
  public static short UNSUPPORTED_DIGEST = 12;
  public static short INCOMPATIBLE_DIGEST = 13;
  public static short INVALID_EXPIRATION_TIME = 14;
  public static short INVALID_USER_ID = 15;
  public static short INVALID_AUTHORIZATION_TIMEOUT = 16;
  public static short UNSUPPORTED_KEY_FORMAT = 17;
  public static short INCOMPATIBLE_KEY_FORMAT = 18;
  public static short UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = 19;
  /** For PKCS8 & PKCS12 */
  public static short UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = 20;
  /** For PKCS8 & PKCS12 */
  public static short INVALID_INPUT_LENGTH = 21;

  public static short KEY_EXPORT_OPTIONS_INVALID = 22;
  public static short DELEGATION_NOT_ALLOWED = 23;
  public static short KEY_NOT_YET_VALID = 24;
  public static short KEY_EXPIRED = 25;
  public static short KEY_USER_NOT_AUTHENTICATED = 26;
  public static short OUTPUT_PARAMETER_NULL = 27;
  public static short INVALID_OPERATION_HANDLE = 28;
  public static short INSUFFICIENT_BUFFER_SPACE = 29;
  public static short VERIFICATION_FAILED = 30;
  public static short TOO_MANY_OPERATIONS = 31;
  public static short UNEXPECTED_NULL_POINTER = 32;
  public static short INVALID_KEY_BLOB = 33;
  public static short IMPORTED_KEY_NOT_ENCRYPTED = 34;
  public static short IMPORTED_KEY_DECRYPTION_FAILED = 35;
  public static short IMPORTED_KEY_NOT_SIGNED = 36;
  public static short IMPORTED_KEY_VERIFICATION_FAILED = 37;
  public static short INVALID_ARGUMENT = 38;
  public static short UNSUPPORTED_TAG = 39;
  public static short INVALID_TAG = 40;
  public static short MEMORY_ALLOCATION_FAILED = 41;
  public static short IMPORT_PARAMETER_MISMATCH = 44;
  public static short SECURE_HW_ACCESS_DENIED = 45;
  public static short OPERATION_CANCELLED = 46;
  public static short CONCURRENT_ACCESS_CONFLICT = 47;
  public static short SECURE_HW_BUSY = 48;
  public static short SECURE_HW_COMMUNICATION_FAILED = 49;
  public static short UNSUPPORTED_EC_FIELD = 50;
  public static short MISSING_NONCE = 51;
  public static short INVALID_NONCE = 52;
  public static short MISSING_MAC_LENGTH = 53;
  public static short KEY_RATE_LIMIT_EXCEEDED = 54;
  public static short CALLER_NONCE_PROHIBITED = 55;
  public static short KEY_MAX_OPS_EXCEEDED = 56;
  public static short INVALID_MAC_LENGTH = 57;
  public static short MISSING_MIN_MAC_LENGTH = 58;
  public static short UNSUPPORTED_MIN_MAC_LENGTH = 59;
  public static short UNSUPPORTED_KDF = 60;
  public static short UNSUPPORTED_EC_CURVE = 61;
  public static short KEY_REQUIRES_UPGRADE = 62;
  public static short ATTESTATION_CHALLENGE_MISSING = 63;
  public static short KEYMASTER_NOT_CONFIGURED = 64;
  public static short ATTESTATION_APPLICATION_ID_MISSING = 65;
  public static short CANNOT_ATTEST_IDS = 66;
  public static short ROLLBACK_RESISTANCE_UNAVAILABLE = 67;
  public static short HARDWARE_TYPE_UNAVAILABLE = 68;
  public static short PROOF_OF_PRESENCE_REQUIRED = 69;
  public static short CONCURRENT_PROOF_OF_PRESENCE_REQUESTED = 70;
  public static short NO_USER_CONFIRMATION = 71;
  public static short DEVICE_LOCKED = 72;
  public static short EARLY_BOOT_ENDED = 73;
  public static short UNIMPLEMENTED = 100;
  public static short VERSION_MISMATCH = 101;
  public static short UNKNOWN_ERROR = 1000;
}
