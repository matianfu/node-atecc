const Promise = require('bluebird')
const EventEmitter = require('events')
const crypto = require('crypto')

const i2c = require('i2c-bus')
const debug = require('debug')('ecc')
const debugCmd = require('debug')('ecc-cmd')

const DER = require('./der')

/** slot 0 stores device key **/
const DEVICE_KEY_SLOT = 0

/** command polling, from latest cryptoauthlib, lib/atca_execution.c **/
const ATCA_POLLING_INIT_TIME_MSEC = 2
const ATCA_POLLING_FREQUENCY_TIME_MSEC = 5
const ATCA_POLLING_MAX_TIME_MSEC = 2500

const UNSUPPORTED = 0xFFFF

/* command definitions */

// minimum number of bytes in command (from count byte to second CRC byte)
const ATCA_CMD_SIZE_MIN = 7
// maximum size of command packet (Verify)
const ATCA_CMD_SIZE_MAX = 4 * 36 + 7
// status byte for success
const CMD_STATUS_SUCCESS = 0x00
// status byte after wake-up
const CMD_STATUS_WAKEUP = 0x11
// command parse error
const CMD_STATUS_BYTE_PARSE = 0x03
// command ECC error
const CMD_STATUS_BYTE_ECC = 0x05
// command execution error
const CMD_STATUS_BYTE_EXEC = 0x0F
// communication error
const CMD_STATUS_BYTE_COMM = 0xFF

/** \name opcodes for ATATECC Commands @{ */
const ATCA_CHECKMAC = 0x28 // CheckMac command op-code
const ATCA_DERIVE_KEY = 0x1C // DeriveKey command op-code
const ATCA_INFO = 0x30 // Info command op-code
const ATCA_GENDIG = 0x15 // GenDig command op-code
const ATCA_GENKEY = 0x40 // GenKey command op-code
const ATCA_HMAC = 0x11 // HMAC command op-code
const ATCA_LOCK = 0x17 // Lock command op-code
const ATCA_MAC = 0x08 // MAC command op-code
const ATCA_NONCE = 0x16 // Nonce command op-code
const ATCA_PAUSE = 0x01 // Pause command op-code
const ATCA_PRIVWRITE = 0x46 // PrivWrite command op-code
const ATCA_RANDOM = 0x1B // Random command op-code
const ATCA_READ = 0x02 // Read command op-code
const ATCA_SIGN = 0x41 // Sign command op-code
const ATCA_UPDATE_EXTRA = 0x20 // UpdateExtra command op-code
const ATCA_VERIFY = 0x45 // GenKey command op-code
const ATCA_WRITE = 0x12 // Write command op-code
const ATCA_ECDH = 0x43 // ECDH command op-code
const ATCA_COUNTER = 0x24 // Counter command op-code
const ATCA_SHA = 0x47 // SHA command op-code
const ATCA_AES = 0x51 // AES command op-code
const ATCA_KDF = 0x56 // KDF command op-code
const ATCA_SECUREBOOT = 0x80 // Secure Boot command op-code
const ATCA_SELFTEST = 0x77 // Self test command op-code

// promote before ATCA_DATA_SIZE uses it
const ATCA_KEY_SIZE = (32) // size of a symmetric SHA key

/** \name Definitions of Data and Packet Sizes @{ */
const ATCA_BLOCK_SIZE = (32) // size of a block
const ATCA_WORD_SIZE = (4) // size of a word
const ATCA_PUB_KEY_PAD = (4) // size of the public key pad
const ATCA_SERIAL_NUM_SIZE = (9) // number of bytes in the device serial number
const ATCA_RSP_SIZE_VAL = 7 // size of response packet containing four bytes of data
const ATCA_KEY_COUNT = (16) // number of keys
const ATCA_ECC_CONFIG_SIZE = (128) // size of configuration zone
const ATCA_SHA_CONFIG_SIZE = (88) // size of configuration zone
const ATCA_OTP_SIZE = (64) // size of OTP zone
const ATCA_DATA_SIZE = (ATCA_KEY_COUNT * ATCA_KEY_SIZE) // size of data zone
const ATCA_AES_GFM_SIZE = ATCA_BLOCK_SIZE // size of GFM data

const ATCA_CHIPMODE_OFFSET = (19) // ChipMode byte offset within the configuration zone
const ATCA_CHIPMODE_I2C_ADDRESS_FLAG = 0x01 // ChipMode I2C Address in UserExtraAdd flag
const ATCA_CHIPMODE_TTL_ENABLE_FLAG = 0x02 // ChipMode TTLenable flag
const ATCA_CHIPMODE_WATCHDOG_MASK = 0x04 // ChipMode watchdog duration mask
const ATCA_CHIPMODE_WATCHDOG_SHORT = 0x00 // ChipMode short watchdog (~1.3s)
const ATCA_CHIPMODE_WATCHDOG_LONG = 0x04 // ChipMode long watchdog (~13s)
const ATCA_CHIPMODE_CLOCK_DIV_MASK = 0xF8 // ChipMode clock divider mask
const ATCA_CHIPMODE_CLOCK_DIV_M0 = 0x00 // ChipMode clock divider M0
const ATCA_CHIPMODE_CLOCK_DIV_M1 = 0x28 // ChipMode clock divider M1
const ATCA_CHIPMODE_CLOCK_DIV_M2 = 0x68 // ChipMode clock divider M2

const ATCA_COUNT_SIZE = 1 // Number of bytes in the command packet Count
const ATCA_CRC_SIZE = 2 // Number of bytes in the command packet CRC
const ATCA_PACKET_OVERHEAD = (ATCA_COUNT_SIZE + ATCA_CRC_SIZE) // Number of bytes in the command packet

const ATCA_PUB_KEY_SIZE = (64) // size of a p256 public key
const ATCA_PRIV_KEY_SIZE = (32) // size of a p256 private key
const ATCA_SIG_SIZE = (64) // size of a p256 signature
// const ATCA_KEY_SIZE = (32) // size of a symmetric SHA key
const RSA2048_KEY_SIZE = (256) // size of a RSA private key

const ATCA_RSP_SIZE_MIN = 4 // minimum number of bytes in response
const ATCA_RSP_SIZE_4 = 7 // size of response packet containing 4 bytes data
const ATCA_RSP_SIZE_72 = 75 // size of response packet containing 64 bytes data
const ATCA_RSP_SIZE_64 = 67 // size of response packet containing 64 bytes data
const ATCA_RSP_SIZE_32 = 35 // size of response packet containing 32 bytes data
const ATCA_RSP_SIZE_16 = 19 // size of response packet containing 16 bytes data
const ATCA_RSP_SIZE_MAX = 75 // maximum size of response packet (GenKey and Verify command)

const OUTNONCE_SIZE = (32) // Size of the OutNonce response expected from several commands

/** \name Definitions for Command Parameter Ranges @{ */
const ATCA_KEY_ID_MAX = 15 // maximum value for key id
const ATCA_OTP_BLOCK_MAX = 1 // maximum value for OTP block

/** \name Definitions for Indexes Common to All Commands @{ */
const ATCA_COUNT_IDX = (0) // command packet index for count
const ATCA_OPCODE_IDX = (1) // command packet index for op-code
const ATCA_PARAM1_IDX = (2) // command packet index for first parameter
const ATCA_PARAM2_IDX = (3) // command packet index for second parameter
const ATCA_DATA_IDX = (5) // command packet index for data load
const ATCA_RSP_DATA_IDX = (1) // buffer index of data in response

/** \name Definitions for Zone and Address Parameters @{ */
const ATCA_ZONE_CONFIG = 0x00 // Configuration zone
const ATCA_ZONE_OTP = 0x01 // OTP (One Time Programming) zone
const ATCA_ZONE_DATA = 0x02 // Data zone
const ATCA_ZONE_MASK = 0x03 // Zone mask
const ATCA_ZONE_ENCRYPTED = 0x40 // Zone bit 6 set: Write is encrypted with an unlocked data zone.
const ATCA_ZONE_READWRITE_32 = 0x80 // Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
const ATCA_ADDRESS_MASK_CONFIG = (0x001F) // Address bits 5 to 7 are 0 for Configuration zone.
const ATCA_ADDRESS_MASK_OTP = (0x000F) // Address bits 4 to 7 are 0 for OTP zone.
const ATCA_ADDRESS_MASK = (0x007F) // Address bit 7 to 15 are always 0.
const ATCA_TEMPKEY_KEYID = (0xFFFF) // KeyID when referencing TempKey

/** \name Definitions for Key types @{ */
const ATCA_B283_KEY_TYPE = 0 // B283 NIST ECC key
const ATCA_K283_KEY_TYPE = 1 // K283 NIST ECC key
const ATCA_P256_KEY_TYPE = 4 // P256 NIST ECC key
const ATCA_AES_KEY_TYPE = 6 // AES-128 Key
const ATCA_SHA_KEY_TYPE = 7 // SHA key or other data

/** \name Definitions for the AES Command @{ */
const AES_MODE_IDX = ATCA_PARAM1_IDX // AES command index for mode
const AES_KEYID_IDX = ATCA_PARAM2_IDX // AES command index for key id
const AES_INPUT_IDX = ATCA_DATA_IDX // AES command index for input data
const AES_COUNT = (23) // AES command packet size
const AES_MODE_MASK = 0xC7 // AES mode bits 3 to 5 are 0
const AES_MODE_KEY_BLOCK_MASK = 0xC0 // AES mode mask for key block field
const AES_MODE_OP_MASK = 0x07 // AES mode operation mask
const AES_MODE_ENCRYPT = 0x00 // AES mode: Encrypt
const AES_MODE_DECRYPT = 0x01 // AES mode: Decrypt
const AES_MODE_GFM = 0x03 // AES mode: GFM calculation
const AES_MODE_KEY_BLOCK_POS = (6) // Bit shift for key block in mode
const AES_DATA_SIZE = (16) // size of AES encrypt/decrypt data
const AES_RSP_SIZE = ATCA_RSP_SIZE_16 // AES command response packet size

/** \name Definitions for the CheckMac Command @{ */
const CHECKMAC_MODE_IDX = ATCA_PARAM1_IDX // CheckMAC command index for mode
const CHECKMAC_KEYID_IDX = ATCA_PARAM2_IDX // CheckMAC command index for key identifier
const CHECKMAC_CLIENT_CHALLENGE_IDX = ATCA_DATA_IDX // CheckMAC command index for client challenge
const CHECKMAC_CLIENT_RESPONSE_IDX = (37) // CheckMAC command index for client response
const CHECKMAC_DATA_IDX = (69) // CheckMAC command index for other data
const CHECKMAC_COUNT = (84) // CheckMAC command packet size
const CHECKMAC_MODE_CHALLENGE = 0x00 // CheckMAC mode     0: first SHA block from key id
const CHECKMAC_MODE_BLOCK2_TEMPKEY = 0x01 // CheckMAC mode bit   0: second SHA block from TempKey
const CHECKMAC_MODE_BLOCK1_TEMPKEY = 0x02 // CheckMAC mode bit   1: first SHA block from TempKey
const CHECKMAC_MODE_SOURCE_FLAG_MATCH = 0x04 // CheckMAC mode bit   2: match TempKey.SourceFlag
const CHECKMAC_MODE_INCLUDE_OTP_64 = 0x20 // CheckMAC mode bit   5: include first 64 OTP bits
const CHECKMAC_MODE_MASK = 0x27 // CheckMAC mode bits 3, 4, 6, and 7 are 0.
const CHECKMAC_CLIENT_CHALLENGE_SIZE = (32) // CheckMAC size of client challenge
const CHECKMAC_CLIENT_RESPONSE_SIZE = (32) // CheckMAC size of client response
const CHECKMAC_OTHER_DATA_SIZE = (13) // CheckMAC size of "other data"
const CHECKMAC_CLIENT_COMMAND_SIZE = (4) // CheckMAC size of client command header size inside "other data"
const CHECKMAC_CMD_MATCH = (0) // CheckMAC return value when there is a match
const CHECKMAC_CMD_MISMATCH = (1) // CheckMAC return value when there is a mismatch
const CHECKMAC_RSP_SIZE = ATCA_RSP_SIZE_MIN // CheckMAC response packet size

/** \name Definitions for the Counter command @{ */
const COUNTER_COUNT = ATCA_CMD_SIZE_MIN
const COUNTER_MODE_IDX = ATCA_PARAM1_IDX // Counter command index for mode
const COUNTER_KEYID_IDX = ATCA_PARAM2_IDX // Counter command index for key id
const COUNTER_MODE_MASK = 0x01 // Counter mode bits 1 to 7 are 0
const COUNTER_MAX_VALUE = 2097151 // Counter maximum value of the counter
const COUNTER_MODE_READ = 0x00 // Counter command mode for reading
const COUNTER_MODE_INCREMENT = 0x01 // Counter command mode for incrementing
const COUNTER_RSP_SIZE = ATCA_RSP_SIZE_4 // Counter command response packet size

/** \name Definitions for the DeriveKey Command @{ */
const DERIVE_KEY_RANDOM_IDX = ATCA_PARAM1_IDX // DeriveKey command index for random bit
const DERIVE_KEY_TARGETKEY_IDX = ATCA_PARAM2_IDX // DeriveKey command index for target slot
const DERIVE_KEY_MAC_IDX = ATCA_DATA_IDX // DeriveKey command index for optional MAC
const DERIVE_KEY_COUNT_SMALL = ATCA_CMD_SIZE_MIN // DeriveKey command packet size without MAC
const DERIVE_KEY_MODE = 0x04 // DeriveKey command mode set to 4 as in datasheet
const DERIVE_KEY_COUNT_LARGE = (39) // DeriveKey command packet size with MAC
const DERIVE_KEY_RANDOM_FLAG = 4 // DeriveKey 1. parameter; has to match TempKey.SourceFlag
const DERIVE_KEY_MAC_SIZE = (32) // DeriveKey MAC size
const DERIVE_KEY_RSP_SIZE = ATCA_RSP_SIZE_MIN // DeriveKey response packet size

/** \name Definitions for the ECDH Command @{ */
const ECDH_PREFIX_MODE = 0x00
const ECDH_COUNT = (ATCA_CMD_SIZE_MIN + ATCA_PUB_KEY_SIZE)
const ECDH_MODE_SOURCE_MASK = 0x01
const ECDH_MODE_SOURCE_EEPROM_SLOT = 0x00
const ECDH_MODE_SOURCE_TEMPKEY = 0x01
const ECDH_MODE_OUTPUT_MASK = 0x02
const ECDH_MODE_OUTPUT_CLEAR = 0x00
const ECDH_MODE_OUTPUT_ENC = 0x02
const ECDH_MODE_COPY_MASK = 0x0C
const ECDH_MODE_COPY_COMPATIBLE = 0x00
const ECDH_MODE_COPY_EEPROM_SLOT = 0x04
const ECDH_MODE_COPY_TEMP_KEY = 0x08
const ECDH_MODE_COPY_OUTPUT_BUFFER = 0x0C
const ECDH_KEY_SIZE = ATCA_BLOCK_SIZE // ECDH output data size
const ECDH_RSP_SIZE = ATCA_RSP_SIZE_64 // ECDH command packet size

/** \name Definitions for the GenDig Command @{ */
const GENDIG_ZONE_IDX = ATCA_PARAM1_IDX // GenDig command index for zone
const GENDIG_KEYID_IDX = ATCA_PARAM2_IDX // GenDig command index for key id
const GENDIG_DATA_IDX = ATCA_DATA_IDX // GenDig command index for optional data
const GENDIG_COUNT = ATCA_CMD_SIZE_MIN // GenDig command packet size without "other data"
const GENDIG_ZONE_CONFIG = 0 // GenDig zone id config. Use KeyID to specify any of the four 256-bit blocks of the Configuration zone.
const GENDIG_ZONE_OTP = 1 // GenDig zone id OTP. Use KeyID to specify either the first or second 256-bit block of the OTP zone.
const GENDIG_ZONE_DATA = 2 // GenDig zone id data. Use KeyID to specify a slot in the Data zone or a transport key in the hardware array.
const GENDIG_ZONE_SHARED_NONCE = 3 // GenDig zone id shared nonce. KeyID specifies the location of the input value in the message generation.
const GENDIG_ZONE_COUNTER = 4 // GenDig zone id counter. KeyID specifies the monotonic counter ID to be included in the message generation.
const GENDIG_ZONE_KEY_CONFIG = 5 // GenDig zone id key config. KeyID specifies the slot for which the configuration information is to be included in the message generation.
const GENDIG_RSP_SIZE = ATCA_RSP_SIZE_MIN // GenDig command response packet size

/** \name Definitions for the GenKey Command @{ */
const GENKEY_MODE_IDX = ATCA_PARAM1_IDX // GenKey command index for mode
const GENKEY_KEYID_IDX = ATCA_PARAM2_IDX // GenKey command index for key id
const GENKEY_DATA_IDX = (5) // GenKey command index for other data
const GENKEY_COUNT = ATCA_CMD_SIZE_MIN // GenKey command packet size without "other data"
const GENKEY_COUNT_DATA = (10) // GenKey command packet size with "other data"
const GENKEY_OTHER_DATA_SIZE = (3) // GenKey size of "other data"
const GENKEY_MODE_MASK = 0x1C // GenKey mode bits 0 to 1 and 5 to 7 are 0
const GENKEY_MODE_PRIVATE = 0x04 // GenKey mode: private key generation
const GENKEY_MODE_PUBLIC = 0x00 // GenKey mode: public key calculation
const GENKEY_MODE_DIGEST = 0x08 // GenKey mode: PubKey digest will be created after the public key is calculated
const GENKEY_MODE_PUBKEY_DIGEST = 0x10 // GenKey mode: Calculate PubKey digest on the public key in KeyId
const GENKEY_PRIVATE_TO_TEMPKEY = 0xFFFF // GenKey Create private key and store to tempkey (608 only)
const GENKEY_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN // GenKey response packet size in Digest mode
const GENKEY_RSP_SIZE_LONG = ATCA_RSP_SIZE_72 // GenKey response packet size when returning a public key

/** \name Definitions for the HMAC Command @{ */
const HMAC_MODE_IDX = ATCA_PARAM1_IDX // HMAC command index for mode
const HMAC_KEYID_IDX = ATCA_PARAM2_IDX // HMAC command index for key id
const HMAC_COUNT = ATCA_CMD_SIZE_MIN // HMAC command packet size
const HMAC_MODE_FLAG_TK_RAND = 0x00 // HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
const HMAC_MODE_FLAG_TK_NORAND = 0x04 // HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
const HMAC_MODE_FLAG_OTP88 = 0x10 // HMAC mode bit 4: Include the first 88 OTP bits (OTP[0] through OTP[10]) in the message.; otherwise, the corresponding message bits are set to zero. Not applicable for ATECC508A.
const HMAC_MODE_FLAG_OTP64 = 0x20 // HMAC mode bit 5: Include the first 64 OTP bits (OTP[0] through OTP[7]) in the message.; otherwise, the corresponding message bits are set to zero. If Mode[4] is set, the value of this mode bit is ignored. Not applicable for ATECC508A.
const HMAC_MODE_FLAG_FULLSN = 0x40 // HMAC mode bit 6: If set, include the 48 bits SN[2:3] and SN[4:7] in the message.; otherwise, the corresponding message bits are set to zero.
const HMAC_MODE_MASK = 0x74 // HMAC mode bits 0, 1, 3, and 7 are 0.
const HMAC_DIGEST_SIZE = (32) // HMAC size of digest response
const HMAC_RSP_SIZE = ATCA_RSP_SIZE_32 // HMAC command response packet size

/** \name Definitions for the Info Command @{ */
const INFO_PARAM1_IDX = ATCA_PARAM1_IDX // Info command index for 1. parameter
const INFO_PARAM2_IDX = ATCA_PARAM2_IDX // Info command index for 2. parameter
const INFO_COUNT = ATCA_CMD_SIZE_MIN // Info command packet size
const INFO_MODE_REVISION = 0x00 // Info mode Revision
const INFO_MODE_KEY_VALID = 0x01 // Info mode KeyValid
const INFO_MODE_STATE = 0x02 // Info mode State
const INFO_MODE_GPIO = 0x03 // Info mode GPIO
const INFO_MODE_VOL_KEY_PERMIT = 0x04 // Info mode GPIO
const INFO_MODE_MAX = 0x03 // Info mode maximum value
const INFO_NO_STATE = 0x00 // Info mode is not the state mode.
const INFO_OUTPUT_STATE_MASK = 0x01 // Info output state mask
const INFO_DRIVER_STATE_MASK = 0x02 // Info driver state mask
const INFO_PARAM2_SET_LATCH_STATE = 0x0002 // Info param2 to set the persistent latch state.
const INFO_PARAM2_LATCH_SET = 0x0001 // Info param2 to set the persistent latch
const INFO_PARAM2_LATCH_CLEAR = 0x0000 // Info param2 to clear the persistent latch
const INFO_SIZE = 0x04 // Info return size
const INFO_RSP_SIZE = ATCA_RSP_SIZE_VAL // Info command response packet size

/** \name Definitions for the KDF Command @{ */
const KDF_MODE_IDX = ATCA_PARAM1_IDX // KDF command index for mode
const KDF_KEYID_IDX = ATCA_PARAM2_IDX // KDF command index for key id
const KDF_DETAILS_IDX = ATCA_DATA_IDX // KDF command index for details
const KDF_DETAILS_SIZE = 4 // KDF details (param3) size
const KDF_MESSAGE_IDX = (ATCA_DATA_IDX + KDF_DETAILS_SIZE)

const KDF_MODE_SOURCE_MASK = 0x03 // KDF mode source key mask
const KDF_MODE_SOURCE_TEMPKEY = 0x00 // KDF mode source key in TempKey
const KDF_MODE_SOURCE_TEMPKEY_UP = 0x01 // KDF mode source key in upper TempKey
const KDF_MODE_SOURCE_SLOT = 0x02 // KDF mode source key in a slot
const KDF_MODE_SOURCE_ALTKEYBUF = 0x03 // KDF mode source key in alternate key buffer

const KDF_MODE_TARGET_MASK = 0x1C // KDF mode target key mask
const KDF_MODE_TARGET_TEMPKEY = 0x00 // KDF mode target key in TempKey
const KDF_MODE_TARGET_TEMPKEY_UP = 0x04 // KDF mode target key in upper TempKey
const KDF_MODE_TARGET_SLOT = 0x08 // KDF mode target key in slot
const KDF_MODE_TARGET_ALTKEYBUF = 0x0C // KDF mode target key in alternate key buffer
const KDF_MODE_TARGET_OUTPUT = 0x10 // KDF mode target key in output buffer
const KDF_MODE_TARGET_OUTPUT_ENC = 0x14 // KDF mode target key encrypted in output buffer

const KDF_MODE_ALG_MASK = 0x60 // KDF mode algorithm mask
const KDF_MODE_ALG_PRF = 0x00 // KDF mode PRF algorithm
const KDF_MODE_ALG_AES = 0x20 // KDF mode AES algorithm
const KDF_MODE_ALG_HKDF = 0x40 // KDF mode HKDF algorithm

const KDF_DETAILS_PRF_KEY_LEN_MASK = 0x00000003 // KDF details for PRF, source key length mask
const KDF_DETAILS_PRF_KEY_LEN_16 = 0x00000000 // KDF details for PRF, source key length is 16 bytes
const KDF_DETAILS_PRF_KEY_LEN_32 = 0x00000001 // KDF details for PRF, source key length is 32 bytes
const KDF_DETAILS_PRF_KEY_LEN_48 = 0x00000002 // KDF details for PRF, source key length is 48 bytes
const KDF_DETAILS_PRF_KEY_LEN_64 = 0x00000003 // KDF details for PRF, source key length is 64 bytes

const KDF_DETAILS_PRF_TARGET_LEN_MASK = 0x00000100 // KDF details for PRF, target length mask
const KDF_DETAILS_PRF_TARGET_LEN_32 = 0x00000000 // KDF details for PRF, target length is 32 bytes
const KDF_DETAILS_PRF_TARGET_LEN_64 = 0x00000100 // KDF details for PRF, target length is 64 bytes

const KDF_DETAILS_PRF_AEAD_MASK = 0x00000600 // KDF details for PRF, AEAD processing mask
const KDF_DETAILS_PRF_AEAD_MODE0 = 0x00000000 // KDF details for PRF, AEAD no processing
const KDF_DETAILS_PRF_AEAD_MODE2 = 0x00000400 // KDF details for PRF, AEAD generate 96 bytes, ignore first 32
const KDF_DETAILS_PRF_AEAD_MODE3 = 0x00000600 // KDF details for PRF, AEAD generate 96 bytes, ignore first 32, split remaining between target and output

const KDF_DETAILS_AES_KEY_LOC_MASK = 0x00000003 // KDF details for AES, key location mask

const KDF_DETAILS_HKDF_MSG_LOC_MASK = 0x00000003 // KDF details for HKDF, message location mask
const KDF_DETAILS_HKDF_MSG_LOC_SLOT = 0x00000000 // KDF details for HKDF, message location in slot
const KDF_DETAILS_HKDF_MSG_LOC_TEMPKEY = 0x00000001 // KDF details for HKDF, message location in TempKey
const KDF_DETAILS_HKDF_MSG_LOC_INPUT = 0x00000002 // KDF details for HKDF, message location in input parameter
const KDF_DETAILS_HKDF_MSG_LOC_IV = 0x00000003 // KDF details for HKDF, message location is a special IV function
const KDF_DETAILS_HKDF_ZERO_KEY = 0x00000004 // KDF details for HKDF, key is 32 bytes of zero

/** \name Definitions for the Lock Command @{ */
const LOCK_ZONE_IDX = ATCA_PARAM1_IDX // Lock command index for zone
const LOCK_SUMMARY_IDX = ATCA_PARAM2_IDX // Lock command index for summary
const LOCK_COUNT = ATCA_CMD_SIZE_MIN // Lock command packet size
const LOCK_ZONE_CONFIG = 0x00 // Lock zone is Config
const LOCK_ZONE_DATA = 0x01 // Lock zone is OTP or Data
const LOCK_ZONE_DATA_SLOT = 0x02 // Lock slot of Data
const LOCK_ZONE_NO_CRC = 0x80 // Lock command: Ignore summary.
const LOCK_ZONE_MASK = (0xBF) // Lock parameter 1 bits 6 are 0.
const ATCA_UNLOCKED = (0x55) // Value indicating an unlocked zone
const ATCA_LOCKED = (0x00) // Value indicating a locked zone
const LOCK_RSP_SIZE = ATCA_RSP_SIZE_MIN // Lock command response packet size

/** \name Definitions for the MAC Command @{ */
const MAC_MODE_IDX = ATCA_PARAM1_IDX // MAC command index for mode
const MAC_KEYID_IDX = ATCA_PARAM2_IDX // MAC command index for key id
const MAC_CHALLENGE_IDX = ATCA_DATA_IDX // MAC command index for optional challenge
const MAC_COUNT_SHORT = ATCA_CMD_SIZE_MIN // MAC command packet size without challenge
const MAC_COUNT_LONG = (39) // MAC command packet size with challenge
const MAC_MODE_CHALLENGE = 0x00 // MAC mode       0: first SHA block from data slot
const MAC_MODE_BLOCK2_TEMPKEY = 0x01 // MAC mode bit   0: second SHA block from TempKey
const MAC_MODE_BLOCK1_TEMPKEY = 0x02 // MAC mode bit   1: first SHA block from TempKey
const MAC_MODE_SOURCE_FLAG_MATCH = 0x04 // MAC mode bit   2: match TempKey.SourceFlag
const MAC_MODE_PTNONCE_TEMPKEY = 0x06 // MAC mode bit   0: second SHA block from TempKey
const MAC_MODE_PASSTHROUGH = 0x07 // MAC mode bit 0-2: pass-through mode
const MAC_MODE_INCLUDE_OTP_88 = 0x10 // MAC mode bit   4: include first 88 OTP bits
const MAC_MODE_INCLUDE_OTP_64 = 0x20 // MAC mode bit   5: include first 64 OTP bits
const MAC_MODE_INCLUDE_SN = 0x40 // MAC mode bit   6: include serial number
const MAC_CHALLENGE_SIZE = (32) // MAC size of challenge
const MAC_SIZE = (32) // MAC size of response
const MAC_MODE_MASK = 0x77 // MAC mode bits 3 and 7 are 0.
const MAC_RSP_SIZE = ATCA_RSP_SIZE_32 // MAC command response packet size

/** \name Definitions for the Nonce Command @{ */
const NONCE_MODE_IDX = ATCA_PARAM1_IDX // Nonce command index for mode
const NONCE_PARAM2_IDX = ATCA_PARAM2_IDX // Nonce command index for 2. parameter
const NONCE_INPUT_IDX = ATCA_DATA_IDX // Nonce command index for input data
const NONCE_COUNT_SHORT = (ATCA_CMD_SIZE_MIN + 20) // Nonce command packet size for 20 bytes of NumIn
const NONCE_COUNT_LONG = (ATCA_CMD_SIZE_MIN + 32) // Nonce command packet size for 32 bytes of NumIn
const NONCE_COUNT_LONG_64 = (ATCA_CMD_SIZE_MIN + 64) // Nonce command packet size for 64 bytes of NumIn
const NONCE_MODE_MASK = 0x03 // Nonce mode bits 2 to 7 are 0.
const NONCE_MODE_SEED_UPDATE = 0x00 // Nonce mode: update seed
const NONCE_MODE_NO_SEED_UPDATE = 0x01 // Nonce mode: do not update seed
const NONCE_MODE_INVALID = 0x02 // Nonce mode 2 is invalid.
const NONCE_MODE_PASSTHROUGH = 0x03 // Nonce mode: pass-through

const NONCE_MODE_INPUT_LEN_MASK = 0x20 // Nonce mode: input size mask
const NONCE_MODE_INPUT_LEN_32 = 0x00 // Nonce mode: input size is 32 bytes
const NONCE_MODE_INPUT_LEN_64 = 0x20 // Nonce mode: input size is 64 bytes

const NONCE_MODE_TARGET_MASK = 0xC0 // Nonce mode: target mask
const NONCE_MODE_TARGET_TEMPKEY = 0x00 // Nonce mode: target is TempKey
const NONCE_MODE_TARGET_MSGDIGBUF = 0x40 // Nonce mode: target is Message Digest Buffer
const NONCE_MODE_TARGET_ALTKEYBUF = 0x80 // Nonce mode: target is Alternate Key Buffer

const NONCE_ZERO_CALC_MASK = 0x8000 // Nonce zero (param2): calculation mode mask
const NONCE_ZERO_CALC_RANDOM = 0x0000 // Nonce zero (param2): calculation mode random, use RNG in calculation and return RNG output
const NONCE_ZERO_CALC_TEMPKEY = 0x8000 // Nonce zero (param2): calculation mode TempKey, use TempKey in calculation and return new TempKey value

const NONCE_NUMIN_SIZE = (20) // Nonce NumIn size for random modes
const NONCE_NUMIN_SIZE_PASSTHROUGH = (32) // Nonce NumIn size for 32-byte pass-through mode

const NONCE_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN // Nonce command response packet size with no output
const NONCE_RSP_SIZE_LONG = ATCA_RSP_SIZE_32 // Nonce command response packet size with output

/** \name Definitions for the Pause Command @{ */
const PAUSE_SELECT_IDX = ATCA_PARAM1_IDX // Pause command index for Selector
const PAUSE_PARAM2_IDX = ATCA_PARAM2_IDX // Pause command index for 2. parameter
const PAUSE_COUNT = ATCA_CMD_SIZE_MIN // Pause command packet size
const PAUSE_RSP_SIZE = ATCA_RSP_SIZE_MIN // Pause command response packet size

/** \name Definitions for the PrivWrite Command @{ */
const PRIVWRITE_ZONE_IDX = ATCA_PARAM1_IDX // PrivWrite command index for zone
const PRIVWRITE_KEYID_IDX = ATCA_PARAM2_IDX // PrivWrite command index for KeyID
const PRIVWRITE_VALUE_IDX = (5) // PrivWrite command index for value
const PRIVWRITE_MAC_IDX = (41) // PrivWrite command index for MAC
const PRIVWRITE_COUNT = (75) // PrivWrite command packet size
const PRIVWRITE_ZONE_MASK = 0x40 // PrivWrite zone bits 0 to 5 and 7 are 0.
const PRIVWRITE_MODE_ENCRYPT = 0x40 // PrivWrite mode: encrypted
const PRIVWRITE_RSP_SIZE = ATCA_RSP_SIZE_MIN // PrivWrite command response packet size

/** \name Definitions for the Random Command @{ */
const RANDOM_MODE_IDX = ATCA_PARAM1_IDX // Random command index for mode
const RANDOM_PARAM2_IDX = ATCA_PARAM2_IDX // Random command index for 2. parameter
const RANDOM_COUNT = ATCA_CMD_SIZE_MIN // Random command packet size
const RANDOM_SEED_UPDATE = 0x00 // Random mode for automatic seed update
const RANDOM_NO_SEED_UPDATE = 0x01 // Random mode for no seed update
const RANDOM_NUM_SIZE = 32 // Number of bytes in the data packet of a random command
const RANDOM_RSP_SIZE = ATCA_RSP_SIZE_32 // Random command response packet size

/** \name Definitions for the Read Command @{ */
const READ_ZONE_IDX = ATCA_PARAM1_IDX // Read command index for zone
const READ_ADDR_IDX = ATCA_PARAM2_IDX // Read command index for address
const READ_COUNT = ATCA_CMD_SIZE_MIN // Read command packet size
const READ_ZONE_MASK = 0x83 // Read zone bits 2 to 6 are 0.
const READ_4_RSP_SIZE = ATCA_RSP_SIZE_VAL // Read command response packet size when reading 4 bytes
const READ_32_RSP_SIZE = ATCA_RSP_SIZE_32 // Read command response packet size when reading 32 bytes

/** \name Definitions for the SecureBoot Command @{ */
const SECUREBOOT_MODE_IDX = ATCA_PARAM1_IDX // SecureBoot command index for mode
const SECUREBOOT_DIGEST_SIZE = (32) // SecureBoot digest input size
const SECUREBOOT_SIGNATURE_SIZE = (64) // SecureBoot signature input size
const SECUREBOOT_COUNT_DIG = (ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE) // SecureBoot command packet size for just a digest
const SECUREBOOT_COUNT_DIG_SIG = (ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE) // SecureBoot command packet size for a digest and signature
const SECUREBOOT_MAC_SIZE = (32) // SecureBoot MAC output size
const SECUREBOOT_RSP_SIZE_NO_MAC = ATCA_RSP_SIZE_MIN // SecureBoot response packet size for no MAC
const SECUREBOOT_RSP_SIZE_MAC = (ATCA_PACKET_OVERHEAD + SECUREBOOT_MAC_SIZE) // SecureBoot response packet size with MAC

const SECUREBOOT_MODE_MASK = 0x07 // SecureBoot mode mask
const SECUREBOOT_MODE_FULL = 0x05 // SecureBoot mode Full
const SECUREBOOT_MODE_FULL_STORE = 0x06 // SecureBoot mode FullStore
const SECUREBOOT_MODE_FULL_COPY = 0x07 // SecureBoot mode FullCopy
const SECUREBOOT_MODE_PROHIBIT_FLAG = 0x40 // SecureBoot mode flag to prohibit SecureBoot until next power cycle
const SECUREBOOT_MODE_ENC_MAC_FLAG = 0x80 // SecureBoot mode flag for encrypted digest and returning validating MAC

const SECUREBOOTCONFIG_OFFSET = (70) // SecureBootConfig byte offset into the configuration zone
const SECUREBOOTCONFIG_MODE_MASK = 0x0003 // Mask for SecureBootMode field in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_DISABLED = 0x0000 // Disabled SecureBootMode in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_FULL_BOTH = 0x0001 // Both digest and signature always required SecureBootMode in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_FULL_SIG = 0x0002 // Signature stored SecureBootMode in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_FULL_DIG = 0x0003 // Digest stored SecureBootMode in SecureBootConfig value

/** \name Definitions for the SelfTest Command @{ */
const SELFTEST_MODE_IDX = ATCA_PARAM1_IDX // SelfTest command index for mode
const SELFTEST_COUNT = ATCA_CMD_SIZE_MIN // SelfTest command packet size
const SELFTEST_MODE_RNG = 0x01 // SelfTest mode RNG DRBG function
const SELFTEST_MODE_ECDSA_VERIFY = 0x02 // SelfTest mode ECDSA verify function
const SELFTEST_MODE_ECDSA_SIGN = 0x04 // SelfTest mode ECDSA sign function
const SELFTEST_MODE_ECDH = 0x08 // SelfTest mode ECDH function
const SELFTEST_MODE_AES = 0x10 // SelfTest mode AES encrypt function
const SELFTEST_MODE_SHA = 0x20 // SelfTest mode SHA function
const SELFTEST_MODE_ALL = 0x3F // SelfTest mode all algorithms
const SELFTEST_RSP_SIZE = ATCA_RSP_SIZE_MIN // SelfTest command response packet size

/** \name Definitions for the SHA Command @{ */
const SHA_COUNT_SHORT = ATCA_CMD_SIZE_MIN
const SHA_COUNT_LONG = ATCA_CMD_SIZE_MIN // Just a starting size
const ATCA_SHA_DIGEST_SIZE = (32)
const SHA_DATA_MAX = (64)
const ATCA_SHA256_BLOCK_SIZE = (64)
const SHA_CONTEXT_MAX_SIZE = (99)

const SHA_MODE_MASK = 0x07 // Mask the bit 0-2
const SHA_MODE_SHA256_START = 0x00 // Initialization, does not accept a message
const SHA_MODE_SHA256_UPDATE = 0x01 // Add 64 bytes in the meesage to the SHA context
const SHA_MODE_SHA256_END = 0x02 // Complete the calculation and return the digest
const SHA_MODE_SHA256_PUBLIC = 0x03 // Add 64 byte ECC public key in the slot to the SHA context
const SHA_MODE_HMAC_START = 0x04 // Initialization, HMAC calculation
const SHA_MODE_HMAC_UPDATE = 0x01 // Add 64 bytes in the meesage to the SHA context
const SHA_MODE_HMAC_END = 0x05 // Complete the HMAC computation and return digest
const SHA_MODE_608_HMAC_END = 0x02 // Complete the HMAC computation and return digest... Different command on 608
const SHA_MODE_READ_CONTEXT = 0x06 // Read current SHA-256 context out of the device
const SHA_MODE_WRITE_CONTEXT = 0x07 // Restore a SHA-256 context into the device
const SHA_MODE_TARGET_MASK = 0xC0 // Resulting digest target location mask
const SHA_MODE_TARGET_TEMPKEY = 0x00 // Place resulting digest both in Output buffer and TempKey
const SHA_MODE_TARGET_MSGDIGBUF = 0x40 // Place resulting digest both in Output buffer and Message Digest Buffer
const SHA_MODE_TARGET_OUT_ONLY = 0xC0 // Place resulting digest both in Output buffer ONLY

const SHA_RSP_SIZE = ATCA_RSP_SIZE_32 // SHA command response packet size
const SHA_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN // SHA command response packet size only status code
const SHA_RSP_SIZE_LONG = ATCA_RSP_SIZE_32 // SHA command response packet size

/** @} *//** \name Definitions for the Sign Command @{ */
const SIGN_MODE_IDX = ATCA_PARAM1_IDX // Sign command index for mode
const SIGN_KEYID_IDX = ATCA_PARAM2_IDX // Sign command index for key id
const SIGN_COUNT = ATCA_CMD_SIZE_MIN // Sign command packet size
const SIGN_MODE_MASK = 0xE1 // Sign mode bits 1 to 4 are 0
const SIGN_MODE_INTERNAL = 0x00 // Sign mode   0: internal
const SIGN_MODE_INVALIDATE = 0x01 // Sign mode bit 1: Signature will be used for Verify(Invalidate)
const SIGN_MODE_INCLUDE_SN = 0x40 // Sign mode bit 6: include serial number
const SIGN_MODE_EXTERNAL = 0x80 // Sign mode bit 7: external
const SIGN_MODE_SOURCE_MASK = 0x20 // Sign mode message source mask
const SIGN_MODE_SOURCE_TEMPKEY = 0x00 // Sign mode message source is TempKey
const SIGN_MODE_SOURCE_MSGDIGBUF = 0x20 // Sign mode message source is the Message Digest Buffer
const SIGN_RSP_SIZE = ATCA_RSP_SIZE_MAX // Sign command response packet size

/** \name Definitions for the UpdateExtra Command @{ */
const UPDATE_MODE_IDX = ATCA_PARAM1_IDX // UpdateExtra command index for mode
const UPDATE_VALUE_IDX = ATCA_PARAM2_IDX // UpdateExtra command index for new value
const UPDATE_COUNT = ATCA_CMD_SIZE_MIN // UpdateExtra command packet size
const UPDATE_MODE_USER_EXTRA = 0x00 // UpdateExtra mode update UserExtra (config byte 84)
const UPDATE_MODE_SELECTOR = 0x01 // UpdateExtra mode update Selector (config byte 85)
const UPDATE_MODE_USER_EXTRA_ADD = UPDATE_MODE_SELECTOR // UpdateExtra mode update UserExtraAdd (config byte 85)
const UPDATE_MODE_DEC_COUNTER = 0x02 // UpdateExtra mode: decrement counter
const UPDATE_RSP_SIZE = ATCA_RSP_SIZE_MIN // UpdateExtra command response packet size

/** \name Definitions for the Verify Command @{ */
const VERIFY_MODE_IDX = ATCA_PARAM1_IDX // Verify command index for mode
const VERIFY_KEYID_IDX = ATCA_PARAM2_IDX // Verify command index for key id
const VERIFY_DATA_IDX = (5) // Verify command index for data
const VERIFY_256_STORED_COUNT = (71) // Verify command packet size for 256-bit key in stored mode
const VERIFY_283_STORED_COUNT = (79) // Verify command packet size for 283-bit key in stored mode
const VERIFY_256_VALIDATE_COUNT = (90) // Verify command packet size for 256-bit key in validate mode
const VERIFY_283_VALIDATE_COUNT = (98) // Verify command packet size for 283-bit key in validate mode
const VERIFY_256_EXTERNAL_COUNT = (135) // Verify command packet size for 256-bit key in external mode
const VERIFY_283_EXTERNAL_COUNT = (151) // Verify command packet size for 283-bit key in external mode
const VERIFY_256_KEY_SIZE = (64) // Verify key size for 256-bit key
const VERIFY_283_KEY_SIZE = (72) // Verify key size for 283-bit key
const VERIFY_256_SIGNATURE_SIZE = (64) // Verify signature size for 256-bit key
const VERIFY_283_SIGNATURE_SIZE = (72) // Verify signature size for 283-bit key
const VERIFY_OTHER_DATA_SIZE = (19) // Verify size of "other data"
const VERIFY_MODE_MASK = 0x03 // Verify mode bits 2 to 7 are 0
const VERIFY_MODE_STORED = 0x00 // Verify mode: stored
const VERIFY_MODE_VALIDATE_EXTERNAL = 0x01 // Verify mode: validate external
const VERIFY_MODE_EXTERNAL = 0x02 // Verify mode: external
const VERIFY_MODE_VALIDATE = 0x03 // Verify mode: validate
const VERIFY_MODE_INVALIDATE = 0x07 // Verify mode: invalidate
const VERIFY_MODE_SOURCE_MASK = 0x20 // Verify mode message source mask
const VERIFY_MODE_SOURCE_TEMPKEY = 0x00 // Verify mode message source is TempKey
const VERIFY_MODE_SOURCE_MSGDIGBUF = 0x20 // Verify mode message source is the Message Digest Buffer
const VERIFY_MODE_MAC_FLAG = 0x80 // Verify mode: MAC
const VERIFY_KEY_B283 = 0x0000 // Verify key type: B283
const VERIFY_KEY_K283 = 0x0001 // Verify key type: K283
const VERIFY_KEY_P256 = 0x0004 // Verify key type: P256
const VERIFY_RSP_SIZE = ATCA_RSP_SIZE_MIN // Verify command response packet size
const VERIFY_RSP_SIZE_MAC = ATCA_RSP_SIZE_32 // Verify command response packet size with validating MAC

/** \name Definitions for the Write Command @{ */
const WRITE_ZONE_IDX = ATCA_PARAM1_IDX // Write command index for zone
const WRITE_ADDR_IDX = ATCA_PARAM2_IDX // Write command index for address
const WRITE_VALUE_IDX = ATCA_DATA_IDX // Write command index for data
const WRITE_MAC_VS_IDX = (9) // Write command index for MAC following short data
const WRITE_MAC_VL_IDX = (37) // Write command index for MAC following long data
const WRITE_MAC_SIZE = (32) // Write MAC size
const WRITE_ZONE_MASK = 0xC3 // Write zone bits 2 to 5 are 0.
const WRITE_ZONE_WITH_MAC = 0x40 // Write zone bit 6: write encrypted with MAC
const WRITE_ZONE_OTP = 1 // Write zone id OTP
const WRITE_ZONE_DATA = 2 // Write zone id data
const WRITE_RSP_SIZE = ATCA_RSP_SIZE_MIN // Write command response packet size

// typedef enum atcacert_date_format_e {
const DATEFMT_ISO8601_SEP = 0 //! < ISO8601 full date YYYY-MM-DDThh:mm:ssZ
const DATEFMT_RFC5280_UTC = 1 //! < RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
const DATEFMT_POSIX_UINT32_BE = 2 //! < POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
const DATEFMT_POSIX_UINT32_LE = 3 //! < POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
const DATEFMT_RFC5280_GEN = 4 //! < RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ
// } atcacert_date_format_t;

// typedef enum atcacert_cert_type_e {
const CERTTYPE_X509 = 0 //! < Standard X509 certificate
const CERTTYPE_CUSTOM = 1 //! < Custom format
// } atcacert_cert_type_t;

// typedef enum atcacert_cert_sn_src_e {
const SNSRC_STORED = 0x0 //! < Cert serial is stored on the device.
const SNSRC_STORED_DYNAMIC = 0x7 //! < Cert serial is stored on the device with the first byte being the DER size (X509 certs only).
const SNSRC_DEVICE_SN = 0x8 //! < Cert serial number is 0x40(MSB) + 9-byte device serial number. Only applies to device certificates.
const SNSRC_SIGNER_ID = 0x9 //! < Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to signer certificates.
const SNSRC_PUB_KEY_HASH = 0xA //! < Cert serial number is the SHA256(Subject public key + Encoded dates), with uppermost 2 bits set to 01.
const SNSRC_DEVICE_SN_HASH = 0xB //! < Cert serial number is the SHA256(Device SN + Encoded dates), with uppermost 2 bits set to 01. Only applies to device certificates.
const SNSRC_PUB_KEY_HASH_POS = 0xC //! < Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates), with MSBit set to 0 to ensure it's positive.
const SNSRC_DEVICE_SN_HASH_POS = 0xD //! < Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates), with MSBit set to 0 to ensure it's positive. Only applies to device certificates.
const SNSRC_PUB_KEY_HASH_RAW = 0xE //! < Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates).
const SNSRC_DEVICE_SN_HASH_RAW = 0xF //! < Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates). Only applies to device certificates.
// } atcacert_cert_sn_src_t;

// typedef enum atcacert_device_zone_e {
const DEVZONE_CONFIG = 0x00 //! < Configuration zone.
const DEVZONE_OTP = 0x01 //! < One Time Programmable zone.
const DEVZONE_DATA = 0x02 //! < Data zone (slots).
const DEVZONE_NONE = 0x07 //! < Special value used to indicate there is no device location.
// } atcacert_device_zone_t;

// typedef enum atcacert_std_cert_element_e {
const STDCERT_PUBLIC_KEY = 0
const STDCERT_SIGNATURE = 1
const STDCERT_ISSUE_DATE = 2
const STDCERT_EXPIRE_DATE = 3
const STDCERT_SIGNER_ID = 4
const STDCERT_CERT_SN = 5
const STDCERT_AUTH_KEY_ID = 6
const STDCERT_SUBJ_KEY_ID = 7
const STDCERT_NUM_ELEMENTS = 8 //! < Special item to give the number of elements in this enum
// } atcacert_std_cert_element_t;

const g_csr_template_2_device = Buffer.from([
  0x30, 0x81, 0xfb, 0x30, 0x81, 0xa2, 0x02, 0x01, 0x00, 0x30, 0x2f, 0x31, 0x14, 0x30, 0x12, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e,
  0x63, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x45, 0x78, 0x61, 0x6d,
  0x70, 0x6c, 0x65, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
  0x07, 0x03, 0x42, 0x00, 0x04, 0xd8, 0x70, 0xa4, 0xdf, 0x98, 0xb4, 0x6a, 0x93, 0x2b, 0xf7, 0x40,
  0x39, 0x86, 0x0f, 0xed, 0xd6, 0x69, 0x03, 0x6a, 0xe7, 0xe4, 0x84, 0x9f, 0xfc, 0xfb, 0x61, 0x50,
  0x63, 0x21, 0x95, 0xa8, 0x91, 0x2c, 0x98, 0x04, 0x0e, 0x9c, 0x2f, 0x03, 0xe1, 0xe4, 0x2e, 0xc7,
  0x93, 0x8c, 0x6b, 0xf4, 0xfb, 0x98, 0x4c, 0x50, 0xdb, 0x51, 0xa3, 0xee, 0x04, 0x1b, 0x55, 0xf0,
  0x60, 0x63, 0xeb, 0x46, 0x90, 0xa0, 0x11, 0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x09, 0x0e, 0x31, 0x02, 0x30, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x26, 0xab, 0x8a, 0x4f, 0x71,
  0x2c, 0xf9, 0xbb, 0x4f, 0xfa, 0xa4, 0xcd, 0x01, 0x48, 0xf1, 0xdf, 0x9c, 0xdc, 0xff, 0xa0, 0xff,
  0x53, 0x8f, 0x35, 0x8d, 0xd4, 0x3d, 0x49, 0xc0, 0x72, 0xf5, 0x0a, 0x02, 0x21, 0x00, 0xa5, 0x9d,
  0xb4, 0x11, 0x4b, 0xa1, 0x65, 0x7c, 0xbb, 0x48, 0xcf, 0x6d, 0xf6, 0xd0, 0x6a, 0x41, 0x00, 0x96,
  0xe1, 0xe2, 0x79, 0x73, 0xdb, 0xf7, 0x97, 0x80, 0x41, 0x9b, 0x35, 0x01, 0x88, 0x5e
])

const g_csr_def_2_device = {
  type: CERTTYPE_X509,
  template_id: 3,
  chain_id: 0,
  private_key_slot: 0,
  sn_source: SNSRC_PUB_KEY_HASH,
  cert_sn_dev_loc: {
    zone: DEVZONE_NONE,
    slot: 0,
    is_genkey: 0,
    offset: 0,
    count: 0
  },
  issue_date_format: DATEFMT_RFC5280_UTC,
  expire_date_format: DATEFMT_RFC5280_UTC,
  tbs_cert_loc: {
    offset: 3,
    count: 165
  },
  expire_years: 0,
  public_key_dev_loc: {
    zone: DEVZONE_NONE,
    slot: 0,
    is_genkey: 1,
    offset: 0,
    count: 64
  },
  comp_cert_dev_loc: {
    zone: DEVZONE_NONE,
    slot: 0,
    is_genkey: 0,
    offset: 0,
    count: 0
  },
  std_cert_elements: [
    { // STDCERT_PUBLIC_KEY
      offset: 85,
      count: 64
    },
    { // STDCERT_SIGNATURE
      offset: 180,
      count: 74
    },
    { // STDCERT_ISSUE_DATE
      offset: 0,
      count: 0
    },
    { // STDCERT_EXPIRE_DATE
      offset: 0,
      count: 0
    },
    { // STDCERT_SIGNER_ID
      offset: 0,
      count: 0
    },
    { // STDCERT_CERT_SN
      offset: 0,
      count: 0
    },
    { // STDCERT_AUTH_KEY_ID
      offset: 0,
      count: 0
    },
    { // STDCERT_SUBJ_KEY_ID
      offset: 0,
      count: 0
    }
  ],
  cert_elements: null,
  cert_elements_count: 0,
  cert_template: g_csr_template_2_device,
  cert_template_size: g_csr_template_2_device.length
}



class EccError extends Error {
  constructor(message, code) {
    super(message)
    this.code = code
  }
}

// provisioning_task.h
const AWS_ECCx08A_I2C_ADDRESS = 0xB0

// ecc_configure.c
const AWS_CONFIG = [
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  AWS_ECCx08A_I2C_ADDRESS, 0x00, 0xAA, 0x00, 0x8F, 0x20, 0xC4, 0x44, 0x87, 0x20, 0x87, 0x20, 0x8F, 0x0F, 0xC4, 0x36,
  0x9F, 0x0F, 0x82, 0x20, 0x0F, 0x0F, 0xC4, 0x44, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
  0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x13, 0x00, 0x7C, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x33, 0x00,
  0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00
]

const validZones = [ATCA_ZONE_CONFIG, ATCA_ZONE_DATA, ATCA_ZONE_OTP]

// return a crc value (uint16_t)
const CRC = data => {
  const polynom = 0x8005 // uint16_t
  let crc_register = 0 // uint16_t
  let shift_register, data_bit, crc_bit // uint8_t

  for (let i = 0; i < data.length; i++) {
    for (shift_register = 0x01;
      shift_register > 0x00;
      shift_register = ((shift_register << 1) & 0xff)) {
      data_bit = ((data[i] & shift_register) & 0xff) ? 1 : 0
      crc_bit = (crc_register >> 15) & 0xff
      crc_register = (crc_register << 1) & 0xffff
      if (data_bit != crc_bit) crc_register ^= polynom
    }
  }

  // return Buffer.from([crc_register, crc_register >> 8])
  return crc_register
}

// lib/basic/atca_basic.c
// return an addr (uint16_t)
const atcabGetAddr = (zone, slot, block, offset) => {
  let addr = 0
  let mem_zone = zone & 0x03 // remove high bits

  if (!validZones.includes(mem_zone)) throw new Error('BAD_PARAM')

  offset = offset & 0x07
  if (mem_zone === ATCA_ZONE_CONFIG || mem_zone === ATCA_ZONE_OTP) {
    addr = block << 3
    addr |= offset
  } else {
    addr = slot << 3
    addr |= offset
    addr |= block << 8
  }

  return addr
}

/**

*/
class Ecc extends EventEmitter {
  constructor (bus) {
    super()

    // promisify
    this.readAsync = Promise.promisify(this.read).bind(this)
    this.dummyWriteAsync = Promise.promisify(this.dummyWrite).bind(this)
    // this.writeAsync = Promise.promisify(this.write).bind(this)

    this.bus = bus
    this.scan()
  }

  scan () {
    this.bus.scan(0x00, 0x7F, (err, addrs) => {
      if (addrs.includes(0xC0 >> 1)) {
        this.addr = 0xC0
        this.emit('initialized')
      } else if (addrs.includes(0xB0 >> 1)) {
        this.addr = 0xB0
        this.emit('initialized')
      }
    })
  }

  read (len, callback) {
    let data = Buffer.alloc(len)
    this.bus.i2cRead(this.addr >> 1, len, data, err => err ? callback(err) : callback(null, data))
  }

  /**
  async readAsync (len) {
    for (let i = 0; i < 100; i++) {
      await new Promise((resolve, reject) => {
        this.read(len, (err, data) => {
        })
      })
    }
  }
*/

  dummyWrite (callback) {
    this.bus.i2cWrite(0x00, 1, Buffer.from([0x00]), () => callback())
  }

  write (data, callback) {
    this.bus.i2cWrite(this.addr >> 1, data.length, data, callback)
  }

  async writeAsync (data) {
    return new Promise((resolve, reject) =>
      this.write(data, err => err ? reject(err) : resolve(null)))
  }


  // TODO delay us in original code, 1500 or 2560
  async wakeAsync () {
    await this.dummyWriteAsync()
    await Promise.delay(3)

    for (let i = 0; i < 20; i++) {
      try {
        let data = await this.readAsync(4)
        if (data.toString('hex') === '04113343') {
          if (i > 0) console.log(`wake read ${i === 1 ? 'twice' : i + 1 + ' times'}`)
          return
        } else {
          console.log(`wake read unexpected data: ${data.toString('hex')}`)
        }
      } finally {
        await Promise.delay(1)
      }
    }

    throw new Error('failed')
  }

  // see idle won't drop anything in mem
  async idleAsync () {
    this.writeAsync(Buffer.from([0x02]))
  }

  // see sleep drop everything
  async sleepAsync () {
    this.writeAsync(Buffer.from([0x01]))
  }

  release (callback) {
  }

  // lib/atca_execution.c in latest cyptoauthlib
  // this command do wake-idle cycle
  async atcaExecuteCommandAsync (packet) {
    let { txsize, opcode, param1, param2, data, rxsize } = packet

    let maxDelayCount = Math.floor(ATCA_POLLING_MAX_TIME_MSEC / ATCA_POLLING_FREQUENCY_TIME_MSEC)

    let wordAddress = Buffer.from([0x03])
    let payload = Buffer.from([txsize, opcode, param1, param2, param2 >> 8])
    payload = Buffer.concat([payload, data])
    let crc = CRC(payload)
    let crcLE = Buffer.from([crc, crc >> 8])

    let cmd = Buffer.concat([wordAddress, payload, crcLE])
    debug('atsend', cmd)

    await this.wakeAsync()
    await this.writeAsync(cmd)

    // initial delay
    await Promise.delay(ATCA_POLLING_INIT_TIME_MSEC)

    let rsp
    do {
      try {
        rsp = await this.readAsync(130)
        break
      } catch (e) {
        if (e.code !== 'ENXIO') {
          await this.idleAsync()
          throw e
        }
      }
     
      await Promise.delay(ATCA_POLLING_FREQUENCY_TIME_MSEC) 
    } while (maxDelayCount-- > 0)

    debug('atreceive', rsp)

    await this.idleAsync()

    if (rsp[0] < 4) throw new Error('invalid count')

    rsp = rsp.slice(0, rsp[0])
    if (CRC(rsp.slice(0, -2)) !== rsp.slice(rsp.length - 2).readUInt16LE(0))
      throw new Error('BAD_CRC')

    return rsp.slice(1, rsp.length - 2)
  }

  // lib/basic/atca_basic_read.c +60
  // return buffer
  async atcabReadZoneAsync (zone, slot, block, offset, len) {
    debug(`atcab_read_zone, zone: ${zone}, slot: ${slot}, block: ${block}, offset: ${offset}, len: ${len}`)

    if (len !== 4 && len !== 32) throw new Error('ATCA_BAD_PARAM')

    let addr = atcabGetAddr(zone, slot, block, offset)
    // let addrLE = ((addr >> 8) & 0xff) | ((addr << 8) & 0xffff)

    if (len === ATCA_BLOCK_SIZE) zone = zone | ATCA_ZONE_READWRITE_32

    // constructing a packet
    let packet = {
      _reserved: null,
      txsize: READ_COUNT,
      opcode: ATCA_READ,
      param1: zone,
      param2: addr,
      data: Buffer.alloc(0),
      execTime: null,
      rxsize: (zone & 0x80) ? READ_32_RSP_SIZE : READ_4_RSP_SIZE
    }

    // atRead will set opcode, txsize, rxsize, and crc (into data)
    // this.atRead(packet)
    return await this.atcaExecuteCommandAsync(packet)
  }

  // lib/basic/atca_basic.c +335
  atcabGetZoneSize (zone, slot) {
    switch (zone) {
      case ATCA_ZONE_CONFIG:
        return 128
      case ATCA_ZONE_OTP:
        return 64
      case ATCA_ZONE_DATA:
        if (slot < 8) {
          return 36
        } else if (slot === 8) {
          return 416
        } else if (slot < 16) {
          return 72
        } else {
          throw new Error('bad param')
        }

      default:
        throw new Error('bad param')
    }
  }

  // lib/basic/atca_basic_read.c +610
  async atcabReadBytesZoneAsync (zone, slot, offset, length) {
    debug(`atcab_read_bytes_zone, zone: ${zone}, slot: ${slot}, offset: ${offset}, length: ${length}`)

    let zone_size = 0
    let data_idx = 0
    let cur_block = 0
    let cur_offset = 0
    let read_size = ATCA_BLOCK_SIZE
    let read_buf_idx = 0
    let copy_length = 0
    let read_offset = 0
    let blocks = []

    if (zone !== ATCA_ZONE_CONFIG && zone !== ATCA_ZONE_OTP && zone !== ATCA_ZONE_DATA) { throw new Error('ATCA_BAD_PARAM') }

    if (zone === ATCA_ZONE_DATA && slot > 15) { throw new Error('ATCA_BAD_PARAM') }

    if (length === 0) return Buffer.alloc(0)

    zone_size = this.atcabGetZoneSize(zone, slot)
    if ((offset + length) > zone_size) throw new Error('ATCA_BAD_PARAM')

    cur_block = offset / ATCA_BLOCK_SIZE

    while (data_idx < length) {
      if (read_size === ATCA_BLOCK_SIZE && zone_size - cur_block * ATCA_BLOCK_SIZE < ATCA_BLOCK_SIZE) {
        // We have less than a block to read and can't read past the end of the zone, switch to word reads
        read_size = ATCA_WORD_SIZE
        cur_offset = ((data_idx + offset) / ATCA_WORD_SIZE) % (ATCA_BLOCK_SIZE / ATCA_WORD_SIZE)
      }

      let read_buf = await this.atcabReadZoneAsync(zone, slot, cur_block, cur_offset, read_size)
      blocks.push(read_buf)

      read_offset = cur_block * ATCA_BLOCK_SIZE + cur_offset * ATCA_WORD_SIZE
      if (read_offset < offset) {
        read_buf_idx = offset - read_offset
      } else {
        read_buf_idx = 0
      }

      if (length - data_idx < read_size - read_buf_idx) {
        copy_length = length - data_idx
      } else {
        copy_length = read_size - read_buf_idx
      }

      // memcpy

      data_idx += copy_length
      if (read_size === ATCA_BLOCK_SIZE) {
        cur_block += 1
      } else {
        cur_offset += 1
      }
    }

    debug('atcab_read_bytes_zone done')
    return Buffer.concat(blocks)
  }

  // lib/basic/atca_basic_read.c +341
  async atcabReadConfigZoneAsync () {
    // TODO validate
    debug('atcab_read_config_zone')
    return this.atcabReadBytesZoneAsync(ATCA_ZONE_CONFIG, 0, 0x00, ATCA_ECC_CONFIG_SIZE)
  }

  // lib/basic/atca_basic_write.c 
  // 1. data is 32 bytes and mac is 32 bytes
  // 2. data is 32 bytes and mac is null
  // 3. data is 4 bytes
  async atcabWriteAsync (zone, addr, _data, mac) {
    // TODO

    let data
    if (zone & ATCA_ZONE_READWRITE_32) {
      if (mac) {
        data = Buffer.concat([
          _data.slice(0, 32),
          mac.slice(0, 32)
        ])
      } else {
        data = _data.slice(0, 32)
      }
    } else {
      data = _data.slice(0, 4)
    }

    let packet = {
      txsize: 7 + data.length,
      opcode: ATCA_WRITE,
      param1: zone,
      param2: addr,
      data,
      execTime: null,
      rxsize: WRITE_RSP_SIZE 
    }

    return this.atcaExecuteCommandAsync(packet)
  }

  // lib/basic/atca_basic_write.c +124
  // data length must be either 4 or 32
  async atcabWriteZoneAsync (zone, slot, block, offset, data) {

    debug('atcab_write_zone', zone, slot, block, offset, data)

    if (data.length !== 4 && data.length !== 32) {
      // console.log(data)
      throw new Error('BAD_PARAM')
    }

    let addr = atcabGetAddr(zone, slot, block, offset)

    if (data.length === ATCA_BLOCK_SIZE) zone = zone | ATCA_ZONE_READWRITE_32

    return this.atcabWriteAsync(zone, addr, data)
  }

  async atcabWriteBytesZoneAsync (zone, slot, offset_bytes, data) {
    let length = data.length

    if (zone !== ATCA_ZONE_CONFIG && zone !== ATCA_ZONE_OTP && zone !== ATCA_ZONE_DATA) {
      throw new Error('BAD_PARAM')
    } else if (zone === ATCA_ZONE_DATA && slot > 15) {
      throw new Error('BAD_PARAM')
    } else if (length === 0) {
      return
    }

    if (offset_bytes % ATCA_WORD_SIZE !== 0 || length % ATCA_WORD_SIZE !== 0) {
      console.log(offset_bytes, length)
      throw new Error('BAD_PARAM')
    }

    let zone_size = 0
    let data_idx = 0
    let cur_block = 0
    let cur_word = 0

    zone_size = this.atcabGetZoneSize(zone, slot)
    if (offset_bytes + length > zone_size) throw new Error('BAD_PARAM')

    cur_block = Math.floor(offset_bytes / ATCA_BLOCK_SIZE)
    cur_word = Math.floor((offset_bytes % ATCA_BLOCK_SIZE) / ATCA_WORD_SIZE)

    while (data_idx < length) {

      // console.log(data_idx)

      if (cur_word === 0 && length - data_idx >= ATCA_BLOCK_SIZE && !(zone === ATCA_ZONE_CONFIG && cur_block === 2)) {
        await this.atcabWriteZoneAsync(zone, slot, cur_block, 0, data.slice(data_idx, data_idx + ATCA_BLOCK_SIZE))
        data_idx += ATCA_BLOCK_SIZE
        cur_block += 1
      } else {
        if (!(zone === ATCA_ZONE_CONFIG && cur_block === 2 && cur_word === 5)) 
          await this.atcabWriteZoneAsync(zone, slot, cur_block, cur_word, data.slice(data_idx, data_idx + ATCA_WORD_SIZE))

        data_idx += ATCA_WORD_SIZE
        cur_word += 1
        if (cur_word === Math.floor(ATCA_BLOCK_SIZE / ATCA_WORD_SIZE)) {
          cur_block += 1
          cur_word = 0
        }
      }
    }
  }

  async atcabUpdateExtraAsync (mode, value) {
    let packet = {
      txsize: UPDATE_COUNT,
      opcode: ATCA_UPDATE_EXTRA,
      param1: mode,
      param2: value,
      rxsize: UPDATE_RSP_SIZE
    }

    await this.atcabExecuteCommand(packet) 
  }

  // should be 128 byte 
  async atcabWriteConfigZoneAsync (data) {
    // TODO validate

    let config_size = this.atcabGetZoneSize(ATCA_ZONE_CONFIG, 0)

    // bypass the first 16-byte device-specific data
    await this.atcabWriteBytesZoneAsync(ATCA_ZONE_CONFIG, 0, 16, data.slice(16))

    try {
      // await this.atcabUpdateExtra(UPDATE_MODE_USER_EXTRA, data[84])
    } catch (e) {
    }

    try {
      // await this.atcabUpdateExtra(UPDATE_MODE_SELECTOR, data[85])
    } catch (e) {
    }
  }

  async writeAWSConfigAsync () {
    debug('write aws config')
    
    let aws_config = Buffer.from(AWS_CONFIG)
    await this.atcabWriteConfigZoneAsync(aws_config)

    let config = await this.atcabReadConfigZoneAsync()

    for (let i = 16; i < aws_config.length; i++) {
      if (i === 86 || i=== 87) {
        if (config[i] !== 0x55) throw new Error('LOCK register not 0x55')
      } else if (aws_config[i] !== config[i]) {
        console.log(i, aws_config[i].toString(16), config[i].toString(16))
        throw new Error('xxx')
      }
    } 

    return config
  }

  /** locking **/

  async atcabLockAsync(mode, summary_crc) {
    let packet = {
      txsize: LOCK_COUNT,
      opcode: ATCA_LOCK,
      param1: mode,
      param2: summary_crc,
      data: Buffer.alloc(0),
      rxsize: LOCK_RSP_SIZE
    }

    return this.atcaExecuteCommandAsync(packet)
  }

  async atcabLockConfigZoneAsync () {
    return this.atcabLockAsync(LOCK_ZONE_NO_CRC | LOCK_ZONE_CONFIG, 0)
  }

  async atcabLockConfigZoneCrcAsync (summary_crc) {
    return this.atcabLockAsync(LOCK_ZONE_CONFIG, summary_crc)
  }

  async atcabLockDataZoneAsync () {
    return this.atcabLockAsync(LOCK_ZONE_NO_CRC | LOCK_ZONE_DATA, 0)
  }

  async atcabLockDataZoneCrcAsync (summary_crc) {
    return this.atcabLockAsync(LOCK_ZONE_DATA, summary_crc)
  }

  async atcabLockDataSlot (slot) {
    return this.atcabLockAsync(slot << 2 | LOCK_ZONE_DATA_SLOT, 0)
  }

  /**
  GenKey command 
  1. create private key
  2. generate ecc public key based upone the private key stored in the slot
  3. calculate digest.
      + combines a public key (keyId) with the current TempKey
      + calc sha256 digest of the resulting message
      + place digest back to TempKey
  */
  async atcabGenKeyBaseAsync (mode, keyId, data, publicKey) {
    // mode see table 9-22
    // bit 4 (GENKEY_MODE_PUBKEY_DIGEST)
    // 0 keyId points to a private key
    // 1 keyId points to a pub key
    // bit 3
    // 0 no pubkey digest is created 
    // 1 create a pubkey digest and put in Tempkey
    // bit 2
    // 0 private key currently stored in slot used to generate the public key
    // 1 a random private key is generated and stored in the Slot specified by keyID
    //    KeyType must indicate an ECC key in the KeyConfig area

    if (data && data.length !== GENKEY_OTHER_DATA_SIZE) 
      throw new Error('invalid data')

    let packet = {
      txsize: 0,
      opcode: ATCA_GENKEY,
      param1: mode,
      param2: keyId,
      data: data || Buffer.alloc(0),
      rxsize: 0
    }

    if (mode & GENKEY_MODE_PUBKEY_DIGEST) {
      packet.txsize = GENKEY_COUNT_DATA
      // removed in new lib
      // packet.rxsize = GENKEY_RSP_SIZE_SHORT
    } else {
      packet.txsize = GENKEY_COUNT
      // removed in new lib, bug
      // packet.rxsize = GENKEY_RSP_SIZE_LONG
    }

    console.log(packet)
    
    return await this.atcaExecuteCommandAsync(packet)
  }

  // return public key
  async atcabGenKeyAsync (keyId) {
    return this.atcabGenKeyBaseAsync(GENKEY_MODE_PRIVATE, keyId, null)
  }

  async atcabGenPubKeyAsync (keyId) {
    return this.atcabGenKeyBaseAsync(GENKEY_MODE_PUBLIC, keyId, null)
  }

  async atcabReadPubKey (keySlot) {
    // TODO
  }

  getEffectiveOffset (cert_def, cert, ref_offset) {
    if (cert_dev.type !== CERTTYPE_X509 || 
        cert_def.sn_source !== SNSRC_STORED_DYNAMIC) return 0

    sn_offset = cert_def.std_cert_elements[STDCERT_CERT_SN].offset
    if (ref_offset <= sn_offset) return 0

    return cert[sn_offset] - cert_def.cert_template[sn_offset]
  }

  async atcertSetCertElement (cert_def, cert_loc, cert, cert_size, data) {
    let eff_offset = 0
    let data_size = data.length
    if (cert_loc.count === 0) return  // pretend to succeed.

    

    if (!(cert_def.type === CERTTYPE_X509 && 
          cert_def.sn_source === SNSRC_STORED_DYNAMIC &&
          cert_loc.offset === cert_def.std_cert_elements[STDCERT_CERT_SN].offset) &&
        data_size !== cert_loc.count) 
        throw new Error('unexpected element size')

    let eff_offset = this.getEffectiveOffset(cert_def, cert, cert_loc.offset)

    if (cert_loc.offset + data_size + eff_offset) > cert_size)
      throw new Error('element out of bounds')

    data.copy(cert, cert_loc.offset + eff_offset)
    return
  }

  atcacertGetTBS (cert_def, cert, cert_size) {
    let { offset, count } = cert_def.tbs_cert_loc
    let eff_offset = this.getEffectiveOffset(cert_def, cert, offset + count)

    if (offset + count + effect_offset > cert_size)
      throw new Error('bad cert')

    return cert.slice(offset, offset, count + eff_offset)
  }

  // return tbs_digest
  atcacertGetTBSDigest (cert_def, cert, cert_size) {
    let tbs = this.atcacertGetTBS(cert_def, cert, cert_size)
    let digest = crypto.createHash('sha256').update(tbs).digest()
    return digest
  }

  atcacertDerEncEdcsaSigValue (raw_sig) {
    
  }

  atcacertSetSignature (cert_def, cert, cert_size, max_cert_size, signature) {
    let sig_offset = cert_def.std_cert_elements[STDCERT_SIGNATURE]
    sig_offset += this.getEffectiveOffset(cert_def, cert, sig_offset)

    if (cert_def.type !== CERTTYPE_X509) {
      this.atcacertSetCertElement(cert_def, 
        cert_def.std_cert_elements[STDCERT_SIGNATURE], cert, cert_size, signature)
      // TODO
    }

    if (sig_offset >= cert_size) 
      throw new Error('out of bounds')

    let cur_der_sig_size = cert_size - sig_offset
    let new_der_sig_size = max_cert_size - sig_offset

    
  }

  // create csr (certificate signing request)
  // 
  async atcacertCreateCsrAsync (csr_def) {
    // pub key and sig    
    let pub_key, sig, tbs_digest

    // duplicate
    let csr_max_size = 1500
    let csr_size = csr_def.cert_template_size
    let csr = Buffer.alloc(csr_max_size)
    csr_def.cert_template.copy(csr, 0, 0)

    let pub_loc = csr_def.std_cert_elements[STDCERT_PUBLIC_KEY] 
    let pub_dev_loc = csr_def.public_key_dev_loc
    let key_slot = pub_dev_loc.slot
    let private_key_slot = crs_def.private_key_slot

    if (pub_dev_loc.is_genkey) {
      pub_key = await this.atcabGetPubKey(key_slot)
    } else {
      pub_key = await this.atcabReadPubKey(key_slot)
    }

    // insert public key into csr template 
    this.atcertSetCertElement(csr_def, pub_loc, csr, csr_size, pub_key)

    let tbs_digest = this.atcacertGetTbsDigest(csr_def, csr, csr_size)
    let sig = await atcabSignAsync(private_key_slot, tbs_digest)

    this.atcertSetSignature(csr_def, csr, csr_size, csr_max_size, sig)
  }

  async preconfigCryptoDeviceAsync () {
    let config = await this.atcabReadConfigZoneAsync ()
    console.log(config)

    config = await this.atcabWriteAWSConfigAsync () 

  }
}

module.exports = Ecc

