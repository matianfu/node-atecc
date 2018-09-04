/** \defgroup command ATCACommand (atca_)
   \brief CryptoAuthLib command builder object, ATCACommand.  Member functions for the ATCACommand object.
   @{ */

/** \brief atca_command is the C object backing ATCACommand.
 */
/**
typedef struct
{
    ATCADeviceType dt;
    uint8_t        clock_divider;
    uint16_t       execution_time_msec;
} atca_command;
*/

/* --- ATCACommand --------- */
/**
typedef atca_command* ATCACommand;
ATCACommand newATCACommand(ATCADeviceType device_type);  // constructor
*/
/* add ATCACommand declarations here
 *
 * since these are still C functions, not classes, naming is an important
 * consideration to keep the namespace from colliding with other 3rd party
 * libraries or even ourselves/ASF.
 *
 * Basic conventions:
 * all methods start with the prefix 'at'
 * all method names must be unique, obviously
 * all method implementations should be proceeded by their Doxygen comment header
 *
 **/

// this is the ATCACommand parameter structure.  The caller to the command method must
// initialize param1, param2 and data if appropriate.  The command method will fill in the rest
// and initialize the packet so it's ready to send via the ATCAIFace.
// this particular structure mimics the ATSHA and ATECC family device's command structures

// Note: pack @ 2 is required, @ 1 causes word alignment crash (though it should not), a known bug in GCC.
// @2, the wire still has the intended byte alignment with arm-eabi.  this is likely the least portable part of atca

// #pragma pack( push, ATCAPacket, 2 )
/** \brief an ATCA packet structure.  This is a superset of the packet transmitted on the wire.  It's also
 * used as a buffer for receiving the response
 */
/**
typedef struct
{

    // used for transmit/send
    uint8_t _reserved;  // used by HAL layer as needed (I/O tokens, Word address values)

    //--- start of packet i/o frame----
    uint8_t  txsize;
    uint8_t  opcode;
    uint8_t  param1;    // often same as mode
    uint16_t param2;
    uint8_t  data[130]; // includes 2-byte CRC.  data size is determined by largest possible data section of any
                        // command + crc (see: x08 verify data1 + data2 + data3 + data4)
                        // this is an explicit design trade-off (space) resulting in simplicity in use
                        // and implementation
    //--- end of packet i/o frame

    // used for receive
    uint8_t  execTime;      // execution time of command by opcode
    uint16_t rxsize;        // expected response size, response is held in data member

    // structure should be packed since it will be transmitted over the wire
    // this method varies by compiler.  As new compilers are supported, add their structure packing method here

} ATCAPacket;
#pragma pack( pop, ATCAPacket)
*/
/** \brief Structure to hold the device execution time and the opcode for the corressponding command
 */
/**
typedef struct
{
    uint8_t  opcode;
    uint16_t execution_time_msec;
} device_execution_time_t;
*/

const UNSUPPORTED = 0xFFFF

/**
ATCA_STATUS atCheckMAC(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atCounter(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atDeriveKey(ATCACommand ca_cmd, ATCAPacket *packet, bool has_mac);
ATCA_STATUS atECDH(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atGenDig(ATCACommand ca_cmd, ATCAPacket *packet, bool is_no_mac_key);
ATCA_STATUS atGenKey(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atHMAC(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atInfo(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atLock(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atMAC(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atNonce(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atPause(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atPrivWrite(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atRandom(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atRead(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atSecureBoot(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atSHA(ATCACommand ca_cmd, ATCAPacket *packet, uint16_t write_context_size);
ATCA_STATUS atSign(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atUpdateExtra(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atVerify(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atWrite(ATCACommand ca_cmd, ATCAPacket *packet, bool has_mac);
ATCA_STATUS atAES(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atSelfTest(ATCACommand ca_cmd, ATCAPacket *packet);
ATCA_STATUS atKDF(ATCACommand ca_cmd, ATCAPacket *packet, uint16_t* out_data_size, uint16_t* out_nonce_size);

bool atIsSHAFamily(ATCADeviceType device_type);
bool atIsECCFamily(ATCADeviceType device_type);
ATCA_STATUS isATCAError(uint8_t *data);
*/
// this map is used to index into an array of execution times
/**
typedef enum
{
    WAKE_TWHI,
    CMD_CHECKMAC,
    CMD_COUNTER,
    CMD_DERIVEKEY,
    CMD_ECDH,
    CMD_GENDIG,
    CMD_GENKEY,
    CMD_HMAC,
    CMD_INFO,
    CMD_LOCK,
    CMD_MAC,
    CMD_NONCE,
    CMD_PAUSE,
    CMD_PRIVWRITE,
    CMD_RANDOM,
    CMD_READMEM,
    CMD_SHA,
    CMD_SIGN,
    CMD_UPDATEEXTRA,
    CMD_VERIFY,
    CMD_WRITEMEM,
    CMD_AES,
    CMD_KDF,
    CMD_SECUREBOOT,
    CMD_SELFTEST,
    CMD_LASTCOMMAND  // placeholder
} ATCA_CmdMap;
*/
// ATCA_STATUS atGetExecTime(uint8_t opcode, ATCACommand ca_cmd);

// void deleteATCACommand(ATCACommand *);        // destructor
// ---- end of ATCACommand ----

// command helpers
// void atCRC(size_t length, const uint8_t *data, uint8_t *crc_le);
// void atCalcCrc(ATCAPacket *pkt);
// ATCA_STATUS atCheckCrc(const uint8_t *response);

/* command definitions */

//! minimum number of bytes in command (from count byte to second CRC byte)
const ATCA_CMD_SIZE_MIN = 7
//! maximum size of command packet (Verify)
const ATCA_CMD_SIZE_MAX = 4 * 36 + 7
//! status byte for success
const CMD_STATUS_SUCCESS = 0x00
//! status byte after wake-up
const CMD_STATUS_WAKEUP = 0x11
//! command parse error
const CMD_STATUS_BYTE_PARSE = 0x03
//! command ECC error
const CMD_STATUS_BYTE_ECC = 0x05
//! command execution error
const CMD_STATUS_BYTE_EXEC = 0x0F
//! communication error
const CMD_STATUS_BYTE_COMM = 0xFF

/** \brief
   @{ */

/** \name opcodes for ATATECC Commands @{ */
const ATCA_CHECKMAC = 0x28 //! < CheckMac command op-code
const ATCA_DERIVE_KEY = 0x1C //! < DeriveKey command op-code
const ATCA_INFO = 0x30 //! < Info command op-code
const ATCA_GENDIG = 0x15 //! < GenDig command op-code
const ATCA_GENKEY = 0x40 //! < GenKey command op-code
const ATCA_HMAC = 0x11 //! < HMAC command op-code
const ATCA_LOCK = 0x17 //! < Lock command op-code
const ATCA_MAC = 0x08 //! < MAC command op-code
const ATCA_NONCE = 0x16 //! < Nonce command op-code
const ATCA_PAUSE = 0x01 //! < Pause command op-code
const ATCA_PRIVWRITE = 0x46 //! < PrivWrite command op-code
const ATCA_RANDOM = 0x1B //! < Random command op-code
const ATCA_READ = 0x02 //! < Read command op-code
const ATCA_SIGN = 0x41 //! < Sign command op-code
const ATCA_UPDATE_EXTRA = 0x20 //! < UpdateExtra command op-code
const ATCA_VERIFY = 0x45 //! < GenKey command op-code
const ATCA_WRITE = 0x12 //! < Write command op-code
const ATCA_ECDH = 0x43 //! < ECDH command op-code
const ATCA_COUNTER = 0x24 //! < Counter command op-code
const ATCA_SHA = 0x47 //! < SHA command op-code
const ATCA_AES = 0x51 //! < AES command op-code
const ATCA_KDF = 0x56 //! < KDF command op-code
const ATCA_SECUREBOOT = 0x80 //! < Secure Boot command op-code
const ATCA_SELFTEST = 0x77 //! < Self test command op-code

/** @} */

// promote before ATCA_DATA_SIZE uses it
const ATCA_KEY_SIZE = (32) //! < size of a symmetric SHA key

/** \name Definitions of Data and Packet Sizes
   @{ */
const ATCA_BLOCK_SIZE = (32) //! < size of a block
const ATCA_WORD_SIZE = (4) //! < size of a word
const ATCA_PUB_KEY_PAD = (4) //! < size of the public key pad
const ATCA_SERIAL_NUM_SIZE = (9) //! < number of bytes in the device serial number
const ATCA_RSP_SIZE_VAL = 7 //! < size of response packet containing four bytes of data
const ATCA_KEY_COUNT = (16) //! < number of keys
const ATCA_ECC_CONFIG_SIZE = (128) //! < size of configuration zone
const ATCA_SHA_CONFIG_SIZE = (88) //! < size of configuration zone
const ATCA_OTP_SIZE = (64) //! < size of OTP zone
const ATCA_DATA_SIZE = (ATCA_KEY_COUNT * ATCA_KEY_SIZE) //! < size of data zone
const ATCA_AES_GFM_SIZE = ATCA_BLOCK_SIZE //! < size of GFM data

const ATCA_CHIPMODE_OFFSET = (19) //! < ChipMode byte offset within the configuration zone
const ATCA_CHIPMODE_I2C_ADDRESS_FLAG = 0x01 //! < ChipMode I2C Address in UserExtraAdd flag
const ATCA_CHIPMODE_TTL_ENABLE_FLAG = 0x02 //! < ChipMode TTLenable flag
const ATCA_CHIPMODE_WATCHDOG_MASK = 0x04 //! < ChipMode watchdog duration mask
const ATCA_CHIPMODE_WATCHDOG_SHORT = 0x00 //! < ChipMode short watchdog (~1.3s)
const ATCA_CHIPMODE_WATCHDOG_LONG = 0x04 //! < ChipMode long watchdog (~13s)
const ATCA_CHIPMODE_CLOCK_DIV_MASK = 0xF8 //! < ChipMode clock divider mask
const ATCA_CHIPMODE_CLOCK_DIV_M0 = 0x00 //! < ChipMode clock divider M0
const ATCA_CHIPMODE_CLOCK_DIV_M1 = 0x28 //! < ChipMode clock divider M1
const ATCA_CHIPMODE_CLOCK_DIV_M2 = 0x68 //! < ChipMode clock divider M2

const ATCA_COUNT_SIZE = 1 //! < Number of bytes in the command packet Count
const ATCA_CRC_SIZE = 2 //! < Number of bytes in the command packet CRC
const ATCA_PACKET_OVERHEAD = (ATCA_COUNT_SIZE + ATCA_CRC_SIZE) //! < Number of bytes in the command packet

const ATCA_PUB_KEY_SIZE = (64) //! < size of a p256 public key
const ATCA_PRIV_KEY_SIZE = (32) //! < size of a p256 private key
const ATCA_SIG_SIZE = (64) //! < size of a p256 signature
// const ATCA_KEY_SIZE = (32) //! < size of a symmetric SHA key
const RSA2048_KEY_SIZE = (256) //! < size of a RSA private key

const ATCA_RSP_SIZE_MIN = 4 //! < minimum number of bytes in response
const ATCA_RSP_SIZE_4 = 7 //! < size of response packet containing 4 bytes data
const ATCA_RSP_SIZE_72 = 75 //! < size of response packet containing 64 bytes data
const ATCA_RSP_SIZE_64 = 67 //! < size of response packet containing 64 bytes data
const ATCA_RSP_SIZE_32 = 35 //! < size of response packet containing 32 bytes data
const ATCA_RSP_SIZE_16 = 19 //! < size of response packet containing 16 bytes data
const ATCA_RSP_SIZE_MAX = 75 //! < maximum size of response packet (GenKey and Verify command)

const OUTNONCE_SIZE = (32) //! < Size of the OutNonce response expected from several commands

/** \name Definitions for Command Parameter Ranges
   @{ */
const ATCA_KEY_ID_MAX = 15 //! < maximum value for key id
const ATCA_OTP_BLOCK_MAX = 1 //! < maximum value for OTP block
/** @} */

/** \name Definitions for Indexes Common to All Commands
   @{ */
const ATCA_COUNT_IDX = (0) //! < command packet index for count
const ATCA_OPCODE_IDX = (1) //! < command packet index for op-code
const ATCA_PARAM1_IDX = (2) //! < command packet index for first parameter
const ATCA_PARAM2_IDX = (3) //! < command packet index for second parameter
const ATCA_DATA_IDX = (5) //! < command packet index for data load
const ATCA_RSP_DATA_IDX = (1) //! < buffer index of data in response
/** @} */

/** \name Definitions for Zone and Address Parameters
   @{ */
const ATCA_ZONE_CONFIG = 0x00 //! < Configuration zone
const ATCA_ZONE_OTP = 0x01 //! < OTP (One Time Programming) zone
const ATCA_ZONE_DATA = 0x02 //! < Data zone
const ATCA_ZONE_MASK = 0x03 //! < Zone mask
const ATCA_ZONE_ENCRYPTED = 0x40 //! < Zone bit 6 set: Write is encrypted with an unlocked data zone.
const ATCA_ZONE_READWRITE_32 = 0x80 //! < Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
const ATCA_ADDRESS_MASK_CONFIG = (0x001F) //! < Address bits 5 to 7 are 0 for Configuration zone.
const ATCA_ADDRESS_MASK_OTP = (0x000F) //! < Address bits 4 to 7 are 0 for OTP zone.
const ATCA_ADDRESS_MASK = (0x007F) //! < Address bit 7 to 15 are always 0.
const ATCA_TEMPKEY_KEYID = (0xFFFF) //! < KeyID when referencing TempKey
/** @} */

/** \name Definitions for Key types
   @{ */
const ATCA_B283_KEY_TYPE = 0 //! < B283 NIST ECC key
const ATCA_K283_KEY_TYPE = 1 //! < K283 NIST ECC key
const ATCA_P256_KEY_TYPE = 4 //! < P256 NIST ECC key
const ATCA_AES_KEY_TYPE = 6 //! < AES-128 Key
const ATCA_SHA_KEY_TYPE = 7 //! < SHA key or other data
/** @} */

/** \name Definitions for the AES Command
   @{ */
const AES_MODE_IDX = ATCA_PARAM1_IDX //! < AES command index for mode
const AES_KEYID_IDX = ATCA_PARAM2_IDX //! < AES command index for key id
const AES_INPUT_IDX = ATCA_DATA_IDX //! < AES command index for input data
const AES_COUNT = (23) //! < AES command packet size
const AES_MODE_MASK = 0xC7 //! < AES mode bits 3 to 5 are 0
const AES_MODE_KEY_BLOCK_MASK = 0xC0 //! < AES mode mask for key block field
const AES_MODE_OP_MASK = 0x07 //! < AES mode operation mask
const AES_MODE_ENCRYPT = 0x00 //! < AES mode: Encrypt
const AES_MODE_DECRYPT = 0x01 //! < AES mode: Decrypt
const AES_MODE_GFM = 0x03 //! < AES mode: GFM calculation
const AES_MODE_KEY_BLOCK_POS = (6) //! < Bit shift for key block in mode
const AES_DATA_SIZE = (16) //! < size of AES encrypt/decrypt data
const AES_RSP_SIZE = ATCA_RSP_SIZE_16 //! < AES command response packet size
/** @} */

/** \name Definitions for the CheckMac Command
   @{ */
const CHECKMAC_MODE_IDX = ATCA_PARAM1_IDX //! < CheckMAC command index for mode
const CHECKMAC_KEYID_IDX = ATCA_PARAM2_IDX //! < CheckMAC command index for key identifier
const CHECKMAC_CLIENT_CHALLENGE_IDX = ATCA_DATA_IDX //! < CheckMAC command index for client challenge
const CHECKMAC_CLIENT_RESPONSE_IDX = (37) //! < CheckMAC command index for client response
const CHECKMAC_DATA_IDX = (69) //! < CheckMAC command index for other data
const CHECKMAC_COUNT = (84) //! < CheckMAC command packet size
const CHECKMAC_MODE_CHALLENGE = 0x00 //! < CheckMAC mode     0: first SHA block from key id
const CHECKMAC_MODE_BLOCK2_TEMPKEY = 0x01 //! < CheckMAC mode bit   0: second SHA block from TempKey
const CHECKMAC_MODE_BLOCK1_TEMPKEY = 0x02 //! < CheckMAC mode bit   1: first SHA block from TempKey
const CHECKMAC_MODE_SOURCE_FLAG_MATCH = 0x04 //! < CheckMAC mode bit   2: match TempKey.SourceFlag
const CHECKMAC_MODE_INCLUDE_OTP_64 = 0x20 //! < CheckMAC mode bit   5: include first 64 OTP bits
const CHECKMAC_MODE_MASK = 0x27 //! < CheckMAC mode bits 3, 4, 6, and 7 are 0.
const CHECKMAC_CLIENT_CHALLENGE_SIZE = (32) //! < CheckMAC size of client challenge
const CHECKMAC_CLIENT_RESPONSE_SIZE = (32) //! < CheckMAC size of client response
const CHECKMAC_OTHER_DATA_SIZE = (13) //! < CheckMAC size of "other data"
const CHECKMAC_CLIENT_COMMAND_SIZE = (4) //! < CheckMAC size of client command header size inside "other data"
const CHECKMAC_CMD_MATCH = (0) //! < CheckMAC return value when there is a match
const CHECKMAC_CMD_MISMATCH = (1) //! < CheckMAC return value when there is a mismatch
const CHECKMAC_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < CheckMAC response packet size
/** @} */

/** \name Definitions for the Counter command
   @{ */
const COUNTER_COUNT = ATCA_CMD_SIZE_MIN
const COUNTER_MODE_IDX = ATCA_PARAM1_IDX //! < Counter command index for mode
const COUNTER_KEYID_IDX = ATCA_PARAM2_IDX //! < Counter command index for key id
const COUNTER_MODE_MASK = 0x01 //! < Counter mode bits 1 to 7 are 0
const COUNTER_MAX_VALUE = 2097151 //! < Counter maximum value of the counter
const COUNTER_MODE_READ = 0x00 //! < Counter command mode for reading
const COUNTER_MODE_INCREMENT = 0x01 //! < Counter command mode for incrementing
const COUNTER_RSP_SIZE = ATCA_RSP_SIZE_4 //! < Counter command response packet size
/** @} */

/** \name Definitions for the DeriveKey Command
   @{ */
const DERIVE_KEY_RANDOM_IDX = ATCA_PARAM1_IDX //! < DeriveKey command index for random bit
const DERIVE_KEY_TARGETKEY_IDX = ATCA_PARAM2_IDX //! < DeriveKey command index for target slot
const DERIVE_KEY_MAC_IDX = ATCA_DATA_IDX //! < DeriveKey command index for optional MAC
const DERIVE_KEY_COUNT_SMALL = ATCA_CMD_SIZE_MIN //! < DeriveKey command packet size without MAC
const DERIVE_KEY_MODE = 0x04 //! < DeriveKey command mode set to 4 as in datasheet
const DERIVE_KEY_COUNT_LARGE = (39) //! < DeriveKey command packet size with MAC
const DERIVE_KEY_RANDOM_FLAG = 4 //! < DeriveKey 1. parameter; has to match TempKey.SourceFlag
const DERIVE_KEY_MAC_SIZE = (32) //! < DeriveKey MAC size
const DERIVE_KEY_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < DeriveKey response packet size
/** @} */

/** \name Definitions for the ECDH Command
   @{ */
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
const ECDH_KEY_SIZE = ATCA_BLOCK_SIZE //! < ECDH output data size
const ECDH_RSP_SIZE = ATCA_RSP_SIZE_64 //! < ECDH command packet size
/** @} */

/** \name Definitions for the GenDig Command
   @{ */
const GENDIG_ZONE_IDX = ATCA_PARAM1_IDX //! < GenDig command index for zone
const GENDIG_KEYID_IDX = ATCA_PARAM2_IDX //! < GenDig command index for key id
const GENDIG_DATA_IDX = ATCA_DATA_IDX //! < GenDig command index for optional data
const GENDIG_COUNT = ATCA_CMD_SIZE_MIN //! < GenDig command packet size without "other data"
const GENDIG_ZONE_CONFIG = 0 //! < GenDig zone id config. Use KeyID to specify any of the four 256-bit blocks of the Configuration zone.
const GENDIG_ZONE_OTP = 1 //! < GenDig zone id OTP. Use KeyID to specify either the first or second 256-bit block of the OTP zone.
const GENDIG_ZONE_DATA = 2 //! < GenDig zone id data. Use KeyID to specify a slot in the Data zone or a transport key in the hardware array.
const GENDIG_ZONE_SHARED_NONCE = 3 //! < GenDig zone id shared nonce. KeyID specifies the location of the input value in the message generation.
const GENDIG_ZONE_COUNTER = 4 //! < GenDig zone id counter. KeyID specifies the monotonic counter ID to be included in the message generation.
const GENDIG_ZONE_KEY_CONFIG = 5 //! < GenDig zone id key config. KeyID specifies the slot for which the configuration information is to be included in the message generation.
const GENDIG_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < GenDig command response packet size
/** @} */

/** \name Definitions for the GenKey Command
   @{ */
const GENKEY_MODE_IDX = ATCA_PARAM1_IDX //! < GenKey command index for mode
const GENKEY_KEYID_IDX = ATCA_PARAM2_IDX //! < GenKey command index for key id
const GENKEY_DATA_IDX = (5) //! < GenKey command index for other data
const GENKEY_COUNT = ATCA_CMD_SIZE_MIN //! < GenKey command packet size without "other data"
const GENKEY_COUNT_DATA = (10) //! < GenKey command packet size with "other data"
const GENKEY_OTHER_DATA_SIZE = (3) //! < GenKey size of "other data"
const GENKEY_MODE_MASK = 0x1C //! < GenKey mode bits 0 to 1 and 5 to 7 are 0
const GENKEY_MODE_PRIVATE = 0x04 //! < GenKey mode: private key generation
const GENKEY_MODE_PUBLIC = 0x00 //! < GenKey mode: public key calculation
const GENKEY_MODE_DIGEST = 0x08 //! < GenKey mode: PubKey digest will be created after the public key is calculated
const GENKEY_MODE_PUBKEY_DIGEST = 0x10 //! < GenKey mode: Calculate PubKey digest on the public key in KeyId
const GENKEY_PRIVATE_TO_TEMPKEY = 0xFFFF //! < GenKey Create private key and store to tempkey (608 only)
const GENKEY_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN //! < GenKey response packet size in Digest mode
const GENKEY_RSP_SIZE_LONG = ATCA_RSP_SIZE_72 //! < GenKey response packet size when returning a public key
/** @} */

/** \name Definitions for the HMAC Command
   @{ */
const HMAC_MODE_IDX = ATCA_PARAM1_IDX //! < HMAC command index for mode
const HMAC_KEYID_IDX = ATCA_PARAM2_IDX //! < HMAC command index for key id
const HMAC_COUNT = ATCA_CMD_SIZE_MIN //! < HMAC command packet size
const HMAC_MODE_FLAG_TK_RAND = 0x00 //! < HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
const HMAC_MODE_FLAG_TK_NORAND = 0x04 //! < HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
const HMAC_MODE_FLAG_OTP88 = 0x10 //! < HMAC mode bit 4: Include the first 88 OTP bits (OTP[0] through OTP[10]) in the message.; otherwise, the corresponding message bits are set to zero. Not applicable for ATECC508A.
const HMAC_MODE_FLAG_OTP64 = 0x20 //! < HMAC mode bit 5: Include the first 64 OTP bits (OTP[0] through OTP[7]) in the message.; otherwise, the corresponding message bits are set to zero. If Mode[4] is set, the value of this mode bit is ignored. Not applicable for ATECC508A.
const HMAC_MODE_FLAG_FULLSN = 0x40 //! < HMAC mode bit 6: If set, include the 48 bits SN[2:3] and SN[4:7] in the message.; otherwise, the corresponding message bits are set to zero.
const HMAC_MODE_MASK = 0x74 //! < HMAC mode bits 0, 1, 3, and 7 are 0.
const HMAC_DIGEST_SIZE = (32) //! < HMAC size of digest response
const HMAC_RSP_SIZE = ATCA_RSP_SIZE_32 //! < HMAC command response packet size
/** @} */

/** \name Definitions for the Info Command
   @{ */
const INFO_PARAM1_IDX = ATCA_PARAM1_IDX //! < Info command index for 1. parameter
const INFO_PARAM2_IDX = ATCA_PARAM2_IDX //! < Info command index for 2. parameter
const INFO_COUNT = ATCA_CMD_SIZE_MIN //! < Info command packet size
const INFO_MODE_REVISION = 0x00 //! < Info mode Revision
const INFO_MODE_KEY_VALID = 0x01 //! < Info mode KeyValid
const INFO_MODE_STATE = 0x02 //! < Info mode State
const INFO_MODE_GPIO = 0x03 //! < Info mode GPIO
const INFO_MODE_VOL_KEY_PERMIT = 0x04 //! < Info mode GPIO
const INFO_MODE_MAX = 0x03 //! < Info mode maximum value
const INFO_NO_STATE = 0x00 //! < Info mode is not the state mode.
const INFO_OUTPUT_STATE_MASK = 0x01 //! < Info output state mask
const INFO_DRIVER_STATE_MASK = 0x02 //! < Info driver state mask
const INFO_PARAM2_SET_LATCH_STATE = 0x0002 //! < Info param2 to set the persistent latch state.
const INFO_PARAM2_LATCH_SET = 0x0001 //! < Info param2 to set the persistent latch
const INFO_PARAM2_LATCH_CLEAR = 0x0000 //! < Info param2 to clear the persistent latch
const INFO_SIZE = 0x04 //! < Info return size
const INFO_RSP_SIZE = ATCA_RSP_SIZE_VAL //! < Info command response packet size
/** @} */

/** \name Definitions for the KDF Command
   @{ */
const KDF_MODE_IDX = ATCA_PARAM1_IDX //! < KDF command index for mode
const KDF_KEYID_IDX = ATCA_PARAM2_IDX //! < KDF command index for key id
const KDF_DETAILS_IDX = ATCA_DATA_IDX //! < KDF command index for details
const KDF_DETAILS_SIZE = 4 //! < KDF details (param3) size
const KDF_MESSAGE_IDX = (ATCA_DATA_IDX + KDF_DETAILS_SIZE)

const KDF_MODE_SOURCE_MASK = 0x03 //! < KDF mode source key mask
const KDF_MODE_SOURCE_TEMPKEY = 0x00 //! < KDF mode source key in TempKey
const KDF_MODE_SOURCE_TEMPKEY_UP = 0x01 //! < KDF mode source key in upper TempKey
const KDF_MODE_SOURCE_SLOT = 0x02 //! < KDF mode source key in a slot
const KDF_MODE_SOURCE_ALTKEYBUF = 0x03 //! < KDF mode source key in alternate key buffer

const KDF_MODE_TARGET_MASK = 0x1C //! < KDF mode target key mask
const KDF_MODE_TARGET_TEMPKEY = 0x00 //! < KDF mode target key in TempKey
const KDF_MODE_TARGET_TEMPKEY_UP = 0x04 //! < KDF mode target key in upper TempKey
const KDF_MODE_TARGET_SLOT = 0x08 //! < KDF mode target key in slot
const KDF_MODE_TARGET_ALTKEYBUF = 0x0C //! < KDF mode target key in alternate key buffer
const KDF_MODE_TARGET_OUTPUT = 0x10 //! < KDF mode target key in output buffer
const KDF_MODE_TARGET_OUTPUT_ENC = 0x14 //! < KDF mode target key encrypted in output buffer

const KDF_MODE_ALG_MASK = 0x60 //! < KDF mode algorithm mask
const KDF_MODE_ALG_PRF = 0x00 //! < KDF mode PRF algorithm
const KDF_MODE_ALG_AES = 0x20 //! < KDF mode AES algorithm
const KDF_MODE_ALG_HKDF = 0x40 //! < KDF mode HKDF algorithm

const KDF_DETAILS_PRF_KEY_LEN_MASK = 0x00000003 //! < KDF details for PRF, source key length mask
const KDF_DETAILS_PRF_KEY_LEN_16 = 0x00000000 //! < KDF details for PRF, source key length is 16 bytes
const KDF_DETAILS_PRF_KEY_LEN_32 = 0x00000001 //! < KDF details for PRF, source key length is 32 bytes
const KDF_DETAILS_PRF_KEY_LEN_48 = 0x00000002 //! < KDF details for PRF, source key length is 48 bytes
const KDF_DETAILS_PRF_KEY_LEN_64 = 0x00000003 //! < KDF details for PRF, source key length is 64 bytes

const KDF_DETAILS_PRF_TARGET_LEN_MASK = 0x00000100 //! < KDF details for PRF, target length mask
const KDF_DETAILS_PRF_TARGET_LEN_32 = 0x00000000 //! < KDF details for PRF, target length is 32 bytes
const KDF_DETAILS_PRF_TARGET_LEN_64 = 0x00000100 //! < KDF details for PRF, target length is 64 bytes

const KDF_DETAILS_PRF_AEAD_MASK = 0x00000600 //! < KDF details for PRF, AEAD processing mask
const KDF_DETAILS_PRF_AEAD_MODE0 = 0x00000000 //! < KDF details for PRF, AEAD no processing
const KDF_DETAILS_PRF_AEAD_MODE2 = 0x00000400 //! < KDF details for PRF, AEAD generate 96 bytes, ignore first 32
const KDF_DETAILS_PRF_AEAD_MODE3 = 0x00000600 //! < KDF details for PRF, AEAD generate 96 bytes, ignore first 32, split remaining between target and output

const KDF_DETAILS_AES_KEY_LOC_MASK = 0x00000003 //! < KDF details for AES, key location mask

const KDF_DETAILS_HKDF_MSG_LOC_MASK = 0x00000003 //! < KDF details for HKDF, message location mask
const KDF_DETAILS_HKDF_MSG_LOC_SLOT = 0x00000000 //! < KDF details for HKDF, message location in slot
const KDF_DETAILS_HKDF_MSG_LOC_TEMPKEY = 0x00000001 //! < KDF details for HKDF, message location in TempKey
const KDF_DETAILS_HKDF_MSG_LOC_INPUT = 0x00000002 //! < KDF details for HKDF, message location in input parameter
const KDF_DETAILS_HKDF_MSG_LOC_IV = 0x00000003 //! < KDF details for HKDF, message location is a special IV function
const KDF_DETAILS_HKDF_ZERO_KEY = 0x00000004 //! < KDF details for HKDF, key is 32 bytes of zero
/** @} */

/** \name Definitions for the Lock Command
   @{ */
const LOCK_ZONE_IDX = ATCA_PARAM1_IDX //! < Lock command index for zone
const LOCK_SUMMARY_IDX = ATCA_PARAM2_IDX //! < Lock command index for summary
const LOCK_COUNT = ATCA_CMD_SIZE_MIN //! < Lock command packet size
const LOCK_ZONE_CONFIG = 0x00 //! < Lock zone is Config
const LOCK_ZONE_DATA = 0x01 //! < Lock zone is OTP or Data
const LOCK_ZONE_DATA_SLOT = 0x02 //! < Lock slot of Data
const LOCK_ZONE_NO_CRC = 0x80 //! < Lock command: Ignore summary.
const LOCK_ZONE_MASK = (0xBF) //! < Lock parameter 1 bits 6 are 0.
const ATCA_UNLOCKED = (0x55) //! < Value indicating an unlocked zone
const ATCA_LOCKED = (0x00) //! < Value indicating a locked zone
const LOCK_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < Lock command response packet size
/** @} */

/** \name Definitions for the MAC Command
   @{ */
const MAC_MODE_IDX = ATCA_PARAM1_IDX //! < MAC command index for mode
const MAC_KEYID_IDX = ATCA_PARAM2_IDX //! < MAC command index for key id
const MAC_CHALLENGE_IDX = ATCA_DATA_IDX //! < MAC command index for optional challenge
const MAC_COUNT_SHORT = ATCA_CMD_SIZE_MIN //! < MAC command packet size without challenge
const MAC_COUNT_LONG = (39) //! < MAC command packet size with challenge
const MAC_MODE_CHALLENGE = 0x00 //! < MAC mode       0: first SHA block from data slot
const MAC_MODE_BLOCK2_TEMPKEY = 0x01 //! < MAC mode bit   0: second SHA block from TempKey
const MAC_MODE_BLOCK1_TEMPKEY = 0x02 //! < MAC mode bit   1: first SHA block from TempKey
const MAC_MODE_SOURCE_FLAG_MATCH = 0x04 //! < MAC mode bit   2: match TempKey.SourceFlag
const MAC_MODE_PTNONCE_TEMPKEY = 0x06 //! < MAC mode bit   0: second SHA block from TempKey
const MAC_MODE_PASSTHROUGH = 0x07 //! < MAC mode bit 0-2: pass-through mode
const MAC_MODE_INCLUDE_OTP_88 = 0x10 //! < MAC mode bit   4: include first 88 OTP bits
const MAC_MODE_INCLUDE_OTP_64 = 0x20 //! < MAC mode bit   5: include first 64 OTP bits
const MAC_MODE_INCLUDE_SN = 0x40 //! < MAC mode bit   6: include serial number
const MAC_CHALLENGE_SIZE = (32) //! < MAC size of challenge
const MAC_SIZE = (32) //! < MAC size of response
const MAC_MODE_MASK = 0x77 //! < MAC mode bits 3 and 7 are 0.
const MAC_RSP_SIZE = ATCA_RSP_SIZE_32 //! < MAC command response packet size
/** @} */

/** \name Definitions for the Nonce Command
   @{ */
const NONCE_MODE_IDX = ATCA_PARAM1_IDX //! < Nonce command index for mode
const NONCE_PARAM2_IDX = ATCA_PARAM2_IDX //! < Nonce command index for 2. parameter
const NONCE_INPUT_IDX = ATCA_DATA_IDX //! < Nonce command index for input data
const NONCE_COUNT_SHORT = (ATCA_CMD_SIZE_MIN + 20) //! < Nonce command packet size for 20 bytes of NumIn
const NONCE_COUNT_LONG = (ATCA_CMD_SIZE_MIN + 32) //! < Nonce command packet size for 32 bytes of NumIn
const NONCE_COUNT_LONG_64 = (ATCA_CMD_SIZE_MIN + 64) //! < Nonce command packet size for 64 bytes of NumIn
const NONCE_MODE_MASK = 0x03 //! < Nonce mode bits 2 to 7 are 0.
const NONCE_MODE_SEED_UPDATE = 0x00 //! < Nonce mode: update seed
const NONCE_MODE_NO_SEED_UPDATE = 0x01 //! < Nonce mode: do not update seed
const NONCE_MODE_INVALID = 0x02 //! < Nonce mode 2 is invalid.
const NONCE_MODE_PASSTHROUGH = 0x03 //! < Nonce mode: pass-through

const NONCE_MODE_INPUT_LEN_MASK = 0x20 //! < Nonce mode: input size mask
const NONCE_MODE_INPUT_LEN_32 = 0x00 //! < Nonce mode: input size is 32 bytes
const NONCE_MODE_INPUT_LEN_64 = 0x20 //! < Nonce mode: input size is 64 bytes

const NONCE_MODE_TARGET_MASK = 0xC0 //! < Nonce mode: target mask
const NONCE_MODE_TARGET_TEMPKEY = 0x00 //! < Nonce mode: target is TempKey
const NONCE_MODE_TARGET_MSGDIGBUF = 0x40 //! < Nonce mode: target is Message Digest Buffer
const NONCE_MODE_TARGET_ALTKEYBUF = 0x80 //! < Nonce mode: target is Alternate Key Buffer

const NONCE_ZERO_CALC_MASK = 0x8000 //! < Nonce zero (param2): calculation mode mask
const NONCE_ZERO_CALC_RANDOM = 0x0000 //! < Nonce zero (param2): calculation mode random, use RNG in calculation and return RNG output
const NONCE_ZERO_CALC_TEMPKEY = 0x8000 //! < Nonce zero (param2): calculation mode TempKey, use TempKey in calculation and return new TempKey value

const NONCE_NUMIN_SIZE = (20) //! < Nonce NumIn size for random modes
const NONCE_NUMIN_SIZE_PASSTHROUGH = (32) //! < Nonce NumIn size for 32-byte pass-through mode

const NONCE_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN //! < Nonce command response packet size with no output
const NONCE_RSP_SIZE_LONG = ATCA_RSP_SIZE_32 //! < Nonce command response packet size with output
/** @} */

/** \name Definitions for the Pause Command
   @{ */
const PAUSE_SELECT_IDX = ATCA_PARAM1_IDX //! < Pause command index for Selector
const PAUSE_PARAM2_IDX = ATCA_PARAM2_IDX //! < Pause command index for 2. parameter
const PAUSE_COUNT = ATCA_CMD_SIZE_MIN //! < Pause command packet size
const PAUSE_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < Pause command response packet size
/** @} */

/** \name Definitions for the PrivWrite Command
   @{ */
const PRIVWRITE_ZONE_IDX = ATCA_PARAM1_IDX //! < PrivWrite command index for zone
const PRIVWRITE_KEYID_IDX = ATCA_PARAM2_IDX //! < PrivWrite command index for KeyID
const PRIVWRITE_VALUE_IDX = (5) //! < PrivWrite command index for value
const PRIVWRITE_MAC_IDX = (41) //! < PrivWrite command index for MAC
const PRIVWRITE_COUNT = (75) //! < PrivWrite command packet size
const PRIVWRITE_ZONE_MASK = 0x40 //! < PrivWrite zone bits 0 to 5 and 7 are 0.
const PRIVWRITE_MODE_ENCRYPT = 0x40 //! < PrivWrite mode: encrypted
const PRIVWRITE_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < PrivWrite command response packet size
/** @} */

/** \name Definitions for the Random Command
   @{ */
const RANDOM_MODE_IDX = ATCA_PARAM1_IDX //! < Random command index for mode
const RANDOM_PARAM2_IDX = ATCA_PARAM2_IDX //! < Random command index for 2. parameter
const RANDOM_COUNT = ATCA_CMD_SIZE_MIN //! < Random command packet size
const RANDOM_SEED_UPDATE = 0x00 //! < Random mode for automatic seed update
const RANDOM_NO_SEED_UPDATE = 0x01 //! < Random mode for no seed update
const RANDOM_NUM_SIZE = 32 //! < Number of bytes in the data packet of a random command
const RANDOM_RSP_SIZE = ATCA_RSP_SIZE_32 //! < Random command response packet size
/** @} */

/** \name Definitions for the Read Command
   @{ */
const READ_ZONE_IDX = ATCA_PARAM1_IDX //! < Read command index for zone
const READ_ADDR_IDX = ATCA_PARAM2_IDX //! < Read command index for address
const READ_COUNT = ATCA_CMD_SIZE_MIN //! < Read command packet size
const READ_ZONE_MASK = 0x83 //! < Read zone bits 2 to 6 are 0.
const READ_4_RSP_SIZE = ATCA_RSP_SIZE_VAL //! < Read command response packet size when reading 4 bytes
const READ_32_RSP_SIZE = ATCA_RSP_SIZE_32 //! < Read command response packet size when reading 32 bytes
/** @} */

/** \name Definitions for the SecureBoot Command
   @{ */
const SECUREBOOT_MODE_IDX = ATCA_PARAM1_IDX //! < SecureBoot command index for mode
const SECUREBOOT_DIGEST_SIZE = (32) //! < SecureBoot digest input size
const SECUREBOOT_SIGNATURE_SIZE = (64) //! < SecureBoot signature input size
const SECUREBOOT_COUNT_DIG = (ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE) //! < SecureBoot command packet size for just a digest
const SECUREBOOT_COUNT_DIG_SIG = (ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE) //! < SecureBoot command packet size for a digest and signature
const SECUREBOOT_MAC_SIZE = (32) //! < SecureBoot MAC output size
const SECUREBOOT_RSP_SIZE_NO_MAC = ATCA_RSP_SIZE_MIN //! < SecureBoot response packet size for no MAC
const SECUREBOOT_RSP_SIZE_MAC = (ATCA_PACKET_OVERHEAD + SECUREBOOT_MAC_SIZE) //! < SecureBoot response packet size with MAC

const SECUREBOOT_MODE_MASK = 0x07 //! < SecureBoot mode mask
const SECUREBOOT_MODE_FULL = 0x05 //! < SecureBoot mode Full
const SECUREBOOT_MODE_FULL_STORE = 0x06 //! < SecureBoot mode FullStore
const SECUREBOOT_MODE_FULL_COPY = 0x07 //! < SecureBoot mode FullCopy
const SECUREBOOT_MODE_PROHIBIT_FLAG = 0x40 //! < SecureBoot mode flag to prohibit SecureBoot until next power cycle
const SECUREBOOT_MODE_ENC_MAC_FLAG = 0x80 //! < SecureBoot mode flag for encrypted digest and returning validating MAC

const SECUREBOOTCONFIG_OFFSET = (70) //! < SecureBootConfig byte offset into the configuration zone
const SECUREBOOTCONFIG_MODE_MASK = 0x0003 //! < Mask for SecureBootMode field in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_DISABLED = 0x0000 //! < Disabled SecureBootMode in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_FULL_BOTH = 0x0001 //! < Both digest and signature always required SecureBootMode in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_FULL_SIG = 0x0002 //! < Signature stored SecureBootMode in SecureBootConfig value
const SECUREBOOTCONFIG_MODE_FULL_DIG = 0x0003 //! < Digest stored SecureBootMode in SecureBootConfig value
/** @} */

/** \name Definitions for the SelfTest Command
   @{ */
const SELFTEST_MODE_IDX = ATCA_PARAM1_IDX //! < SelfTest command index for mode
const SELFTEST_COUNT = ATCA_CMD_SIZE_MIN //! < SelfTest command packet size
const SELFTEST_MODE_RNG = 0x01 //! < SelfTest mode RNG DRBG function
const SELFTEST_MODE_ECDSA_VERIFY = 0x02 //! < SelfTest mode ECDSA verify function
const SELFTEST_MODE_ECDSA_SIGN = 0x04 //! < SelfTest mode ECDSA sign function
const SELFTEST_MODE_ECDH = 0x08 //! < SelfTest mode ECDH function
const SELFTEST_MODE_AES = 0x10 //! < SelfTest mode AES encrypt function
const SELFTEST_MODE_SHA = 0x20 //! < SelfTest mode SHA function
const SELFTEST_MODE_ALL = 0x3F //! < SelfTest mode all algorithms
const SELFTEST_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < SelfTest command response packet size
/** @} */

/** \name Definitions for the SHA Command
   @{ */
const SHA_COUNT_SHORT = ATCA_CMD_SIZE_MIN
const SHA_COUNT_LONG = ATCA_CMD_SIZE_MIN //! < Just a starting size
const ATCA_SHA_DIGEST_SIZE = (32)
const SHA_DATA_MAX = (64)
const ATCA_SHA256_BLOCK_SIZE = (64)
const SHA_CONTEXT_MAX_SIZE = (99)

const SHA_MODE_MASK = 0x07 //! < Mask the bit 0-2
const SHA_MODE_SHA256_START = 0x00 //! < Initialization, does not accept a message
const SHA_MODE_SHA256_UPDATE = 0x01 //! < Add 64 bytes in the meesage to the SHA context
const SHA_MODE_SHA256_END = 0x02 //! < Complete the calculation and return the digest
const SHA_MODE_SHA256_PUBLIC = 0x03 //! < Add 64 byte ECC public key in the slot to the SHA context
const SHA_MODE_HMAC_START = 0x04 //! < Initialization, HMAC calculation
const SHA_MODE_HMAC_UPDATE = 0x01 //! < Add 64 bytes in the meesage to the SHA context
const SHA_MODE_HMAC_END = 0x05 //! < Complete the HMAC computation and return digest
const SHA_MODE_608_HMAC_END = 0x02 //! < Complete the HMAC computation and return digest... Different command on 608
const SHA_MODE_READ_CONTEXT = 0x06 //! < Read current SHA-256 context out of the device
const SHA_MODE_WRITE_CONTEXT = 0x07 //! < Restore a SHA-256 context into the device
const SHA_MODE_TARGET_MASK = 0xC0 //! < Resulting digest target location mask
const SHA_MODE_TARGET_TEMPKEY = 0x00 //! < Place resulting digest both in Output buffer and TempKey
const SHA_MODE_TARGET_MSGDIGBUF = 0x40 //! < Place resulting digest both in Output buffer and Message Digest Buffer
const SHA_MODE_TARGET_OUT_ONLY = 0xC0 //! < Place resulting digest both in Output buffer ONLY

const SHA_RSP_SIZE = ATCA_RSP_SIZE_32 //! < SHA command response packet size
const SHA_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN //! < SHA command response packet size only status code
const SHA_RSP_SIZE_LONG = ATCA_RSP_SIZE_32 //! < SHA command response packet size
/** @} */

/** @} *//** \name Definitions for the Sign Command
   @{ */
const SIGN_MODE_IDX = ATCA_PARAM1_IDX //! < Sign command index for mode
const SIGN_KEYID_IDX = ATCA_PARAM2_IDX //! < Sign command index for key id
const SIGN_COUNT = ATCA_CMD_SIZE_MIN //! < Sign command packet size
const SIGN_MODE_MASK = 0xE1 //! < Sign mode bits 1 to 4 are 0
const SIGN_MODE_INTERNAL = 0x00 //! < Sign mode   0: internal
const SIGN_MODE_INVALIDATE = 0x01 //! < Sign mode bit 1: Signature will be used for Verify(Invalidate)
const SIGN_MODE_INCLUDE_SN = 0x40 //! < Sign mode bit 6: include serial number
const SIGN_MODE_EXTERNAL = 0x80 //! < Sign mode bit 7: external
const SIGN_MODE_SOURCE_MASK = 0x20 //! < Sign mode message source mask
const SIGN_MODE_SOURCE_TEMPKEY = 0x00 //! < Sign mode message source is TempKey
const SIGN_MODE_SOURCE_MSGDIGBUF = 0x20 //! < Sign mode message source is the Message Digest Buffer
const SIGN_RSP_SIZE = ATCA_RSP_SIZE_MAX //! < Sign command response packet size
/** @} */

/** \name Definitions for the UpdateExtra Command
   @{ */
const UPDATE_MODE_IDX = ATCA_PARAM1_IDX //! < UpdateExtra command index for mode
const UPDATE_VALUE_IDX = ATCA_PARAM2_IDX //! < UpdateExtra command index for new value
const UPDATE_COUNT = ATCA_CMD_SIZE_MIN //! < UpdateExtra command packet size
const UPDATE_MODE_USER_EXTRA = 0x00 //! < UpdateExtra mode update UserExtra (config byte 84)
const UPDATE_MODE_SELECTOR = 0x01 //! < UpdateExtra mode update Selector (config byte 85)
const UPDATE_MODE_USER_EXTRA_ADD = UPDATE_MODE_SELECTOR //! < UpdateExtra mode update UserExtraAdd (config byte 85)
const UPDATE_MODE_DEC_COUNTER = 0x02 //! < UpdateExtra mode: decrement counter
const UPDATE_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < UpdateExtra command response packet size
/** @} */

/** \name Definitions for the Verify Command
   @{ */
const VERIFY_MODE_IDX = ATCA_PARAM1_IDX //! < Verify command index for mode
const VERIFY_KEYID_IDX = ATCA_PARAM2_IDX //! < Verify command index for key id
const VERIFY_DATA_IDX = (5) //! < Verify command index for data
const VERIFY_256_STORED_COUNT = (71) //! < Verify command packet size for 256-bit key in stored mode
const VERIFY_283_STORED_COUNT = (79) //! < Verify command packet size for 283-bit key in stored mode
const VERIFY_256_VALIDATE_COUNT = (90) //! < Verify command packet size for 256-bit key in validate mode
const VERIFY_283_VALIDATE_COUNT = (98) //! < Verify command packet size for 283-bit key in validate mode
const VERIFY_256_EXTERNAL_COUNT = (135) //! < Verify command packet size for 256-bit key in external mode
const VERIFY_283_EXTERNAL_COUNT = (151) //! < Verify command packet size for 283-bit key in external mode
const VERIFY_256_KEY_SIZE = (64) //! < Verify key size for 256-bit key
const VERIFY_283_KEY_SIZE = (72) //! < Verify key size for 283-bit key
const VERIFY_256_SIGNATURE_SIZE = (64) //! < Verify signature size for 256-bit key
const VERIFY_283_SIGNATURE_SIZE = (72) //! < Verify signature size for 283-bit key
const VERIFY_OTHER_DATA_SIZE = (19) //! < Verify size of "other data"
const VERIFY_MODE_MASK = 0x03 //! < Verify mode bits 2 to 7 are 0
const VERIFY_MODE_STORED = 0x00 //! < Verify mode: stored
const VERIFY_MODE_VALIDATE_EXTERNAL = 0x01 //! < Verify mode: validate external
const VERIFY_MODE_EXTERNAL = 0x02 //! < Verify mode: external
const VERIFY_MODE_VALIDATE = 0x03 //! < Verify mode: validate
const VERIFY_MODE_INVALIDATE = 0x07 //! < Verify mode: invalidate
const VERIFY_MODE_SOURCE_MASK = 0x20 //! < Verify mode message source mask
const VERIFY_MODE_SOURCE_TEMPKEY = 0x00 //! < Verify mode message source is TempKey
const VERIFY_MODE_SOURCE_MSGDIGBUF = 0x20 //! < Verify mode message source is the Message Digest Buffer
const VERIFY_MODE_MAC_FLAG = 0x80 //! < Verify mode: MAC
const VERIFY_KEY_B283 = 0x0000 //! < Verify key type: B283
const VERIFY_KEY_K283 = 0x0001 //! < Verify key type: K283
const VERIFY_KEY_P256 = 0x0004 //! < Verify key type: P256
const VERIFY_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < Verify command response packet size
const VERIFY_RSP_SIZE_MAC = ATCA_RSP_SIZE_32 //! < Verify command response packet size with validating MAC
/** @} */

/** \name Definitions for the Write Command
   @{ */
const WRITE_ZONE_IDX = ATCA_PARAM1_IDX //! < Write command index for zone
const WRITE_ADDR_IDX = ATCA_PARAM2_IDX //! < Write command index for address
const WRITE_VALUE_IDX = ATCA_DATA_IDX //! < Write command index for data
const WRITE_MAC_VS_IDX = (9) //! < Write command index for MAC following short data
const WRITE_MAC_VL_IDX = (37) //! < Write command index for MAC following long data
const WRITE_MAC_SIZE = (32) //! < Write MAC size
const WRITE_ZONE_MASK = 0xC3 //! < Write zone bits 2 to 5 are 0.
const WRITE_ZONE_WITH_MAC = 0x40 //! < Write zone bit 6: write encrypted with MAC
const WRITE_ZONE_OTP = 1 //! < Write zone id OTP
const WRITE_ZONE_DATA = 2 //! < Write zone id data
const WRITE_RSP_SIZE = ATCA_RSP_SIZE_MIN //! < Write command response packet size
/** @} */

/**

#pragma pack( push, ATCAPacket, 2 )

\brief an ATCA packet structure.  This is a superset of the packet transmitted on the wire.  It's also
used as a buffer for receiving the response

typedef struct
{

    // used for transmit/send
    uint8_t _reserved;  // used by HAL layer as needed (I/O tokens, Word address values)

    //--- start of packet i/o frame----
    uint8_t  txsize;
    uint8_t  opcode;
    uint8_t  param1;    // often same as mode
    uint16_t param2;
    uint8_t  data[130]; // includes 2-byte CRC.  data size is determined by largest possible data section of any
                        // command + crc (see: x08 verify data1 + data2 + data3 + data4)
                        // this is an explicit design trade-off (space) resulting in simplicity in use
                        // and implementation
    //--- end of packet i/o frame

    // used for receive
    uint8_t  execTime;      // execution time of command by opcode
    uint16_t rxsize;        // expected response size, response is held in data member

    // structure should be packed since it will be transmitted over the wire
    // this method varies by compiler.  As new compilers are supported, add their structure packing method here

} ATCAPacket;
#pragma pack( pop, ATCAPacket)

*/

// this is called the crc16maxim or crc16ibm
// crc-16 polynomial 0x8005, little endian
const atCRC = data => {
  let counter // size_t
  let crc_register = 0 // uint16_t
  let polynom = 0x8005 // uint16_t
  let shift_register, data_bit, crc_bit // uint8_t

  for (let count = 0; count < data.length; counter++) {
    for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
      data_bit = (data[counter] & shift_register) ? 1 : 0
      crc_bit = crc_register >> 15
      crc_register <<= 1
      if (data_bit !== crc_bit) {
        crc_register ^= polynom
      }
    }
  }

  // crc_le[0] = crc_register & 0x00FF
  // crc_le[1] = crc_register >> 8
  // little endian
}

// lib/atca_command.c +1047
const atCalcCrc = packet => {
  let length = packet.txsize - ATCA_CRC_SIZE
  let buffer = Buffer.alloc(length)

  buffer[0] = packet.txsize
  buffer[1] = packet.opcode
  buffer[2] = packet.param1
  buffer[3] = packet.param2 >> 8 // big endian
  buffer[4] = packet.param2
  for (let i = 0; i < length; i++) { buffer[5 + i] = packet.data[i] }

  let crc = atCRC(buffer)
  packet.data[packet.txsize - 1] = crc // little endian
  packet.data[packet.txsize - 2] = crc >> 8
  return packet
}

// lib/atca_command.c +499
// ca_cmd is not used
const atRead = (ca_cmd, packet) => {
  packet.opcode = ATCA_READ
  packet.txsize = READ_COUNT

  if ((packet.param1 & 0x80) === 0) {
    packet.rxsize = READ_4_RSP_SIZE
  } else {
    packet.rxsize = READ_32_RSP_SIZE
  }

  atCalcCrc(packet)
  return packet
}
