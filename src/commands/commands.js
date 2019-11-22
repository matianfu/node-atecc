/**
 * all possible commands for atecc508a
 *
 * - CheckMac
 * - Counter
 * - DeriveKey
 * - ECDH
 * - GenDig
 * - GenKey
 * - HMAC
 * - Info
 * - Lock
 * - MAC
 * - Nonce
 * - Pause
 * - PrivWrite
 * - Random
 * - Read
 * - SHA
 * - Sign
 * - UpdateExtra
 * - Verify
 * - Write
 */


const CONFIG_ZONE = 0x00
const OTP_ZONE = 0x01
const DATA_ZONE = 0x02
// zone bit 6, if set, write is encrypted
const ZONE_ENCRYPTED = 0x40 
// zone bit 7, if set, access 32 bytes, otherwise, 4 bytes
const ZONE_READWRITE_32 = 0x80

/**
 *
 * @param {number} zone - CONFIG_ZONE, OTP_ZONE, or DATA_ZONE 
 * @param {number} slot - slot number
 * @param {number} block - block number
 * @param {number} offset - offset
 */
const getAddr = (zone, slot, block, offset) => {
  switch (zone & 0x03) {
    case CONFIG_ZONE:
    case OTP_ZONE:
      return (block << 3) | (offset & 0x07)
    case DATA_ZONE:
      return (slot << 3) | (offset & 0x07) | (block << 8)
    default:
      throw new Error('bad zone')
  }
}

const getZoneSize = (zone, slot) => {
  switch (zone) {
    case CONFIG_ZONE:
      return 128
    case OTP_ZONE:
      return 64
    case DATA_ZONE:
      if (slot < 8) {
        return 36
      } else if (slot === 8) {
        return 416
      } else if (slot < 16) {
        return 72
      } else {
        throw new Error('bad slot')
      }
    default:
      throw new Error('bad zone')
  }
}


/**
 *
 */
const readZoneAsync = async (bus, addr, zone, slot, block, offset, len) => {
  return execAsync({
    txsize: 7,
    opcode: 0x02, // ATCA_READ,
    param1: len === 32 ? (zone | ZONE_READWRITE_32) : zone,
    parma2: getAddr(zone, slot, block, offset),
  })
}

