const crypto = require('crypto')

const i2c = require('i2c-bus')
const commands = require('./commands')
let { abel, zeroTouchAWS, factory } = require('./config')


const KEYTYPE_ECC = 4

const I2C_ADDRESS = 16
const SLOT_CONFIG = 20
const COUNTER_0 = 52
const USER_EXTRA = 84
const SELECTOR = 85
const LOCK_VALUE = 86
const LOCK_CONFIG = 87
const SLOT_LOCKED = 88
const X509_FORMAT = 92
const KEY_CONFIG = 96

const revMap = new Map([
  [Buffer.from([0x00, 0x00, 0x60, 0x01]).readUInt32BE(), '608'],
  [Buffer.from([0x00, 0x00, 0x60, 0x02]).readUInt32BE(), '608'],
  [Buffer.from([0x00, 0x00, 0x50, 0x00]).readUInt32BE(), '508'],
]) 

class ECC {

  constructor (bus) {
    this.bus = bus
  }

  scan (callback) {
    this.bus.scan(0x00, 0x7f, (err, addrs) => {
      if (err) return callback(err)
      if (addrs.includes(0xC0 >> 1)) {
        this.addr = 0xC0
        callback(null)
      } else if (addrs.includes(0xB0 >> 1)) {
        this.addr = 0xB0
        callback(null)
      } else {
        let err = new Error('not found')
        err.code = 'ENOENT'
        callback(err)
      }
    })
  }

  close (callback) {
    this.bus.close(err => callback && callback(err))
  }

  async scanAsync () {
    return new Promise((resolve, reject) => {
      this.scan(err => err ? reject(err) : resolve(null))
    }) 
  }

  /**
    
  */
  async chipStatusAsync () {
    let cfg = await this.readConfigZoneAsync()

    let sn = Buffer.concat([cfg.slice(0, 4), cfg.slice(8, 13)]).toString('hex')
    let rev = cfg.slice(4, 8)
    let type = revMap.get(rev.readUInt32BE()) 
    let i2cAddr = cfg[16]
    let dataLocked = cfg[86] !== 0x55
    let configLocked = cfg[87] !== 0x55
    let slotLocked = cfg.readUInt16LE(88)

    let slots = []
    for (let i = 0; i < 16; i++) {
      let slotConfig = cfg.readUInt16LE(20 + i * 2)
      let keyConfig = cfg.readUInt16LE(96 + i * 2)
      let slot = {}

      slot.isPrivate = !!(keyConfig & 1)
      slot.pubInfo = !!(keyConfig & (1 << 2))
      slot.keyType = (keyConfig >> 2) & 0x07
      slot.lockable = !!(keyConfig & (1 << 5))
      slot.reqRandom = !!(keyConfig & (1 << 6))
      slot.reqAuth = !!(keyConfig & (1 << 7))
      slot.authKey = (keyConfig >> 8) & 0x0f 

      slot.readKey = slotConfig & 0x0f
      slot.noMac = !!(slotConfig & (1 << 4))
      slot.limitedUse = !!(slotConfig & (1 << 5))
      slot.encryptedRead = !!(slotConfig & (1 << 6))
      slot.isSecret = !!(slotConfig & (1 << 7))
      slot.writeKey = (slotConfig >> 8) & 0x0f
      slot.writeConfig = (slotConfig >> 12) & 0x0f

      if (slot.keyType === KEYTYPE_ECC) {
        if (slot.isPrivate) {
          slot.keyValid = await this.keyValidAsync(i)
        } else {
          // for public key in slots where PubInfo is zero, the information
          // returned by this command is not useful
          if (slot.pubInfo) slot.keyValid = await this.keyValidAsync(i)
        }
      } 

      slot.locked = !(slotLocked & (1 << i))
      slots.push(slot)
    } 
  
    return { sn, type, i2cAddr, dataLocked, configLocked, slots }
  }

  chipStatus (callback) {
    this.chipStatusAsync().then(x => callback(null, x)).catch(e => callback(e)) 
  }

  signAsync () {

  }

  sign () {

  }

  /**
  1,  read config
  2,  check config
  3,  if lock config
  4,  gen key (0, 6, 7)
  5,  check validity
  6.  lock 0, 6, 7
  */
  async presetAsync () {

    let config = await this.readConfigZoneAsync()

    if (config[LOCK_CONFIG] === 0x55) { // unlocked
      let read 

      // lock bytes are checked first, if they are not factory value,
      // the chip is considered bad
      // 84 UserExtra, Selector, LockValue, LockConfig
      // 88 SlotLocked, RFU 
      // factory value are [00 00 55 55 ff ff 00 00]
      let lockBytes = Buffer.from([0x00, 0x00, 0x55, 0x55, 0xff, 0xff, 0x00, 0x00])
      let lockedBytes = Buffer.from([0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00])

      read = await this.readBytesZoneAsync(0, 0, USER_EXTRA, 8)
      if (!read.equals(lockBytes)) throw new Error('failed')

      const head = abel.slice(I2C_ADDRESS, USER_EXTRA)
      const tail = abel.slice(X509_FORMAT)    

      await this.writeBytesZoneAsync(0, 0, I2C_ADDRESS, head)
      read = await this.readBytesZoneAsync(0, 0, I2C_ADDRESS, head.length)
      if (!read.equals(head)) throw new Error('failed')

      await this.writeBytesZoneAsync(0, 0, X509_FORMAT, tail)
      read = await this.readBytesZoneAsync(0, 0, X509_FORMAT, tail.length)
      if (!read.equals(tail)) throw new Error('failed')

      // lock config and data zone
      await this.lockConfigZoneAsync ()  
      await this.lockDataZoneAsync () 

      // re-read config
      config = await this.readConfigZoneAsync ()
      let lockedConfig = Buffer.concat([head, lockedBytes, tail]) 
      if (!config.slice(16).equals(lockedConfig)) throw new Error('failed')
    } else {
      // TODO check compatibility
    } 

    
  }

  preset (callback) {
    this.presetAsync()
      .then(x => callback(null, x))
      .catch(e => callback(e))
  }
    
}

Object.assign(ECC.prototype, commands)

const initEcc = (busNum, callback) => {
  let bus = i2c.open(busNum, err => {
    if (err) return callback(err)
    let ecc = new ECC(bus)
    ecc.scan(err => {
      if (err) {
        ecc.close()
        callback(err)
      } else {
        ecc.busNum = busNum
        callback(null, ecc)
      }
    })
  })
}

module.exports = initEcc