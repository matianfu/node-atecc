const i2c = require('i2c-bus')
const commands = require('./commands')

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

  async statusAsync () {
    let cfg = await this.readConfigZoneAsync()
    let sn = Buffer.concat([cfg.slice(0, 4), cfg.slice(8, 13)]).toString('hex')
    let rev = cfg.slice(4, 8)
    let type = revMap.get(rev.readUInt32BE()) 
    let i2cAddr = cfg[16]
    let lockValue = cfg[86] === 0x00
    let lockConfig = cfg[87] === 0x00
    let slotLocked = Array.from(Buffer.alloc(16))
      .map((_, i) => !((1 << i) & cfg.readUInt16BE(88)))

    return { sn, type, i2cAddr, lockValue, lockConfig, slotLocked }
  }

  status (callback) {
    this.statusAsync().then(x => callback(null, x)).catch(e => callback(e)) 
  }

  preset () {

  }

  signAsync () {

  }

  sign () {

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
