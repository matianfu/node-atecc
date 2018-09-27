const Promise = require('bluebird')

/** command polling, from latest cryptoauthlib, lib/atca_execution.c **/
const POLLING_INIT = 2
const POLLING_FREQUENCY = 5
const POLLING_MAX = 2500

const CRC = data => {
  const polynom = 0x8005 // uint16_t
  let crcRegister = 0 // uint16_t
  let shiftRegister, dataBit, crcBit // uint8_t
  for (let i = 0; i < data.length; i++) {
    for (shiftRegister = 0x01;
      shiftRegister > 0x00;
      shiftRegister = ((shiftRegister << 1) & 0xff)) {
      dataBit = ((data[i] & shiftRegister) & 0xff) ? 1 : 0
      crcBit = (crcRegister >> 15) & 0xff
      crcRegister = (crcRegister << 1) & 0xffff
      if (dataBit !== crcBit) crcRegister ^= polynom
    }
  }
  return crcRegister
}

module.exports = {

  async i2cReadAsync (len) {
    let data = Buffer.alloc(len)
    await new Promise((resolve, reject) =>
      this.bus.i2cRead(this.addr >> 1, len, data, err =>
        err ? reject(err) : resolve(null)))
    return data
  },

  async i2cWriteAsync (data) {
    return new Promise((resolve, reject) =>
      this.bus.i2cWrite(this.addr >> 1, data.length, data, err =>
        err ? reject(err) : resolve(null)))
  },

  async wakeAsync () {
    await new Promise((resolve, reject) =>
      this.bus.i2cWrite(0x00, 1, Buffer.from([0x00]), () => resolve()))

    let maxDelayCount = 1000
    do {
      await Promise.delay(3)
      try {
        let data = await this.i2cReadAsync(4)
        if (data.equals(Buffer.from([0x04, 0x11, 0x33, 0x43]))) return
      } catch (e) {
        if (e.code !== 'ENXIO') {
          await this.sleepAsync()
          throw e
        }
      }
    } while (maxDelayCount-- > 0)

    throw new Error('wake timeout')
  },

  async idleAsync () {
    return this.i2cWriteAsync(Buffer.from([0x02]))
  },

  async sleepAsync () {
    return this.i2cWriteAsync(Buffer.from([0x01]))
  },

  async execAsync (packet) {
    let { txsize, opcode, param1, param2, data } = packet
    data = data || Buffer.alloc(0)

    let maxDelayCount = Math.floor(POLLING_MAX / POLLING_FREQUENCY)
    let wordAddress = Buffer.from([0x03])
    let payload = Buffer.from([txsize, opcode, param1, param2, param2 >> 8])
    payload = Buffer.concat([payload, data])
    let crc = CRC(payload)
    let crcLE = Buffer.from([crc, crc >> 8])
    let cmd = Buffer.concat([wordAddress, payload, crcLE])
    await this.wakeAsync()
    await this.i2cWriteAsync(cmd)
    await Promise.delay(POLLING_INIT)

    let rsp
    do {
      try {
        rsp = await this.i2cReadAsync(130)
        break
      } catch (e) {
        if (e.code !== 'ENXIO') {
          await this.idleAsync()
          throw e
        }
      }
      await Promise.delay(POLLING_FREQUENCY)
    } while (maxDelayCount-- > 0)
    await this.idleAsync()

    if (rsp[0] < 4) throw new Error('invalid count')

    rsp = rsp.slice(0, rsp[0])
    if (CRC(rsp.slice(0, -2)) !== rsp.slice(rsp.length - 2).readUInt16LE(0)) { throw new Error('BAD_CRC') }

    return rsp.slice(1, rsp.length - 2)
  }
}
