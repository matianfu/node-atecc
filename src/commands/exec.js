/**
 * async delay
 * @param {number} msec - delayed time in milli-seconds
 */
const delayAsync = async msec =>
  new Promise((resolve, reject) =>
    setTimeout(() => resolve(null), msec))

/**
 * calculates CRC of chip response
 * @param {Buffer} data
 * @returns {number} the crc value (unsigned int in C)
 */
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

/**
 * read data from device
 * @param {object} bus - i2c bus object
 * @param {number} addr - atecc i2c address
 * @param {number} len - data length
 * @returns {Buffer} data read
 * @throws error
 */
const i2cReadAsync = async (bus, addr, len) => {
  return new Promise((resolve, reject) => {
    const data = Buffer.alloc(len)
    bus.i2cRead(addr >> 1, len, data, err => {
      if (err) {
        reject(err) 
      } else {
        resolve(data)
      }
    })
  })
}

/**
 * write data to device
 * @param {object} bus - i2c bus object
 * @parma {number} addr - atecc i2c address
 * @param {Buffer} data - data to be written to device
 */
const i2cWriteAsync = async (bus, addr, data) => 
  new Promise((resolve, reject) => {
    bus.i2cWrite(addr >> 1, data.length, data, err => {
      if (err) {
        reject(err)
      } else {
        resolve(null)
      }
    }) 
  })

/**
 * sends a wake token to bus (broadcasting)
 */
const wakeTokenAsync = async bus =>
  new Promise((resolve, reject) =>
    bus.i2cWrite(0x00, 1, Buffer.from([0x00]), () => resolve()))

const AFTER_WAKE = Buffer.from([0x04, 0x11, 0x33, 0x43])

/**
 * assuming atecc is in idle or sleep mode, wake up the chip and confirm
 * response
 */
const wakeAsync = async (bus, addr) => {
  await wakeTokenAsync(bus)
  /**
   * tWLO 60us + tWHI 1500us < 2ms
   */
  await delayAsync(2)
  const rsp = await i2cReadAsync(bus, addr, 4)
  if (!rsp.equals(AFTER_WAKE)) {
    throw new Error('bad response in wake')
  }
}

/**
 * assuming atecc is in awake mode, put the chip into idle
 */
const idleAsync = async bus => {
  await i2cWriteAsync(bus, Buffer.from([0x02]))
  try {
    await i2cReadAsync(bus, addr, 4)
  } catch (e) {
    if (e.code === 'ENXIO') return
    throw e
  }
  throw new Error('idle failed')
}

/**
 * assuming atecc is in any mode. try its best to put the chip into sleep mode
 */
const sleepAsync = async bus => {
  // issue a sleep token and check result
  try {
    await i2cWriteAsync(bus, Buffer.from([0x01]))
  } catch (e) {
    if (e.code === 'ENXIO') {
      // the chip may be busy, idle, or sleep
    }
  }
}

/**
 * assuming atecc is in any state: busy, idle, sleep, or awake.
 * there is no need to analyze states carefully. Just send
 * sleep and wake token and read back repeatedly, until we
 * get a AFTER_WAKE response, or timeout (2s total).
 * according to code, the longest non-selftest execution time are:
 * - atecc508a 115ms (Genkey)
 * - atecc608a m0 165ms (KDF)
 * - atecc608a m1 295ms (Sign)
 * - atecc608a m2 1085ms (Verify)
 */
const sleepWakeAsync = async (bus, addr) => {
  const start = new Date().getTime()
  while (true) {
    try {
      await i2cWriteAsync(bus, addr, Buffer.from([0x01]))
    } catch (e) {
      if (e.code !== 'ENXIO') {
        console.log('sleep token anyway', e.message)
      }
    }

    await delayAsync(4)

    try {
      return await wakeAsync(bus, addr)
    } catch (e) {
      console.log('wakeAsync error', e.message)
    }

    const end = new Date().getTime()
    if (end - start > 2000) {
      const err = new Error('timeout')
      err.code = 'ETIMEOUT'
      throw err
    }
  }
}

module.exports = {
  CRC,
  AFTER_WAKE,
  delayAsync,
  i2cReadAsync,
  i2cWriteAsync,
  wakeAsync,
  idleAsync,
  sleepAsync,
  sleepWakeAsync
}
