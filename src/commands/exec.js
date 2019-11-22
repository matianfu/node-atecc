
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
const wakeAysnc = async bus => {
  await wakeTokenAsync(bus)
  /**
   * tWLO 60us + tWHI 1500us < 2ms 
   */
  await delayAsync(4) 
  const rsp = await i2cReadAsync(bus, 4) 
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
    const rsp = await i2cReadAsync(bus, 4)
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
    await i2cWriteAsync(bus, Buffer.from([0x01])
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
const sleepWakeAsync = async bus => {
  const start = new Date().getTime()
  while (true) {
    try { 
      await i2cWriteAsync(bus, Buffer.from([0x01])) 
    } catch (e) {}

    await delayAsync(4)

    try {
      return await wakeAsync(bus)
    } catch (e) {}

    const end = new Date().getTime()
    if (end - start > 2000) { 
      const err = new Error('timeout')
      err.code = 'ETIMEOUT'
      throw err
    }
  }
}


