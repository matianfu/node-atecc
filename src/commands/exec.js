/**
 * @module atecc_execution
 *
 * reference:
 * https://github.com/MicrochipTech/cryptoauthlib/blob/master/lib/atca_execution.c
 *
 * This module provides basic functions for executing atecc commands.
 *
 * Most functions are based on optimistic assumption, which means the
 * chip is on an assumed power mode. The only exception is the
 * `sleepWakeAsync`, which assumes the chip may be in any power mode,
 * and it guarantees a sleep-wake-read (AFTER_WAKE) sequence is done
 * before return.
 *
 * The user should always start from the `sleepWakeAsync` for executing
 * a sequence of commands, a typical pattern looks something like:
 *
 * ```js
 * // in async function
 * try {
 *   await sleepWakeAsync(bus, addr)
 *   await command1Async(bus, addr, ...args)
 *   await idleWakeAsync(bus, addr)
 *   await command2Async(bus, addr, ...args)
 *   await idleWakeAsync(bus, addr)
 *   await command3Async(bus, addr, ...args)
 *   await sleepAsync(bus, addr)
 * } catch (e) {
 *   // handling error
 * }
 * ```
 *
 * where `idleWakeAsync` is a shortcut for `idleAsync` then `wakeAsync`.
 */

/** @constant execution polling interval */
const POLLING_FREQUENCY = 5

/** @constant max execution polling duration */
const POLLING_MAX = 2500

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
 * assuming atecc is awake, put it into idle mode and verify
 * it could not respong to read
 */
const idleAsync = async (bus, addr) => {
  await i2cWriteAsync(bus, addr, Buffer.from([0x02]))
  try {
    await i2cReadAsync(bus, addr, 4)
  } catch (e) {
    if (e.code === 'ENXIO') return
    throw e
  }
  throw new Error('idle failed')
}

const idleWakeAsync = async (bus, addr) => {
  await idleAsync(bus, addr)
  await wakeAsync(bus, addr)
}

/**
 * assuming atecc is awake, put it into sleep mode and verify
 * it could not respond to read
 */
const sleepAsync = async (bus, addr) => {
  await i2cWriteAsync(bus, addr, Buffer.from([0x01]))
  try {
    await i2cReadAsync(bus, addr, 4)
  } catch (e) {
    if (e.code === 'ENXIO') return
    throw e
  }
  throw new Error('sleep failed')
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

/**
 * handle response from i2cReadAsync
 * @param {Buffer} rsp - response buffer
 * @throws ECC_COMM if response bad size, bad crc, chip error code 0xff or unknown
 * @throws ECC_MISCOMPARE for checkmac or verify error
 * @throws ECC_PARSE for bad parameters (no retry)
 * @throws ECC_FAULT for bad precondition (retry after change precondition)
 * @throws ECC_WAKE for bad power mode
 * @throws ECC_WATCHDOG for insufficient time to execute (should not happen
 * if idle-wake are cycled for each single command)
 */
const handleResponse = rsp => {
  if (rsp[0] < 4) {
    const err = new Error('bad response')
    err.code = 'ECC_COMM'
    throw err
  }
  rsp = rsp.slice(0, rsp[0])
  const payload = rsp.slice(0, -2)
  const crc = rsp.slice(rsp.length - 2).readUInt16LE()
  if (CRC(payload) !== crc) {
    const err = new Error('bad crc')
    err.code = 'ECC_COMM'
    throw err
  }
  const data = rsp.slice(1, rsp.length - 2)
  if (data.length === 1) {
    const val = data[0]
    if (val === 0x00) {

    } else if (val === 0x01) {
      const err = new Error('checkmac or verify miscompare')
      err.code = 'ECC_MISCOMPARE'
      throw err
    } else if (val === 0x03) {
      const err = new Error('parse error')
      err.code = 'ECC_PARSE'
      throw err
    } else if (val === 0x05) {
      const err = new Error('ecc fault')
      err.code = 'ECC_FAULT'
      throw err
    } else if (val === 0x0f) {
      const err = new Error('execution error')
      err.code = 'ECC_EXECUTION'
      throw err
    } else if (val === 0x11) {
      const err = new Error('unexpected wake response')
      err.code = 'ECC_WAKE'
      throw err
    } else if (val === 0xee) {
      const err = new Error('watchdog about to expire')
      err.code = 'ECC_WATCHDOG'
      throw err
    } else if (val === 0xff) {
      const err = new Error('crc or other communication error')
      err.code = 'ECC_COMM'
      throw err
    } else {
      const err = new Error('unknown error')
      err.code = 'ECC_COMM'
      throw err
    }
  } else {
    return data
  }
}

/**
 * executes a command. For packet format, see:
 * section 9.1.1 Security Command Packets in datasheet
 *
 * @param {object} bus - i2c bus object
 * @param {number} addr - atecc i2c address
 * @param {object} packet - data to be encoded and sent to chip
 * @param {Buffer} packet.txsize -
 * @param {Buffer} packet.opcode -
 * @param {Buffer} packet.param1 -
 * @param {Buffer} packet.param2 -
 * @param {Buffer} packet.data -
 * @param {Buffer} packet.rxsize - expected return data size (not used)
 */
const execAsync = async (bus, addr, packet) => {
  const { txsize, opcode, param1, param2 } = packet
  const data = packet.data || Buffer.alloc(0)

  /** if not provided, using 75 */
  const rxsize = Number.isInteger(packet.rxsize) ? packet.rxsize : 75

  let maxDelayCount = Math.floor(POLLING_MAX / POLLING_FREQUENCY)
  const wordAddress = Buffer.from([0x03])
  let payload = Buffer.from([txsize, opcode, param1, param2, param2 >> 8])
  payload = Buffer.concat([payload, data])
  const crc = CRC(payload)
  const crcLE = Buffer.from([crc, crc >> 8])
  const cmd = Buffer.concat([wordAddress, payload, crcLE])

  // write command
  await i2cWriteAsync(bus, addr, cmd)

  while (maxDelayCount-- > 0) {
    await delayAsync(POLLING_FREQUENCY)
    try {
      return handleResponse(await i2cReadAsync(bus, addr, rxsize))
    } catch (e) {
      if (e.code !== 'ENXIO') throw e
    }
  }

  throw new Error('timeout')
}

module.exports = {
  CRC,
  AFTER_WAKE,
  delayAsync,
  i2cReadAsync,
  i2cWriteAsync,
  wakeAsync,
  idleAsync,
  idleWakeAsync,
  sleepAsync,
  sleepWakeAsync,
  execAsync
}
