const path = require('path')

const chai = require('chai')
const expect = chai.expect

const {
  CRC,
  AFTER_WAKE,
  delayAsync,
  i2cReadAsync,
  i2cWriteAsync,
  wakeAsync,
  idleAsync,
  sleepAsync,
  sleepWakeAsync
} = require('src/commands/exec')


const i2c = require('i2c-bus') 

const i2c1 = i2c.openSync(1)
const addr = 0xC0

describe(path.basename(__filename), () => {
  it('sleep-wake', async () => {
    await sleepWakeAsync(i2c1, addr)
  })

  it('sleep-wake, sleep', async () => {
    await sleepWakeAsync(i2c1, addr)
    await sleepAsync(i2c1, addr)
  })

  it('sleep-wake, idle', async () => {
    await sleepWakeAsync(i2c1, addr)
    await idleAsync(i2c1, addr)
  })

  it('sleep-wake, sleep-wake', async () => {
    await sleepWakeAsync(i2c1, addr)
    await sleepWakeAsync(i2c1, addr)
  })

  it('sleep-wake, sleep-wake, idle', async () => {
    await sleepWakeAsync(i2c1, addr)
    await sleepWakeAsync(i2c1, addr)
    await idleAsync(i2c1, addr)
  }) 

  it('sleep-wake, sleep-wake, sleep', async () => {
    await sleepWakeAsync(i2c1, addr)
    await sleepWakeAsync(i2c1, addr)
    await sleepAsync(i2c1, addr)
  }) 
})
