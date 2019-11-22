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
  it('sleep-wake, read', async () => {
    await sleepWakeAsync(i2c1, addr)
    const rsp = await i2cReadAsync(i2c1, addr, 4)
    expect(rsp.equals(AFTER_WAKE)).to.be.true
  })

  it('sleep-wake, sleep-wake, read', async () => {
    await sleepWakeAsync(i2c1, addr)
    await sleepWakeAsync(i2c1, addr)
    const rsp = await i2cReadAsync(i2c1, addr, 4)
    expect(rsp.equals(AFTER_WAKE)).to.be.true
  })
})
