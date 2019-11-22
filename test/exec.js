const path = require('path')

const chai = require('chai')
const expect = chai.expect

const {
  CRC,
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

describe(__filename, () => {
  it('should do something', async () => {
    await wakeAsync(i2c1, addr)
    const rsp = await i2cReadAsync(i2c1, addr, 4)
    console.log(rsp)
  })
})
