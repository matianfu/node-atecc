const i2c = require('i2c-bus')

class EccHal {

  constructor (busnum) {
    this.addr = 0xC0 >> 1 
    this.bus = 
  }

  send (data, callback) {
    this.bus.i2cWrite(this.addr, data.length, data, err => callback)
  } 

   
}
