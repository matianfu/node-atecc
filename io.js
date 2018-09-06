const fs = require('fs')
const ioctl = require('ioctl')

const I2C_SLAVE = 0x0703

let fd = fs.openSync('/dev/i2c-1', 'w+')

let r

r = ioctl(fd, I2C_SLAVE, 96)

// fs.read(fd, buffer, offset, length, position, callback)
let buffer = Buffer.alloc(1024)
fs.read(fd, buffer, 0, 1024, null, (err, bytesRead, data) => {
  console.log(err)
  console.log(bytesRead)
  console.log(data)
})



