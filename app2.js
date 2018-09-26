const Promise = require('bluebird')
const fs = Promise.promisifyAll(require('fs'))
const child = Promise.promisifyAll(require('child_process'))
const crypto = require('crypto')

const i2c = require('i2c-bus')
const Ecc = require('./lib/ecc')

const i2c1 = i2c.open(1, err => {
  if (err) {
    console.log('failed to open i2c1')
  } else {
  }
})
