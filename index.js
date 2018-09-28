const Promise = require('bluebird')
const fs = Promise.promisifyAll(require('fs'))
const child = Promise.promisifyAll(require('child_process'))
const crypto = require('crypto')

const { createCsrAsync } = require('./lib/cert') 

const i2c = require('i2c-bus')
const initEcc = require('./lib/ecc') 

initEcc(1, (err, ecc) => {
  if (err) return console.log(err)
  ecc.preset(err => {
    if (err) return console.log(err)
    ecc.generateCsr({ o: 'hello', cn: 'world' }, (err, csr) => {
      if (err) {
        console.log(err)
      } else {
        console.log('done')
      }
    })
  })
})

