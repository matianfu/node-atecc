const Promise = require('bluebird')
const i2c = require('i2c-bus')
const Ecc = require('./lib/ecc') 

const i2c1 = i2c.open(1, err => {
  if (err) {
    console.log('failed to open i2c1')
  } else {
    let ecc = new Ecc(i2c1) 
    ecc.on('initialized', () => {
      console.log('ecc initialized', '0x' + ecc.addr.toString(16).toUpperCase())

      ;(async () => {
        let config = await ecc.atcabReadConfigZoneAsync()
  
        console.log(config)
       
        await ecc.writeAWSConfigAsync() 

        config = await ecc.atcabReadConfigZoneAsync()
        console.log(config)

      })().then(x => x).catch(e => console.log(e))

    })
  }
})



