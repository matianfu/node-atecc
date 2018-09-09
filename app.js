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
  
//        console.log(config)
//        console.log(config[86], config[87]) 
/**
        config = await ecc.writeAWSConfigAsync() 

        console.log(config)

        await ecc.atcabLockConfigZoneAsync ()

        console.log('config zone locked')

        await ecc.atcabLockDataZoneAsync ()

        console.log('data zone locked')

        await ecc.wakeAsync()
        await ecc.sleepAsync()

        console.log('done')
*/

        console.log(ecc.addr.toString(16))

        let pubkey

        pubkey = await ecc.atcabGenKeyAsync(0)
        console.log('pubkey', pubkey)

        pubkey = await ecc.atcabGenPubKeyAsync(0)
        console.log('pubkey', pubkey)

//        pubkey = await ecc.atcabGenPub

//        await ecc.atcabGenKeyAsync(2)
//        await ecc.atcabGenKeyAsync(3)
//        await ecc.atcabGenKeyAsync(7)


      })().then(x => x).catch(e => console.log(e))

    })
  }
})


