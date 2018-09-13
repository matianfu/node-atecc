const Promise = require('bluebird')
const fs = require('fs')
const crypto = require('crypto')

const i2c = require('i2c-bus')

const Ecc = require('./lib/ecc') 
const { createCsrAsync } = require('./lib/cert')


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

//        console.log(ecc.addr.toString(16))

        let serial_number = Buffer.concat([
          config.slice(0, 4),
          config.slice(8, 13)
        ])

        let revision = await ecc.revisionAsync()
        console.log('revision', revision)

        let rev_num = config.slice(4, 8)

        console.log('serial number', serial_number)
        console.log('revision number', rev_num)

        let key = await ecc.atcabGenKeyAsync(0)
        console.log('pubkey', key.length, key)

        key = await ecc.atcabGenPubKeyAsync(0)

        console.log('pubkey', key.length, key)

        let signAsync = async data => ecc.atcabSignAsync(0, data)
       
        let { ber, pem, tbs, digest, sig, csr } = 
          await createCsrAsync('Example Inc', 'Example Device', key, signAsync)

        console.log('ber', ber)
        fs.writeFileSync('pubkey.ber', ber)
        console.log('pem', pem)
        console.log('tbs', tbs.length, tbs)
        console.log('digest', digest.length, digest)
        console.log('sig', sig.length, sig)

        let verify = crypto.createVerify('SHA256')
        verify.update(tbs)
        
        console.log(verify.verify(pem, sig))

        fs.writeFileSync('cert.csr', csr)

//        pubkey = await ecc.atcabGenPub

//        await ecc.atcabGenKeyAsync(2)
//        await ecc.atcabGenKeyAsync(3)
//        await ecc.atcabGenKeyAsync(7)

/**
        let csr = await ecc.awsGenCsrAsync ()
        console.log('csr', csr)
        fs.writeFileSync('cert.csr', csr)
*/

      })().then(x => x).catch(e => console.log(e))

    })
  }
})


