const Promise = require('bluebird')
const fs = Promise.promisifyAll(require('fs'))
const child = Promise.promisifyAll(require('child_process'))
const crypto = require('crypto')

const i2c = require('i2c-bus')
const initEcc = require('./lib/ecc2') 

initEcc(1, (err, ecc) => {
  ecc.preset((err, res) => {
    console.log(err, res)
  })
})


//const { createCsrAsync } = require('./lib/cert')

/**
const i2c1 = i2c.open(1, err => {
  if (err) {
    console.log('failed to open i2c1')
  } else {
    let ecc = new Ecc(i2c1) 
    ecc.on('initialized', () => {
      console.log('ecc initialized', '0x' + ecc.addr.toString(16).toUpperCase())

      ;(async () => {
        let config = await ecc.readConfigZoneAsync()
        let arr = Array.from(config)
          .map(x => '0x' + x.toString(16).padStart(2, '0'))

        console.log(JSON.stringify(arr).replace(/"/g, ''))

          console.log(config)
  
//        console.log(config)
//        console.log(config[86], config[87]) 
*/
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
/**
        let serial_number = Buffer.concat([
          config.slice(0, 4),
          config.slice(8, 13)
        ])

        let revision = await ecc.revisionAsync()

        let rev_num = config.slice(4, 8)

        for (let i = 0; i < 16; i++) {
          let keyValid = await ecc.keyValidAsync(i)
          console.log('key valid', keyValid)
        }

        let stateInfo = await ecc.stateInfoAsync()
        console.log('state info', stateInfo)

        let key = await ecc.atcabGenKeyAsync(0)
        console.log('pubkey', key.length, key)

        key = await ecc.atcabGenPubKeyAsync(0)

        console.log('pubkey', key.length, key)

//        let signAsync = async data => ecc.atcabSignAsync(0, data)

        let signAsync = async data => ecc.signAsync(0, data)
       
        let r = await createCsrAsync('Example Inc', 'Example Device', key, signAsync)

        let { subjectPublicKeyInfoPEM, toBeSigned, 
          signature, signatureBER, certificationRequestBER } = r
*/
/**         

        let verifyx = await ecc.verifyExternAsync(digest, sig, key)
        console.log('verify ---------------------------')
        console.log(verifyx)
        console.log('verify ---------------------------')

        let verify2 = await ecc.verifyExternAsync(
          crypto.createHash('sha256').update('hello').digest()
        , sig, key)

        console.log('verify ---------------------------')
        console.log(verify2)
        console.log('verify ---------------------------')
*/
/*
        let verify = crypto.createVerify('SHA256')
        verify.update(toBeSigned)

        console.log(subjectPublicKeyInfoPEM)
        console.log('toBeSigned', toBeSigned.length, toBeSigned)
        console.log('signature', signature.length, signature)
        console.log('signatureBER', signatureBER.length, signatureBER)
        console.log('certificationRequestBER',
          certificationRequestBER.length, certificationRequestBER)
        
        console.log(verify.verify(subjectPublicKeyInfoPEM, signatureBER))

//         fs.writeFileSync('cert.csr', csr)

//        pubkey = await ecc.atcabGenPub

//        await ecc.atcabGenKeyAsync(2)
//        await ecc.atcabGenKeyAsync(3)
//        await ecc.atcabGenKeyAsync(7)
*/
/**
        let csr = await ecc.awsGenCsrAsync ()
        console.log('csr', csr)
        fs.writeFileSync('cert.csr', csr)
*/

//        let csrPEM = 

//        fs.writeFileAsync('device.csr', 
/*
        let csrPEM = '-----BEGIN CERTIFICATE REQUEST-----\n' +
          certificationRequestBER.toString('base64') + 
          '\n-----END CERTIFICATE REQUEST-----'

        console.log(csrPEM)

        await new Promise((resolve, reject) => {
          let cmd = `openssl req -verify -noout -in <(echo -e "${csrPEM}")` 
          child.exec(cmd, { shell: '/bin/bash' }, (err, stdout, stderr) => {
            if (err) reject(err)
            if (stderr.trim() !== 'verify OK') reject('openssl output (stderr) does not match verify OK')
            resolve()
          })
        })
*/
//        let sslVerify = await child.execAsync(`openssl req -verify -in <(echo -e "${csrPEM}")`, { shell: '/bin/bash' })

/**
      })().then(x => x).catch(e => console.log(e))

    })
  }
})
*/


