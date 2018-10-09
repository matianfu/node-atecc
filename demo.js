const fs = require('fs')
const initEcc = require('./lib/wrapper')

initEcc(1, (err, ecc) => {
  if (err) return console.log(err)
  ecc.preset(err => {
    if (err) return console.log(err)
    ecc.genCsr({ o: 'hello', cn: 'world' }, (err, der) => {
      if (err) {
        console.log(err)
      } else {
        let pem = '-----BEGIN CERTIFICATE REQUEST-----\n'
                + der.toString('base64') + '\n'
                + '-----END CERTIFICATE REQUEST-----\n'
          
        fs.writeFile('deviceCSR.pem', pem, err => console.log(err))
      }
    })
  })
})
