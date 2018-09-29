const initEcc = require('./lib/wrapper')

initEcc(1, (err, ecc) => {
  if (err) return console.log(err)
  ecc.preset(err => {
    if (err) return console.log(err)
    ecc.genCsr({ o: 'hello', cn: 'world' }, (err, der) => {
      if (err) {
        console.log(err)
      } else {
        console.log(der.toString('base64'))
      }
    })
  })
})
