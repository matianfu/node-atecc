const fs = require('fs')
const crypto = require('crypto')

const verify = crypto.createVerify('SHA256')
verify.update(fs.readFileSync('tbs'))

const pubkey = fs.readFileSync('pubkey-compiled.pem')
const signature = fs.readFileSync('sig')

console.log(verify.verify(pubkey, signature))

