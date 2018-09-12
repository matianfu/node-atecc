const fs = require('fs')
const child = require('child_process')

const b = fs.readFileSync('tmpl.csr')

// the first block 
fs.writeFileSync('tbs', b.slice(3, 168))

// extract pub key
child.execSync('openssl req -inform der -in tmpl.csr -pubkey -out pubkey.pem')

// the last block in tmpl is bit string, starting from 180
fs.writeFileSync('sig', b.slice(183))

child.execSync('openssl dgst -sha256 -verify pubkey.pem -signature sig < tbs')
