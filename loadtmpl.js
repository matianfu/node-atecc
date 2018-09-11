const fs = require('fs')
const asn1 = require('asn1js')

module.exports = () => {
  let b = fs.readFileSync('tmpl.csr')
  let a = new ArrayBuffer(b.length)
  let v = new Uint8Array(a)
  for (let i = 0; i < b.length; i++) v[i] = b[i]
  return a
}
