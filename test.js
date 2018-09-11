const fs = require('fs')
const asn1js = require('asn1js')
const pkijs = require('pkijs')
const Certificate = pkijs.Certificate

const asn1 = asn1js.fromBER(fs.readFileSync('./cert.csr'))
const cert = new Certificate({ shcema: asn1.result })

console.log(cert)
