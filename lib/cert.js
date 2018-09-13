const fs = require('fs')
const crypto = require('crypto')

const { BitString, Integer, ObjectIdentifier, Sequence, 
  Set, Constructed, Utf8String } = require('asn1js')

/**
const pubKey = Buffer.from([
  0xd8, 0x70, 0xa4, 0xdf, 0x98, 0xb4, 0x6a, 0x93, 0x2b, 0xf7, 0x40, 0x39, 0x86, 0x0f, 0xed, 0xd6,
  0x69, 0x03, 0x6a, 0xe7, 0xe4, 0x84, 0x9f, 0xfc, 0xfb, 0x61, 0x50, 0x63, 0x21, 0x95, 0xa8, 0x91,
  0x2c, 0x98, 0x04, 0x0e, 0x9c, 0x2f, 0x03, 0xe1, 0xe4, 0x2e, 0xc7, 0x93, 0x8c, 0x6b, 0xf4, 0xfb,
  0x98, 0x4c, 0x50, 0xdb, 0x51, 0xa3, 0xee, 0x04, 0x1b, 0x55, 0xf0, 0x60, 0x63, 0xeb, 0x46, 0x90
])

const orgName = 'Example Inc'
const commonName = 'Example Device'

const cri = createCri(orgName, commonName, pubKey)

let ber = Buffer.from(cri.toBER())
console.log(ber.length, ber)

console.log(crypto.createHash('sha256').update(ber).digest('hex'))

let oer = fs.readFileSync('tmpl.csr').slice(3, 168)
console.log(oer.length, oer)
console.log(crypto.createHash('sha256').update(oer).digest('hex'))
*/

const ArrayBufferFrom = x => {
  let b = Buffer.from(x)
  let a = new ArrayBuffer(b.length)
  let v = new Uint8Array(a)
  for (let i = 0; i < b.length; i++) v[i] = b[i]
  return a
}

// convert key buffer to keyInfo
const createKeyInfo = keyBuf => 
  new Sequence({ value: [
    new Sequence({ value: [
      new ObjectIdentifier({ value: '1.2.840.10045.2.1' }),
      new ObjectIdentifier({ value: '1.2.840.10045.3.1.7' })
    ] }),
    new BitString({ 
      valueHex: ArrayBufferFrom(Buffer.concat([Buffer.from([0x04]), keyBuf])) })
  ] })

// return a PEM format key
const createPEMKey = keyInfo => [
  '-----BEGIN PUBLIC KEY-----\n',
  ...(Buffer.from(keyInfo.toBER())
    .toString('base64')
    .match(/.{1,64}/g)
    .map(l => l + '\n')),
  '-----END PUBLIC KEY-----\n'
].join('')  

// create certificate request information
const createCri = (orgName, commonName, keyInfo) => new Sequence({ value: [
  new Integer({ valueHex: ArrayBufferFrom([0]) }),
  new Sequence({ value: [
    new Set({ value: [
      new Sequence({ value: [
        // 0x55, 0x04, 0x0a
        new ObjectIdentifier({ value: '2.5.4.10' }),         
        new Utf8String({ valueHex: ArrayBufferFrom(orgName) })
      ] })
    ] }),
    new Set({ value: [
      new Sequence({ value: [
        // 0x55, 0x04, 0x03
        new ObjectIdentifier({ value: '2.5.4.3' }), 
        new Utf8String({ valueHex: ArrayBufferFrom(commonName) })
      ] })
    ] })
  ] }),
  keyInfo,
  new Constructed({
    idBlock: { tagClass: 3, tagNumber: 0 },
    value: [
      new Sequence({ value: [
        // 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e
        new ObjectIdentifier({ value: '1.2.840.113549.1.9.14' }),         
        new Set({ value: [ new Sequence() ] })
      ] })
    ]
  })
] })

// create certificate signing request from cri and (raw) signature
const createCsr = (cri, signature) => new Sequence({ value: [
  cri,
  new Sequence({ value: [
    // 0x2a 0x86 0x48 0xce 0x3d 0x04 0x03 0x02    
    new ObjectIdentifier({ value: '1.2.840.10045.4.3.2' }) 
  ] }),
  new BitString({ valueHex: ArrayBufferFrom(signature) })
] })

const createCsrAsync = async (orgName, commonName, pubKey, signAsync) => {
  let keyInfo = createKeyInfo(pubKey)
  let ber = Buffer.from(keyInfo.toBER())
  let pem = createPEMKey(keyInfo) 
  let cri = createCri(orgName, commonName, keyInfo)
  let tbs = Buffer.from(cri.toBER())
  let digest = crypto.createHash('sha256').update(tbs).digest()
  let sig = await signAsync(digest)
  let csr = Buffer.from(createCsr(cri, sig).toBER())
  return { ber, pem, tbs, digest, sig, csr }
}

module.exports = {
  createKeyInfo,
  createCri,
  createCsr,
  createCsrAsync,
}
