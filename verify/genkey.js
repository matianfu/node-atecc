const fs = require('fs')
const { Sequence, ObjectIdentifier, BitString } = require('asn1js')

const ArrayBufferFrom = x => {
  let b = Buffer.from(x)
  let a = new ArrayBuffer(b.length)
  let v = new Uint8Array(a)

  for (let i = 0; i < b.length; i++) v[i] = b[i]
  return a
}

const pubKey = [
  0xd8, 0x70, 0xa4, 0xdf, 0x98, 0xb4, 0x6a, 0x93, 0x2b, 0xf7, 0x40, 0x39, 0x86, 0x0f, 0xed, 0xd6,
  0x69, 0x03, 0x6a, 0xe7, 0xe4, 0x84, 0x9f, 0xfc, 0xfb, 0x61, 0x50, 0x63, 0x21, 0x95, 0xa8, 0x91,
  0x2c, 0x98, 0x04, 0x0e, 0x9c, 0x2f, 0x03, 0xe1, 0xe4, 0x2e, 0xc7, 0x93, 0x8c, 0x6b, 0xf4, 0xfb,
  0x98, 0x4c, 0x50, 0xdb, 0x51, 0xa3, 0xee, 0x04, 0x1b, 0x55, 0xf0, 0x60, 0x63, 0xeb, 0x46, 0x90
]

/**
     SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }
*/
const pubKeyInfo = rawKey => 
  new Sequence({ value: [
    new Sequence({ value: [
      new ObjectIdentifier({ value: '1.2.840.10045.2.1' }),
      new ObjectIdentifier({ value: '1.2.840.10045.3.1.7' })
    ] }),
    new BitString({ valueHex: ArrayBufferFrom([0x04, ...rawKey]) })
  ] })

/**
const pubKeyBinToPEM = pk => [
  '-----BEGIN PUBLIC KEY-----',
  ...(Buffer.from(new Sequence({ value: [
    new Sequence({ value: [
      new ObjectIdentifier({ value: '1.2.840.10045.2.1' }),
      new ObjectIdentifier({ value: '1.2.840.10045.3.1.7' })
    ] }),
    new BitString({ valueHex: ArrayBufferFrom(pk) })
  ] }).toBER()).toString('base64').match(/.{1,64}/g)),
  '-----END PUBLIC KEY-----'
].join('\n')
*/

let ber = Buffer.from(pubKeyInfo(pubKey).toBER())

console.log(ber.length)
console.log(ber.slice(0, 32))
console.log(ber.slice(32, 64))
console.log(ber.slice(64))

let oer = Buffer.from(fs.readFileSync('pubkey.der'))

console.log(oer.length)
console.log(oer.slice(0, 32))
console.log(oer.slice(32, 64))
console.log(oer.slice(64))

let lines = ber.toString('base64').match(/.{1,64}/g)
lines.unshift('-----BEGIN PUBLIC KEY-----')
lines.push('-----END PUBLIC KEY-----')


console.log(lines.join('\n'))

fs.writeFileSync('pubkey-compiled.pem', lines.map(l => l + '\n').join(''))


console.log(fs.readFileSync('pubkey.pem').toString())





