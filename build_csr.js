const fs = require('fs')
const crypto = require('crypto')
const asn1 = require('asn1js')
const { BitString, Integer, ObjectIdentifier, 
  Sequence, Set, Constructed, Utf8String } = asn1

const createArrayBuffer = x => {
  let b = Buffer.from(x)
  let a = new ArrayBuffer(b.length)
  let v = new Uint8Array(a)

  for (let i = 0; i < b.length; i++) v[i] = b[i]
  return a
}

/**
seq
  integer 0
  seq
    set
      seq
        oid org name
        utf8string
    set
      seq
        oid common name
        utf8string 
  seq
    seq
      oid ECC
      oid ECDSA_P256
    bitstring (pub key)
  constructed
    seq
      oid extension
      set
        seq (empty)
seq (oid, sha256ECDSA)
bitstring (sigature)
*/

const seq = new Sequence({ 
  value: [
    new Integer({ 
      valueHex: createArrayBuffer([0]) 
    }),
    new Sequence({
      value: [
        new Set({
          value: [
            new Sequence({
              value: [
                new ObjectIdentifier({ value: '2.5.4.10' /* 0x55, 0x04, 0x0a */ }),
                new Utf8String({ valueHex: createArrayBuffer('Example Inc') })
              ]
            }),
          ]
        }),
        new Set({
          value: [
            new Sequence({
              value: [
                new ObjectIdentifier({ value: '2.5.4.3' /* 0x55, 0x04, 0x03 */ }),
                new Utf8String({ valueHex: createArrayBuffer('Example Device') })
              ]
            })
          ]
        })
      ]
    }),
    new Sequence({
      value: [
        new Sequence({
          value: [
            new ObjectIdentifier({ value: '1.2.840.10045.2.1' /* 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 */ }),
            new ObjectIdentifier({ value: '1.2.840.10045.3.1.7' /* 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 */ })
          ]
        }),
        new BitString({
          valueHex: createArrayBuffer([
            0x04, 
            0xd8, 0x70, 0xa4, 0xdf, 0x98, 0xb4, 0x6a, 0x93, 0x2b, 0xf7, 0x40, 0x39, 0x86, 0x0f, 0xed, 0xd6, 
            0x69, 0x03, 0x6a, 0xe7, 0xe4, 0x84, 0x9f, 0xfc, 0xfb, 0x61, 0x50, 0x63, 0x21, 0x95, 0xa8, 0x91, 
            0x2c, 0x98, 0x04, 0x0e, 0x9c, 0x2f, 0x03, 0xe1, 0xe4, 0x2e, 0xc7, 0x93, 0x8c, 0x6b, 0xf4, 0xfb, 
            0x98, 0x4c, 0x50, 0xdb, 0x51, 0xa3, 0xee, 0x04, 0x1b, 0x55, 0xf0, 0x60, 0x63, 0xeb, 0x46, 0x90
          ])
        })
      ]
    }),
    new Constructed({
      idBlock: { tagClass: 3, tagNumber: 0 },
      value: [
        new Sequence({ 
          value: [
            new ObjectIdentifier({ value: '1.2.840.113549.1.9.14' /* 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e */ }),
            new Set({ value: [ new Sequence() ] })
          ]
        })
      ]
    })
  ] 
}) 

let ber = Buffer.from(seq.toBER())
console.log(ber.length, ber)

console.log(crypto.createHash('sha256').update(ber).digest('hex'))

let oer = fs.readFileSync('tmpl.csr').slice(3, 168)
console.log(oer.length, oer)

console.log(crypto.createHash('sha256').update(oer).digest('hex'))





