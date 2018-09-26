const Promise = require('bluebird')
const fs = require('fs')
const child = require('child_process')
const crypto = require('crypto')

const { BitString, Integer, ObjectIdentifier, Sequence, Set, Constructed, Utf8String } = require('asn1js')

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

/**
(rfc2986)

PKCS #10: Certification Request Syntax Specification

CertificationRequest ::= SEQUENCE {
  certificationRequestInfo  CertificationRequestInfo,
  signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
  signature                 BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
  version       INTEGER { v1(0) } (v1,...),
  subject       Name,
  subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
  attributes    [0] Attributes{{ CRIAttributes }}
}

SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
  algorithm        AlgorithmIdentifier {{IOSet}},
  subjectPublicKey BIT STRING
}

*/

const ArrayBufferFrom = x => {
  let b = Buffer.from(x)
  let a = new ArrayBuffer(b.length)
  let v = new Uint8Array(a)
  for (let i = 0; i < b.length; i++) v[i] = b[i]
  return a
}

const SubjectPublicKeyInfo = rawPubKey => 
  new Sequence({ value: [
    new Sequence({ value: [
      new ObjectIdentifier({ value: '1.2.840.10045.2.1' }),
      new ObjectIdentifier({ value: '1.2.840.10045.3.1.7' })
    ] }),
    new BitString({ 
      valueHex: ArrayBufferFrom(Buffer.concat([Buffer.from([0x04]), rawPubKey])) })
  ] })

// generate a PEM format subjectPublicKeyInfo, used for verification
const SubjectPublicKeyInfoPEM = subjectPublicKeyInfoBER => [
  '-----BEGIN PUBLIC KEY-----\n',
  ...(subjectPublicKeyInfoBER.toString('base64').match(/.{1,64}/g).map(l => l + '\n')),
  '-----END PUBLIC KEY-----\n'
].join('')  

// create certificate request information
const CertificationRequestInfo = (orgName, commonName, subjectPublicKeyInfo) => 
  new Sequence({ value: [
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
    subjectPublicKeyInfo,
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


const zero = Buffer.from([0x00])
const prepend = x => (x[0] & 0x80) ? Buffer.concat([zero, x]) : x
const SignatureBER = raw => 
  Buffer.from(new Sequence({ value: [
    new Integer({ valueHex: ArrayBufferFrom(prepend(raw.slice(0, 32))) }),
    new Integer({ valueHex: ArrayBufferFrom(prepend(raw.slice(32, 64))) })
  ] }).toBER())

const CertificationRequest = (certificationRequestInfo, signatureBER) => 
  new Sequence({ value: [
    certificationRequestInfo,
    new Sequence({ value: [
      // 0x2a 0x86 0x48 0xce 0x3d 0x04 0x03 0x02    
      new ObjectIdentifier({ value: '1.2.840.10045.4.3.2' }) 
    ] }),
    new BitString({ valueHex: ArrayBufferFrom(signatureBER) })
  ] })

const opensslVerifyCsr = (csrBER, callback) => {
  let c = child.exec('openssl req -inform DER -in cert.csr -noout -verify',
    (err, stdout, stderr) => err 
      ? callback(err)
      : callback(null, (stdout.toString().trim() === 'verify OK')))

  c.stdin.write(csrBER)
  c.stdin.end()
}

const opensslVerifyCsrAsync = Promise.promisify(opensslVerifyCsr)

const createCsrAsync = async (orgName, commonName, rawPubKey, signAsync) => {
  let subjectPublicKeyInfo = SubjectPublicKeyInfo(rawPubKey)
  let subjectPublicKeyInfoBER = Buffer.from(subjectPublicKeyInfo.toBER())
  let subjectPublicKeyInfoPEM = SubjectPublicKeyInfoPEM(subjectPublicKeyInfoBER)

  let certificationRequestInfo = CertificationRequestInfo(
    orgName, commonName, subjectPublicKeyInfo)

  /* generate signature (ber) */
  let toBeSigned = Buffer.from(certificationRequestInfo.toBER())
  let digest = crypto.createHash('sha256').update(toBeSigned).digest()
  let signature = await signAsync(digest)
  let signatureBER = SignatureBER(signature)
  let certificationRequestBER = Buffer.from(
    CertificationRequest(certificationRequestInfo, signatureBER).toBER())

  /* verification by node.js */
  let verified = crypto.createVerify('sha256') 
    .update(toBeSigned) 
    .verify(subjectPublicKeyInfoPEM, signatureBER)

  if (!verified) throw new Error('(node) code verification failed')

  /* verification by openssl */
  verifified = await opensslVerifyCsrAsync(certificationRequestBER) 
  if (!verified) throw new Error('openssl verification failed')

  return { 
    subjectPublicKeyInfoPEM,
    toBeSigned,
    digest,
    signature,
    signatureBER,
    certificationRequestBER,
  }
}

module.exports = {
  createCsrAsync,
}
