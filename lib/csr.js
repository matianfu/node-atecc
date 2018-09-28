const { BitString, Integer, UInteger, ObjectIdentifier, 
  UTF8String, Sequence, Set, ContentInfo } = require('./asn1.js')

const CertReqInfo = (o, cn, key) =>
  Sequence(
    Integer(Buffer.alloc(1)),
    Sequence(
      Set(
        Sequence(
          ObjectIdentifier('2.5.4.10'),
          UTF8String(o))),
      Set(
        Sequence(
          ObjectIdentifier('2.5.4.3'),
          UTF8String(cn)))),
    Sequence(
      Sequence(
        ObjectIdentifier('1.2.840.10045.2.1'),
        ObjectIdentifier('1.2.840.10045.3.1.7')),
      BitString(0, 0x04, key)),
    ContentInfo(
      Sequence(
        ObjectIdentifier('1.2.840.113549.1.9.14'),
        Set(Sequence()))))

const CertRequest = (cri, sig) =>
  Sequence(
    cri,
    Sequence(
      ObjectIdentifier('1.2.840.10045.4.3.2')),
    BitString(
      Sequence(
        UInteger(sig.slice(0, 32)),
        UInteger(sig.slice(32, 64)))))


