const Promise = require('bluebird')
const fs = require('fs')
const child = require('child_process')
const crypto = require('crypto')


// https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/distinguished-encoding-rules

// 32bit length at most
const L = v => v.length < 128
  ? Buffer.from([v])
  : Buffer.from(Array.from(Buffer.alloc(4).writeUInt32BE(v.length))
    .reduce((a, c) => a.length ? [...a, c] : c ? [c] : [], [])
    .reduce((a, c, i, arr) =>
      i ? [...a, c] : [arr.length | 0x80, c], []))

const TLV = (t, v) =>
  Buffer.concat([Buffer.from([t]), L(v), v])

const BitString = (buf, unused) =>
  TLV(0x03, Buffer.concat([Buffer.from([unused]), buf]))

const Integer = buf => TLV(0x02, buf)

const UInteger = buf => buf[0] < 128 
  ? Integer(buf) 
  : Integer(Buffer.concat([Buffer.alloc(1), buf]))

const Sequence = buf => TLV(0x30, buf)

const Set = buf => TLV(0x31, buf)
const UTF8String = buf => TLV(0x0c, buf)

const base128 = n => Buffer.from(n.toString(2)
  .padStart(Math.ceil(n.toString(2).length / 7) * 7, '0')
  .match(/.{7}/g)
  .map(x => parseInt(x, 2))
  .map((x, i, arr) => i === arr.length - 1 ? x : (x | 0x80)))

const OID = str =>
  TLV(0x06, Buffer.concat(str.split('.').map(s => base128(parseInt(s)))))

// TODO see laymans guide
const Constructed = 0 

