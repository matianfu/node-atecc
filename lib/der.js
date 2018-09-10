/**
encoding length (uint32_t) to DER format buffer

Original
int atcacert_der_enc_length(uint32_t length, 
                            uint8_t* der_length, 
                            size_t* der_length_size)

Porting
[in]  length, a uint32_t value
returns a buffer
*/
const encodeLength = length => {
  let size, exp
  if (length < 0x80) {
    // short-form
    exp = 0
    size = 1
  } else {
    // long-form, encoded as a multi-byte big-endian unsigned integer
    exp = 5 // sizeof(length) + 1
    while (Math.floor(length / (1 << 8 * exp)) === 0) exp--
    size = 2 + exp
  }

  let dlen = Buffer.alloc(size)
  for (; exp >= 0; exp--) { 
    dlen[size - 1 - exp] = length >> (exp * 8) 
  }

  if (size > 1) dlen[0] = 0x80 | (size - 1)

  return dlen
}

/**
decode a DER length from given buffer

Original
int atcacert_der_dec_length(const uint8_t* der_length, 
                            size_t* der_length_size, 
                            uint32_t* length)

Porting
return decoded { value, data }
*/
const decodeLength = (buf, offset = 0) => {
  let value, size

  if (buf[offset] & 0x80) {
    // long-form
    let numBytes = buf[offset] & 0x7F
    value = 0
    for (let i = 1; i <= numBytes; i++) {
      value += buf[offset + i] * (1 << 8 * (numBytes - 1))
    }

    size = numBytes + 1
  } else {
    value = buf[offset]
    size = 1
  }

  return {
    value,
    data: buf.slice(offset, offset + size)
  }
}

/**
Original
int atcacert_der_enc_integer(const uint8_t* int_data,
                             size_t         int_data_size,
                             uint8_t        is_unsigned,
                             uint8_t*       der_int,
                             size_t*        der_int_size)

Porting
[in] data, buffer containing integer to be encoded
return a buffer containing encoded integer
*/
const encodeInteger = (data, isUnsigned) => {
  let trim, pad

  if (!(isUnsigned && data[0] & 0x80)) {
    while ((data.length - trim >= 2) &&
      (((data[trim] === 0x00) && ((data[trim + 1] & 0x80) === 0)) ||
      ((data[trim] === 0xff) && ((data[trim + 1] & 0x80) !== 0)))) {
      trim++
    }
    pad = 0
  } else {
    trim = 0
    pad = 1
  }

  return Buffer.concat([
    Buffer.from([0x02]), // tag
    encodeLength(data.length + pad - trim), // length
    ...(pad ? [Buffer.from([0x00])] : []), // optional padding
    data.slice(trim)
  ])

/**
  // integer tag
  dint[0] = 0x02
  // integer length
  dlen.copy(dint, 1)
  // unsigned integer requires padding
  if (pad) dint[dlen.length + 1] = 0
  // integer value
  data.copy(dint, dlen.length + 1 + pad, trim, data.length)
*/
}

/**
Original
int atcacert_der_dec_integer(const uint8_t* der_int,
                             size_t*        der_int_size,
                             uint8_t*       int_data,
                             size_t*        int_data_size)

Porting
return decoded { value, data }
*/
const decodeInteger = (buf, start) => {
  if (buf[start] !== 0x02) throw new Error('bad tag')

  // decode length
  let len = decodeLength(buf, start + 1)
  let offset = 1 + len.data.length
  let size = offset + len.value

  return {
    value: buf.slice(start + offset, start + size),
    data: buf.slice(start, start + size)
  }
}

/**
const adjustLength (der_length, der_length_size, delta_length, new_length) {
  let new_der_len_size = 0
  let old_len = 0
  let new_len = 0
  let new_der_length = Buffer.alloc(5)

  old_len = decodeLength(der_length)
  new_len = old_len + delta_length
  new_der_len_size = 5

  new_lenjk
}
*/

/**
Original

[in]      raw_sig
[in/out]  der_sig
[in/out]  der_sig_size, initially the max buffer size
int atcacert_der_enc_ecdsa_sig_value(const uint8_t raw_sig[64],
                                     uint8_t*      der_sig,
                                     size_t*       der_sig_size)

Porting

[in]      raw_sig
return a buffer containing
*/
const encodeEcdsaSignature = rsig => {
  let dsig = Buffer.concat([
    Buffer.alloc(5),
    encodeInteger(rsig.slice(0, 32), true),
    encodeInteger(rsig.slice(32, 64), true)
  ])

  dsig[0] = 0x03 // tag
  dsig[1] = dsig.length - 2 // bit string length
  dsig[2] = 0x00 // bit string spare bits
  dsig[3] = 0x30 // sequence tag
  dsig[4] = dsig.length - 5 // sequence length
  return dsig
}

/**
Original:
int atcacert_der_dec_ecdsa_sig_value(const uint8_t* der_sig,
                                     size_t*        der_sig_size,
                                     uint8_t        raw_sig[64])


*/
const decodeEcdsaSignature = dsig => {

}

module.exports = {
  encodeLength,
  decodeLength,
  encodeInteger,
  decodeInteger,
  encodeEcdsaSignature,
  decodeEcdsaSignature
}
