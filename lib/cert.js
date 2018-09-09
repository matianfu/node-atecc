// typedef enum atcacert_date_format_e {
const DATEFMT_ISO8601_SEP = 0 //! < ISO8601 full date YYYY-MM-DDThh:mm:ssZ
const DATEFMT_RFC5280_UTC = 1 //! < RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
const DATEFMT_POSIX_UINT32_BE = 2 //! < POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
const DATEFMT_POSIX_UINT32_LE = 3 //! < POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
const DATEFMT_RFC5280_GEN = 4 //! < RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ
// } atcacert_date_format_t;

// typedef enum atcacert_cert_type_e {
const CERTTYPE_X509 = 0 //! < Standard X509 certificate
const CERTTYPE_CUSTOM = 1 //! < Custom format
// } atcacert_cert_type_t;

// typedef enum atcacert_cert_sn_src_e {
const SNSRC_STORED = 0x0 //! < Cert serial is stored on the device.
const SNSRC_STORED_DYNAMIC = 0x7 //! < Cert serial is stored on the device with the first byte being the DER size (X509 certs only).
const SNSRC_DEVICE_SN = 0x8 //! < Cert serial number is 0x40(MSB) + 9-byte device serial number. Only applies to device certificates.
const SNSRC_SIGNER_ID = 0x9 //! < Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to signer certificates.
const SNSRC_PUB_KEY_HASH = 0xA //! < Cert serial number is the SHA256(Subject public key + Encoded dates), with uppermost 2 bits set to 01.
const SNSRC_DEVICE_SN_HASH = 0xB //! < Cert serial number is the SHA256(Device SN + Encoded dates), with uppermost 2 bits set to 01. Only applies to device certificates.
const SNSRC_PUB_KEY_HASH_POS = 0xC //! < Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates), with MSBit set to 0 to ensure it's positive.
const SNSRC_DEVICE_SN_HASH_POS = 0xD //! < Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates), with MSBit set to 0 to ensure it's positive. Only applies to device certificates.
const SNSRC_PUB_KEY_HASH_RAW = 0xE //! < Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates).
const SNSRC_DEVICE_SN_HASH_RAW = 0xF //! < Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates). Only applies to device certificates.
// } atcacert_cert_sn_src_t;

// typedef enum atcacert_device_zone_e {
const DEVZONE_CONFIG = 0x00 //! < Configuration zone.
const DEVZONE_OTP = 0x01 //! < One Time Programmable zone.
const DEVZONE_DATA = 0x02 //! < Data zone (slots).
const DEVZONE_NONE = 0x07 //! < Special value used to indicate there is no device location.
// } atcacert_device_zone_t;

// typedef enum atcacert_std_cert_element_e {
const STDCERT_PUBLIC_KEY = 0
const STDCERT_SIGNATURE = 1
const STDCERT_ISSUE_DATE = 2
const STDCERT_EXPIRE_DATE = 3
const STDCERT_SIGNER_ID = 4
const STDCERT_CERT_SN = 5
const STDCERT_AUTH_KEY_ID = 6
const STDCERT_SUBJ_KEY_ID = 7
const STDCERT_NUM_ELEMENTS = 8 //! < Special item to give the number of elements in this enum
// } atcacert_std_cert_element_t;

const g_csr_template_2_device = Buffer.from([
  0x30, 0x81, 0xfb, 0x30, 0x81, 0xa2, 0x02, 0x01, 0x00, 0x30, 0x2f, 0x31, 0x14, 0x30, 0x12, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e,
  0x63, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x45, 0x78, 0x61, 0x6d,
  0x70, 0x6c, 0x65, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
  0x07, 0x03, 0x42, 0x00, 0x04, 0xd8, 0x70, 0xa4, 0xdf, 0x98, 0xb4, 0x6a, 0x93, 0x2b, 0xf7, 0x40,
  0x39, 0x86, 0x0f, 0xed, 0xd6, 0x69, 0x03, 0x6a, 0xe7, 0xe4, 0x84, 0x9f, 0xfc, 0xfb, 0x61, 0x50,
  0x63, 0x21, 0x95, 0xa8, 0x91, 0x2c, 0x98, 0x04, 0x0e, 0x9c, 0x2f, 0x03, 0xe1, 0xe4, 0x2e, 0xc7,
  0x93, 0x8c, 0x6b, 0xf4, 0xfb, 0x98, 0x4c, 0x50, 0xdb, 0x51, 0xa3, 0xee, 0x04, 0x1b, 0x55, 0xf0,
  0x60, 0x63, 0xeb, 0x46, 0x90, 0xa0, 0x11, 0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x09, 0x0e, 0x31, 0x02, 0x30, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x26, 0xab, 0x8a, 0x4f, 0x71,
  0x2c, 0xf9, 0xbb, 0x4f, 0xfa, 0xa4, 0xcd, 0x01, 0x48, 0xf1, 0xdf, 0x9c, 0xdc, 0xff, 0xa0, 0xff,
  0x53, 0x8f, 0x35, 0x8d, 0xd4, 0x3d, 0x49, 0xc0, 0x72, 0xf5, 0x0a, 0x02, 0x21, 0x00, 0xa5, 0x9d,
  0xb4, 0x11, 0x4b, 0xa1, 0x65, 0x7c, 0xbb, 0x48, 0xcf, 0x6d, 0xf6, 0xd0, 0x6a, 0x41, 0x00, 0x96,
  0xe1, 0xe2, 0x79, 0x73, 0xdb, 0xf7, 0x97, 0x80, 0x41, 0x9b, 0x35, 0x01, 0x88, 0x5e
])

const g_csr_def_2_device = {
  type: CERTTYPE_X509,
  template_id: 3,
  chain_id: 0,
  private_key_slot: 0,
  sn_source: SNSRC_PUB_KEY_HASH,
  cert_sn_dev_loc: {
    zone: DEVZONE_NONE,
    slot: 0,
    is_genkey: 0,
    offset: 0,
    count: 0
  },
  issue_date_format: DATEFMT_RFC5280_UTC,
  expire_date_format: DATEFMT_RFC5280_UTC,
  tbs_cert_loc: {
    offset: 3,
    count: 165
  },
  expire_years: 0,
  public_key_dev_loc: {
    zone: DEVZONE_NONE,
    slot: 0,
    is_genkey: 1,
    offset: 0,
    count: 64
  },
  comp_cert_dev_loc: {
    zone: DEVZONE_NONE,
    slot: 0,
    is_genkey: 0,
    offset: 0,
    count: 0
  },
  std_cert_elements: [
    { // STDCERT_PUBLIC_KEY
      offset: 85,
      count: 64
    },
    { // STDCERT_SIGNATURE
      offset: 180,
      count: 74
    },
    { // STDCERT_ISSUE_DATE
      offset: 0,
      count: 0
    },
    { // STDCERT_EXPIRE_DATE
      offset: 0,
      count: 0
    },
    { // STDCERT_SIGNER_ID
      offset: 0,
      count: 0
    },
    { // STDCERT_CERT_SN
      offset: 0,
      count: 0
    },
    { // STDCERT_AUTH_KEY_ID
      offset: 0,
      count: 0
    },
    { // STDCERT_SUBJ_KEY_ID
      offset: 0,
      count: 0
    }
  ],
  cert_elements: null,
  cert_elements_count: 0,
  cert_template: g_csr_template_2_device,
  cert_template_size: g_csr_template_2_device.length
}

const atcacertCreateCsr (csr_def) {
}
