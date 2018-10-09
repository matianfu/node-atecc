const fs = require('fs')
const TLS = require('telsa')
const initEcc = require('./lib/wrapper')

const MQTT_PINGREQ = Buffer.from([12 << 4, 0])
const MQTT_PINGRESP = Buffer.from([13 << 4, 0])

initEcc(1, (err, ecc) => {
  if (err) return console.log(err)
  ecc.preset(err => {
    if (err) return console.log(err)
    console.log('ecc preset done')
    TLS.createConnection({
      port: 8883,
      host: 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn',
      // PEM format
      ca: fs.readFileSync('ca-cert.pem').toString().replace(/\r\n/g, '\n'),
      // convert to DER format
      clientCertificates: [
        Buffer.from(fs.readFileSync('device-cert.pem')
          .toString()
          .split('\n')
          .filter(x => !!x && !x.startsWith('--'))
          .join(''), 'base64')
      ],

      clientPrivateKey: (data, callback) =>
        ecc.sign({ data, der: true }, callback),

      clientCertificateVerifier: {
        algorithm: '',
        sign: ''
      }

    }, (err, tls) => {
      console.log('tls connected')
      tls.once('data', data => {
        if (data.equals(MQTT_PINGRESP)) {
          console.log('MQTT_PINGESP received')
        } else {
          console.log('server replied: ', data)
        }
      })

      tls.write(MQTT_PINGREQ)
      console.log('MQTT_PINGREQ sent to server')
    })
  })
})
