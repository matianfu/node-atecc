const child = require('child_process')

child.exec('openssl req -in device.csr -noout -pubkey', (err, stdout) => {
  console.log(stdout)
  let b64 = stdout.split('\n')
    .map(x => x.trim())
    .filter(x => !!x && !x.startsWith('--')) 
    .join('')

  console.log(b64)
  let b = Buffer.from(b64, 'base64')
  console.log(b.length, b)
})
