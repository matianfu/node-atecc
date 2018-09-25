const Promise = require('bluebird')
const child = Promise.promisifyAll(require('child_process'))


const main = async () => {
  let signerPrivateKey = await child.execAsync('openssl ecparam -name prime256v1 -genkey')
  let signerCertificate = await child.execAsync(`openssl req -new -x509 -nodes -key <(echo "${signerPrivateKey}") -subj "/O=WST/CN=WST Signer" -days 11499`, { 
    input: signerPrivateKey, shell: '/bin/bash' 
  })

  console.log(signerCertificate)
}

main().then(() => {}).catch(e => console.log(e))

