const Promise = require('bluebird')
const child = Promise.promisifyAll(require('child_process'))


const main = async () => {
  // generate root ca, though it is named signer
  let signerPrivateKey = await child.execAsync('openssl ecparam -name prime256v1 -genkey')
  let signerCertificate = await child.execAsync(`openssl req -new -x509 -nodes -key <(echo "${signerPrivateKey}") -subj "/O=WST/CN=WST Signer" -days 11499`, { 
    input: signerPrivateKey, shell: '/bin/bash' 
  })

/**
subjectKeyIdentifier

openssl x509 -req -days 11499 
  -in device.csr 
  -CA ecc-ca-cert.pem 
  -CAkey ecc-private-key.pem 
  -CAcreateserial 
  -extfile x509v3.extension.conf 
  -extensions identifier 
  -out device.crt
*/
  console.log(signerCertificate)
}

/*

[identifier]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
*/

main().then(() => {}).catch(e => console.log(e))

