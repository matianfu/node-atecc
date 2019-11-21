const crypto = require('crypto')
const initEcc = require('./lib/wrapper')

const initEccAsync = async () =>
  new Promise((resolve, reject) => {
    initEcc(1, (err, ecc) => {
      if (err) {
        reject(err)
      } else {
        ecc.preset(err => {
          if (err) {
            reject(err)
          } else {
            resolve(ecc)
          }
        })
      }
    })
  })

const eccGenCsrAsync = async (ecc) =>
  new Promise((resolve, reject) => {
    ecc.genCsr({ o: 'hello', cn: 'world' }, (err, der) => {
      if (err) {
        reject(err)
      } else {
        resolve(null)
      }
    })    
  })

const buf = Buffer.alloc(1024)
crypto.randomFillSync(buf)

const eccSignAsync = async ecc =>
  new Promise((resolve, reject) => {
    ecc.sign({ data: buf }, (err, sig) => {
      if (err) {
        reject(err)
      } else {
        resolve(sig)
      }
    }) 
  })

const delayAsync = async msec =>
  new Promise((resolve, reject) => {
    setTimeout(() => resolve(null), msec)
  })

const mainAsync = async () => {
  const ecc = await initEccAsync()
  let count = 0
  let error_count = 0

  while (true) {
    const rand = Math.floor(500 + Math.random() * 1500)
    await delayAsync(rand)

    const r = rand.toString().padStart(4, '0')

    count++
    try {
      // const sig = await eccSignAsync(ecc)
      // console.log(r, sig.slice(0, 8).toString('hex') + '...')
      await eccGenCsrAsync(ecc)
      // console.log(r)
    } catch (e) {
      error_count++
      console.log(r, `${error_count}/${count}`, e)
    }

  }
}

mainAsync().then(() => {}).catch(e => console.log(e))
