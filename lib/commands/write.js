const { getAddr, getZoneSize } = require('./common')

// Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
const ATCA_ZONE_READWRITE_32 = 0x80 


module.exports = {
  async atWriteAsync (zone, addr, data, mac = Buffer.alloc(0)) {
    return this.execAsync({
      txsize: 7 + data.length,
      opcode: ATCA_WRITE,
      param1: zone,
      param2: addr,
      data: (zone & ATCA_ZONE_READWRITE_32)
        ? Buffer.concat([data.slice(0, 32), mac.slice(0, 32)])
        : data.slice(0, 4)
    })
  },

  async writeZoneAsync (zone, slot, block, offset, data) {
    if (data.length !== 4 && data.length !== 32) throw new Error('bad param')
    let addr = getAddr(zone, slot, block, offset)
    if (data.length === 32) zone = zone | ATCA_ZONE_READWRITE_32
    return this.atWriteAsync(zone, addr, data)
  },
  
  async writeBytesZoneAsync (zone, slot, offset, data) {
    let length = data.length

    if (![0,1,2].includes(zone) || (zone === ATCA_ZONE_DATA && slot > 15)) 
      throw new Error('bad param')

    if (length === 0) return
    if (offset % 4 !== 0 || length % 4 !== 0) throw new Error('bad param')
    if (offset + length > getZoneSize(zone, slot)) throw new Error('bad param')

    let curBlock = Math.floor(offset / 32)
    let curWord = Math.floor((offset % 32) / 4)
    let dataIdx = 0
    while (dataIdx < length) {
      if (curWord === 0 && 
        length - dataIdx >= 32 && 
        !(zone === ATCA_ZONE_CONFIG && curBlock === 2)) {
        let block = data.slice(dataIdx, dataIdx + 32) 
        await this.writeZoneAsync(zone, slot, curBlock, 0, block)
        dataIdx += 32
        curBlock += 1
      } else {
        if (!(zone === ATCA_ZONE_CONFIG && curBlock === 2 && curWord === 5)) {
          let word = data.slice(dataIdx, dataIdx + 4)
          await this.atcabWriteZoneAsync(zone, slot, curBlock, curWord, word)
        }
        dataIdx += 4
        curWord += 1
        if (curWord === Math.floor(32 / 4)) {
          curBlock += 1
          curWord = 0
        }
      }
    }
  },

}
