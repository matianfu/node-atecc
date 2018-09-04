const i2c = require('i2c-bus')

/**
There is a _gDevice which is initialized by atcab_init(cfg), where cfg is

ATCAIfaceCfg cfg_ateccx08a_i2c_default = { 
  .iface_type             = ATCA_I2C_IFACE,
  .devtype                = ATECC508A,
  .atcai2c.slave_address  = 0xC0,
  .atcai2c.bus            = 2,
  .atcai2c.baud           = 400000,
  //.atcai2c.baud = 100000,
  .wake_delay             = 1500,
  .rx_retries             = 20
};

This device is created by newATCADevice(cfg)

->mCommands = newATCACommand(cfg -> devtype)
  ca_cmd->dt = device_type
  ca_cmd->clock_divider = 0
  ca_cmd->execution_time_msec = ??? not initialized after malloc
->mIface = newATCAIface(cfg)
  ca_iface->mType = cfg->iface_type
  ca_iface->mIfaceCFG=cfg
  
  hal_iface_init: set hal methods to static methods
    halinit
    halpostinit
    halreceive
    halsend
    halsleep
    halwake
    helidle
    halrelease
    hal_data = null

  then
    ca_iface->atinit = hal->halinit
    ...

  typedef enum
  {
    ATCA_I2C_IFACE,
    ATCA_SWI_IFACE,
    ATCA_UART_IFACE,
    ATCA_SPI_IFACE,
    ATCA_HID_IFACE,
    ATCA_CUSTOM_IFACE,
    // additional physical interface types here
    ATCA_UNKNOWN_IFACE,
  } ATCAIfaceType;

  for SAMG55 demo, ATCA_I2C_IFACE is used. for linux userspace hal, no idea.
*/

const ATECC508_ADDR = 0x60

const ATCA_ECC_CONFIG_SIZE = 128 // /lib/atca_command.h +268
const ATCA_BLOCK_SIZE = 32 // atca_command.h +262
const ATCA_WORD_SIZE = 4 // atca_command.h +263

const cfg_ateccx08a_i2c_default = {
  // /lib/atca_cfgs.c +44
  iface_type: 'ATCA_I2C_IFACE',
  devtype: 'ATECC508A',
  atcai2c: {
    slave_address: 0xC0,
    bus: 2,
    baud: 400000,
  },
  wake_delay: 1500,
  rx_retries: 20
}

// default address for unconfigured dev. provisioning_task.h +76
const ECCx08A_DEFAULT_ADDRESS = 0xC0 

// atcab_init has some extra work on 608

/**
  provisioning_task.c detect_crypto_device() 
  ecc_configure.c detect_crypto_device()
  atcab_init
  atcab_read_config_zone(&config)

*/

/**
const atcab_get_zone_size = (zone, slot) => {
  switch (zone) {
    case 'ATCA_ZONE_CONFIG':
      return 128
    case 'ATCA_ZONE_OTP':
      return 64
    case 'ATCA_ZONE_DATA':
      if (slot < 8) return 36
      else if (slot === 8) return 416
      else if (slot < 16) return 72
      else return 0
  }
}
*/

const atcab_wakup = () => {

}

const atsend = () => {
}

const atreceive = () => {
}

// lib/basic/atca_basic.c +392
const atcab_execute_command = packet => {
  
}

// lib/atca_command.c +499
const atRead = (ca_cmd, packet) => {
  packet.opcode = ATCA_READ
  packet.txsize = READ_COUNT
  
  if (packet.param1 & 0x80 === 0) {
    packet.rxsize = READ_4_RSP_SIZE
  } else {
    packet.rxsize = READ_32_RSP_SIZE
  }

  atCalcCrc(packet)
  return 
} 

// lib/basic/atca_basic.c + 290
// uint16 addr
const atcab_get_addr = (zone, slot, block, offset) => {
  let addr = 0

  offset = offset & 0x07
  if (zone is config or otp) { // CONFIG or OTP
    addr = block << 3
    addr |= offset 
  } else {  // DATA
    addr = slot << 3
    addr |= offset 
    addr |= block << 8
  }
}


// lib/basic/atca_basic_read.c 60
// zone, slot, block, offset, len
const atcab_read_zone = (zone, slot, block, offset, len) => {

  let addr = atcab_get_addr(zone, slot, block, offset) 

  if (len === ATCA_BLOCK_SIZE) zone = zone | ATCA_ZONE_READWRITE_32

  packet.param1 = zone
  packet.param2 = addr

  atRead(null, packet)
  atcab_execute_command(packet)
} 

// lib/basic/atca_basic_read.c 610
// return buffer or throw error
const atcab_read_bytes_zone = (zone, slot, offset, size) => {
  // TODO validate args   
  // TODO support zone other than config
  let zone_size = 128

  let data_idx = 0
  let cur_block = 0
  let cur_offset = 0
  let read_size = ATCA_BLOCK_SIZE 
  let read_buf_idx = 0
  let copy_length = 0
  let read_offset = 0
  // read_buf[32] ???

  // read block by block 
  let cur_block = offset / ATCA_BLOCK_SIZE
  
  while (data_idx < length) {
    if (read_size === ATCA_BLOCK_SIZE && zone_size - cur_block * ATCA_BLOCK_SIZE < ATCA_BLOCK_SIZE) {
      read_size = ATCA_WORD_SIZE
      cur_offset = ((data_idx + offset) / ATCA_WORD_SIZE) % (ATCA_BLOCK_SIZE / ATCA_WORD_SIZE)

      let buf = atcab_read_zone(zone, slot, cur_block, cur_offset, read_size)
      
      read_offset = cur_block * ATCA_BLOCK_SIZE + cur_offset * ATCA_WORD_SIZE 
      if (read_offset < offset) {
        read_buf_idx = offset - read_offset
      } else {
        read_buf_idx = 0
      }

      if (length - data_idx < read_size - read_buf_idx) {
        copy_length = length - data_idx
      } else {
        copy_length = read_size - read_buf_idx
      }

      if (read_size === ATCA_BLOCK_SIZE) {
        cur_block++
      } else {
        cur_offset++
      }
    }
  }
}

// lib/basic/atca_basic_read.c 341
// should return config_data
const atcab_read_config_zone = () => 
  // if not 204
  atcab_read_bytes_zone('ATCA_ZONE_CONFIG', 0, 0x00) // zone, slot, offset
  // config_data, ATCA_ECC_CONFIG_SIZE = 128, in atca_command.h +268

const i2c1 = i2c.open(1, (err, bus) => {
  if (err) {
    console.log(err)
  } else {
    console.log(bus)
  }
})
