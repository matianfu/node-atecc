# Configuration

> datasheet 4.1
> 16 bit (2 byte) integers, typically Param2, SlotConfig or KeyConfig, appear on the bus least-significant byte first.


## Factory Config

The following configuration are read out of a chip. The first 16 bytes are device specific.

```
   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
--------------------------------------------------
0x 01 23 15 03 00 00 50 00 37 85 F0 A2 EE C0 59 00
1x C0 00 55 00 83 20 87 20 8F 20 C4 8F 8F 8F 8F 8F
2x 9F 8F AF 8F 00 00 00 00 00 00 00 00 00 00 00 00
3x 00 00 AF 8F FF FF FF FF 00 00 00 00 FF FF FF FF
4x 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF
5x FF FF FF FF 00 00 55 55 FF FF 00 00 00 00 00 00
6x 33 00 33 00 33 00 1C 00 1C 00 1C 00 1C 00 1C 00
7x 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 1C 00
```

## AWS Config

This is the configuration used in Microchip Zero Touch project.

1. the first 16 bytes are device specific and are not copied
2. i2c address are set to 0xB0 for pre-configured device
```
   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
--------------------------------------------------
0x FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
1x B0 00 AA 00 8F 20 C4 44 87 20 87 20 8F 0F C4 36
2x 9F 0F 82 20 0F 0F C4 44 0F 0F 0F 0F 0F 0F 0F 0F
3x 0F 0F 0F 0F FF FF FF FF 00 00 00 00 FF FF FF FF
4x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
5x 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00
6x 33 00 1C 00 13 00 13 00 7C 00 1C 00 3C 00 33 00
7x 3C 00 3C 00 3C 00 30 00 3C 00 3C 00 3C 00 30 00
```

|Byte|Name|Description|Write|Read|Factory|AWS|
|--|--|--|--|--|--|--|
|00-03|SN<0:3>||Never|Always|DS|NA|
|04-07|RevNum||Never|Always|DS|NA|
|08-0C|SN<4:8>||Never|Always|DS|NA|
|0D|Reserved||Never|Always|DS|NA|
|0E|I2C Enable|bit 0 = 1, I2C mode|Never|Always|59|NA|
|0F|Reserved||Never|Always|DS|NA|
|10|i2c address||If Config unlocked|Always|C0|B0|
|11|Reserved|Must be zero|If Config unlocked|Always|00|00|
|12|OTPmode|0xAA Read-only, 0x55 Consumption|If Config unlocked|Always|55|AA|
|13|ChipMode|Bit2=0, t<sub>watchdog</sub>=1.3s; <br/>Bit1=0, fixed referrence; <br/>Bit0=0, Selector can always be written with the UpdateExtra command|If Config unlocked|Always|00|00|
|14-15/|SlotConfig<0>||If Config unlocked<br/>0: ???|Always|83 20|8F 20|
|16-17|SlotConfig<1>||If Config unlocked|Always|87 20|C4 44|
|18-19|SlotConfig<2>||If Config unlocked|Always|8F 20|87 20|
|1A-1B|SlotConfig<3>||If Config unlocked|Always|C4 8F|87 20|
|1C-1D|SlotConfig<4>||If Config unlocked|Always|8F 8F|8F 0F|
|1E-1F|SlotConfig<5>||If Config unlocked|Always|8F 8F|C4 36|
|20-21|SlotConfig<6>||If Config unlocked|Always|9F 8F|9F 0F|
|22-23|SlotConfig<7>||If Config unlocked|Always|AF 8F|82 20|
|24-25|SlotConfig<8>||If Config unlocked|Always|00 00|0F 0F|
|26-27|SlotConfig<9>||If Config unlocked|Always|00 00|C4 44|
|28-29|SlotConfig<10>||If Config unlocked|Always|00 00|0F 0F|
|2A-2B|SlotConfig<11>||If Config unlocked|Always|00 00|0F 0F|
|2C-2D|SlotConfig<12>||If Config unlocked|Always|00 00|0F 0F|
|2E-2F|SlotConfig<13>||If Config unlocked|Always|00 00|0F 0F|
|30-31|SlotConfig<14>||If Config unlocked|Always|00 00|0F 0F|
|32-33|SlotConfig<15>||If Config unlocked|Always|AF 8F|0F 0F|
|34-3B|Counter<0>|Monotonic counter, connected to keys via the LimitedUse bit.|If Config unlocked|Always|FFFFFFFF 00000000|FFFFFFFF 00000000|
|3C-43|Counter<1>|Second monotonic counter, not connected to any keys.|If Config unlocked|Always|FFFFFFFF 00000000|FFFFFFFF 00000000|
|44-53|LastKeyUse|128bits to control limited use for KeyID 15.|If Config unlocked|Always|All FF| All 00|
|54|UserExtra|UpdateExtra after the Data Zone has been locked.|Via UpdateExtra Cmd only|Always|00|00|
|55|Selector|Selects which device will remain in active mode after execution of the Pause command.|Via UpdateExtra Cmd only|Always|00|00|
|56|LockValue|Data and OTP zone policies.<br/>0x55 unlocked;<br/>0x00 locked.|Via Lock command only|Always|55|00|
|57|LockConfig|Configuration zone lock. <br/>0x55 unlocked;<br/>0x00 locked.| Via Lock command only|Always|55|00|
|58-59|SlotLocked|Sigle bit for each slot. 0 is locked.|If Config unlocked, Via lock command|Always|FF|FF|
|5A-5B|RFU|Must be Zero|If Config unlocked|Always|0000|0000|
|5C-5F|X509format||If Config unlocked|Always|00000000|00000000|
|60-61|KeyConfig<0>||If Config unlocked|Always|33 00|33 00|
|62-63|KeyConfig<1>||If Config unlocked|Always|33 00|1C 00|
|64-65|KeyConfig<2>||If Config unlocked|Always|33 00|13 00|
|66-67|KeyConfig<3>||If Config unlocked|Always|1C 00|13 00|
|68-69|KeyConfig<4>||If Config unlocked|Always|1C 00|7C 00|
|6A-6B|KeyConfig<5>||If Config unlocked|Always|1C 00|1C 00|
|6C-6D|KeyConfig<6>||If Config unlocked|Always|1C 00|3C 00|
|6E-6F|KeyConfig<7>||If Config unlocked|Always|1C 00|33 00| 
|70-71|KeyConfig<8>||If Config unlocked|Always|3C 00|3C 00|
|72-73|KeyConfig<9>||If Config unlocked|Always|3C 00|3C 00|
|74-75|KeyConfig<10>||If Config unlocked|Always|3C 00|3C 00|
|76-77|KeyConfig<11>||If Config unlocked|Always|3C 00|30 00|
|78-79|KeyConfig<12>||If Config unlocked|Always|3C 00|3C 00|
|7A-7B|KeyConfig<13>||If Config unlocked|Always|3C 00|3C 00|
|7C-7D|KeyConfig<14>||If Config unlocked|Always|3C 00|3C 00|
|7E-7F|KeyConfig<15>||If Config unlocked|Always|1C 00|30 00|

Slot<0>

+ SlotConfig 20 8F
    + 0010 WriteConfig
        + Write command forbidden, no key storage. 
        + (Source Key Target) DeriveKey can be run without authorizing MAC. (Roll)
        + GenKey may be used to write random keys into this slot.
        + PrivWrite forbidden
    + 0000 WriteKey=0
    + 1000 
        + isSecret=1
        + EncryptedRead=0
        + LimitedUse=0
        + NoMac=0
    + 1111 ReadKey=15
+ KeyConfig 00 33
    + 0000 x.509, RFU, IntrusionDisable = 0
    + 0000 AuthKey = 0
    + 001 
        + ReqAuth=0
        + ReqRandom=0
        + Lockable=1
    + 100 P256 NIST ECC key
    + 1 The public version of this key can always be generated.
    + 1 ECC private key, can be used only with Sign, GenKey, ECDH and PrivWrite commands.

Slot<1>

+ SlotConfig 44 C4, 
    + 0100 WriteConfig
        + Write to this slot require a properly computed MAC and the input data must be encrypted by the system with WriteKey using the encryption algorithm documented in the Write command. 4 byte writes to this slot are prohibited.
        + May not be used as the target of the DeriveKey command.
        + GenKey may NOT be used to write random keys into this slot.
        + PrivWrite Writes to this slot requie a properly computed MAC and the input data must be encrypted by the system with SlotConfig.
    + 0100 WriteKey = 4
    + 1100 
        + isSecrete=1
        + EncryptedRead=1
        + LimitedUse=0
        + NoMac=0
    + 0100 ReadKey = 4
+ KeyConfig 00 1C
    + 0000 x.509, RFU, IntrusionDisable = 0
    + 0000 AuthKey = 0
    + 000
        + ReqAuth=0
        + ReqRandom=0
        + Lockable=0
    + 111 Not an ECC Key
    + 0 The public key in this slot can be used by the Verify command without being validated.
    + 0 Not a ECC private key. Cannot be used with Sign, GenKey, ECDH and PrivWrite. It may contain ECC public key, a SHA key, or data.

Slot<2>

+ SlotConfig 20 87
    + same as slot<0>, except that Readkey=7
+ KeyConfig 00 13
    + 00
    + 000
    + 100 P256 NIST ECC key
    + 1 The public version of this key can always be generated.
    + 1 Private

Slot <3>

+ SlotConfig 20 87
    + same as slot<2>
+ KeyConfig 00 13
    + same as slot<2>

Slot <4>

+ SlotConfig 0F 8F
    + 0000 WriteConfig
        + Write Command: Always
        + DeriveKey: -
        + GenKey: no
        + PrivWrite: Forbidden
    + 1111 WriteKey=15
    + 1000
        + isSecret=1
        + EncryptRead=0
        + LimitedUse=0
        + NoMac=0
    + 1111 ReadKey=15
+ KeyConfig 00 7C
    + 0
    + 0000 AuthKey=0
    + 011 
        + ReqAuth=1
        + ReqRandom=0
        + Lockable=0
    + 111 Not a ECC key
    + 0 The public key in this slot can be used by the Verify command without being validated.
    + 0 Not Private

Slot <5>

Slot <6>

Slot <7>

Slot <8>

Slot <9>

Slot <10>

Slot <11>

Slot <12>

Slot <13>

Slot <14>

Slot <15>

# Preconfigure

> `preconfigure_crypto_device()` in ecc_configure.c

1. write the aws configuration to the configuration zone.
2. lock configuration zone.
3. lock data zone.
4. wake then sleep to have the changes to take effect.
5. generate private keys in slot 0, 2, 3, and 7, respectively.

----

```
// local configure_device
detect_crypto_device()
preconfigure_crypto_device()
check_config_compatibility() (not used)

0, 2, 8, 9, 10, 11, 12, 14
```

Both in factory config and aws config, userextra config[0x84] and selector config[0x85] are '00'. 

After aws_config written, the config zone is read back and compared with original value byte by byte. The differences are:

config [0x86] & config [0x87], which remain 0x55 (unlocked).

