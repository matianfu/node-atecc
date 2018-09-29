# node-atecc

This library is intended to access the functionality of Microchip atecc508a ic in linux, using userspace i2c. `i2c-bus` is used for low-level access to i2c-bus.

This project is incomplete. Only a few functions of atecc chip are implemented, including:

1. set the chip configuration
2. lock the configuration and data zone
3. generate private ecc key and generate public key from private key.
4. sign a digest.
5. verify a signature using given external public ecc key.

The chip has many functions. However, for a linux system, most of them can be done using software, including node.js and openssl. The most important feature of this chip, which cannot be done by a software, is it can safely store private ecc keys and sign a piece of data using those keys. So only this feature is implemented in this library.

# Configuration

The chip has many possible configuration. In this project, the configuration is copied from the Microchip official demo of aws iot project. I don't fully understand all configurations for all data slot. Their potential usage or intention. But merely for the purpose mentioned above, the default configuration in this project, which is named as `abel`, works.

Here is the modification of `abel` configuration from that of official project.

1. the i2c address is not change. It remains as `0xC0`. In Microchip's aws iot demo, this value is set to `0xB0` after presetting.
2. key slot 0, 6, and 7 hold private keys. slot 0 is the so-called device key. This keys is used in generating the certificate signing request (csr). Other two keys are reserved for future use.
3. Keys in slot 0, 6, and 7 are generated and locked after presetting. There is no way change them.
4. The configuration is located in `lib/config.js`.

# TLS

The main purpose for implementing this library, is to use it with tls and aws iot.

It is possible to develop an openssl engine to access atecc508a. It requires C/C++ code and openssl configuration and compilation each time openssl or node.js is upgraded.

Another choice is to use node-forge, which is a pure javascript implementation of tls. Unfortunately, it does not support tls 1.2, which is a mandatory requirement by aws iot.

To keep it simple with full control, we implemented a very simple tls 1.2 protocol using node.js. The project is named telsa. Though it is not a good choice for transmitting large amount of data, the performance is suffice to aws iot mqtt.

mqtt.js supports external builder for creating a tls connection. So we can chain this proect, telsa, and mqtt.js, to have a pure node.js solution for using atecc508a with aws iot.

# Usage

see `demo.js`.

The semantic is not optimized. May be changed in future. Also, good to hear any comments or advices.


# Features and Bugs

File an issue please.



