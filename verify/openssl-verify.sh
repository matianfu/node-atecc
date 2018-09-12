#!/bin/bash

# generate a file
echo hello > hello

# generate a ec private key
openssl ecparam -genkey -name prime256v1 -noout -out private.pem

# generae the public key
openssl ec -in private.pem -pubout -out public.pem

# sign file
openssl dgst -sha256 -sign private.pem < hello > hello.sig

# verify
openssl dgst -sha256 -verify public.pem -signature hello.sig < hello
