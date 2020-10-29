#!/bin/bash

HTTP_HOST="vfe8q.sse.codesandbox.io"

# generate an RSA private key
openssl genrsa 2048 > ./certs/private.key

# generate an RSA public key
openssl req -new -x509 -nodes -sha1 -days 365 \
 -key ./certs/private.key \
 -out ./certs/public.pem \
 -subj "/C=GB/ST=London/L=London/O=IT/OU=IT Department/CN=$HTTP_HOST"
