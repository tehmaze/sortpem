#!/bin/bash -x

[ ! -f openssl.cnf ] && {
  cat > openssl.cnf <<ZOMG
[ ca ]
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always

[ server ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
ZOMG
}

[ ! -f root.key ] && openssl genrsa -out root.key 2048
[ ! -f root.crt ] && openssl req -new -x509 -nodes -days 3650 -sha256 -subj "/CN=Test Root/" -key root.key -out root.crt -batch

[ ! -f intermediate.key ] && openssl genrsa -out intermediate.key 2048
[ ! -f intermediate.csr ] && openssl req -new -subj "/CN=Test Intermediate/" -key intermediate.key -out intermediate.csr -batch
[ ! -f intermediate.crt ] && OPENSSL_CONF=openssl.cnf openssl x509 -extensions ca -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -sha256 -days 3650 -out intermediate.crt

[ ! -f issuer.key ] && openssl genrsa -out issuer.key 2048
[ ! -f issuer.csr ] && openssl req -new -subj "/CN=Test Issuer/" -key issuer.key -out issuer.csr -batch
[ ! -f issuer.crt ] && OPENSSL_CONF=openssl.cnf openssl x509 -extensions ca -req -in issuer.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -sha256 -days 3650 -out issuer.crt

[ ! -f endpoint.key ] && openssl genrsa -out endpoint.key 2048
[ ! -f endpoint.csr ] && openssl req -new -subj "/CN=endpoint.example.org/L=IL/" -key endpoint.key -out endpoint.csr -batch
[ ! -f endpoint.crt ] && OPENSSL_CONF=openssl.cnf openssl x509 -extensions ca -req -in endpoint.csr -CA issuer.crt -CAkey issuer.key -CAcreateserial -sha256 -days 3650 -out endpoint.crt
