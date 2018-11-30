#!/bin/bash -x

[ ! -f openssl.cnf ] && {
  cat > openssl.cnf <<ZOMG
[ ca ]
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ server ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
attributes          = req_attributes
x509_extensions		= ca
req_extensions		= v3_req

[ req_distinguished_name ]

[ req_attributes ]

[ v3_req ]
ZOMG
}

[ ! -f ca.ext ] && {
    cat > ca.ext <<ZOMG
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
ZOMG
}

[ ! -f ca-basic.ext ] && {
    cat > ca-basic.ext <<ZOMG
basicConstraints = CA:TRUE
ZOMG
}

[ ! -f server.ext ] && {
    cat > server.ext <<ZOMG
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
ZOMG
}

[ ! -f root.key ] && openssl genrsa -out root.key 2048
[ ! -f root.crt ] && OPENSSL_CONF=openssl.cnf openssl req -new -x509 -nodes -days 3650 -sha256 -subj "/CN=Test Root/" -key root.key -out root.crt -batch

[ ! -f intermediate.key ] && openssl genrsa -out intermediate.key 2048
[ ! -f intermediate.csr ] && openssl req -new -subj "/CN=Test Intermediate/" -key intermediate.key -out intermediate.csr -batch
[ ! -f intermediate.crt ] && OPENSSL_CONF=openssl.cnf openssl x509 -extfile ca-basic.ext -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -sha256 -days 3650 -out intermediate.crt

[ ! -f issuer.key ] && openssl genrsa -out issuer.key 2048
[ ! -f issuer.csr ] && openssl req -new -subj "/CN=Test Issuer/" -key issuer.key -out issuer.csr -batch
[ ! -f issuer.crt ] && OPENSSL_CONF=openssl.cnf openssl x509 -extfile ca.ext -req -in issuer.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -sha256 -days 3650 -out issuer.crt

[ ! -f endpoint.key ] && openssl genrsa -out endpoint.key 2048
[ ! -f endpoint.csr ] && openssl req -new -subj "/CN=endpoint.example.org/L=IL/" -key endpoint.key -out endpoint.csr -batch
[ ! -f endpoint.crt ] && OPENSSL_CONF=openssl.cnf openssl x509 -extfile server.ext -req -in endpoint.csr -CA issuer.crt -CAkey issuer.key -CAcreateserial -sha256 -days 3650 -out endpoint.crt


[ ! -f root-dsa.key ] && openssl dsaparam -genkey -out root-dsa.key 1024
[ ! -f root-dsa.crt ] && OPENSSL_CONF=openssl.cnf openssl req -new -x509 -nodes -days 3650 -sha256 -subj "/CN=Test Root DSA/" -key root-dsa.key -out root-dsa.crt -batch

[ ! -f root-ec.key ] && openssl ecparam -genkey -out root-ec.key -name prime256v1
[ ! -f root-ec.crt ] && OPENSSL_CONF=openssl.cnf openssl req -new -x509 -nodes -days 3650 -sha256 -subj "/CN=Test Root EC/" -key root-ec.key -out root-ec.crt -batch
