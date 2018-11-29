# sortpem

Sorting utility for PEM files. Failing to remember what order to put the
certificate and its intermediates in? And what intermediate should we include?
Wonder no longer, and let `sortpem` resolve the chain for you.

It is assumed your system receives software updates, and it has a recent copy
of the trusted certificate bundle for your operating system. `sortpem` does
not provide root certificates; there are many sources out there that can
provide you that information. 

If you wish to use a custom trusted roots bundle (in PEM format), you can pass
the `-ca <file>` flag to `sortpem`.

## Options

Most of the flags are compatible with the `sort(1)` utility:

```
-D    Enable debug logging
-a    Output all blocks, not only the ones matching -t
-c    Count blocks
-ca string
      CA file
-d    Dump text output of decoded PEM block
-o string
      Print the output to a file in stead of standard output
-p string
      Preset (use "list" for an overview)
-r    Reverse sort
-root
      Include root certificate
-s    Stable sort
-t value
      Type of block order and filter (regular expression(s))
-u    Unique blocks
```

## Presets

There are presets available that sets a combination of default options based
on the chose preset:

```
certs    -t "^CERTIFICATE$" -R
keys     -t "PRIVATE KEY$"
nginx    -t "^CERTIFICATE$" -t "PRIVATE KEY$"
haproxy  -t "^CERTIFICATE$" -t "PRIVATE KEY$" -R
```

## Example

Sort a PEM bundle, CERTIFICATEs first, then any PRIVATE KEY:

```console
user@host:~$ ls -1 testdata/*.crt testdata/endpoint.key
testdata/endpoint.crt
testdata/endpoint.key 
testdata/intermediate.crt 
testdata/issuer.crt 
testdata/root.crt

# We have a self-signed root:
user@host:~$ openssl x509 -in testdata/root.crt -noout -subject -issuer
subject= /CN=Test Root
issuer= /CN=Test Root

# By default, the root certificate is omitted (enabled -d which decodes blocks):
user@host:~$ cat testdata/*.crt testdata/endpoint.key | sortpem -d | grep Subject:
  Subject:    CN=endpoint.example.org,L=IL
  Subject:    CN=Test Intermediate
  Subject:    CN=Test Issuer

# We can include it, with -root:
user@host:~$ cat testdata/*.crt testdata/endpoint.key | sortpem -root -d | grep Subject:
  Subject:    CN=endpoint.example.org,L=IL
  Subject:    CN=Test Intermediate
  Subject:    CN=Test Issuer
  Subject:    CN=Test Root

# The private key is in there too, by the way:
user@host:~$ cat testdata/*.crt testdata/endpoint.key | sortpem -root | grep 'BEGIN '
-----BEGIN CERTIFICATE-----
-----BEGIN CERTIFICATE-----
-----BEGIN CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----

# Download a public certificate:
user@host:~$ echo "" | openssl s_client -connect google.com:443 -showcerts > testdata/google.com.crt
depth=1 C = US, O = Google Trust Services, CN = Google Internet Authority G3
verify error:num=20:unable to get local issuer certificate
verify return:0
DONE

# It sent us 2 certificates:
user@host:~$ grep -c 'BEGIN CERTIFICATE' testdata/google.com.crt
2

# Inspect them:
user@host:~$ sortpem -d testdata/google.com.crt | grep Subject:
  Subject:    CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
  Subject:    CN=Google Internet Authority G3,O=Google Trust Services,C=US

# Get the full chain, including root:
user@host:~$ sortpem -root -d testdata/google.com.crt | grep Subject:
  Subject:    CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
  Subject:    CN=Google Internet Authority G3,O=Google Trust Services,C=US
  Subject:    CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign