# QuickTLS

QuickTLS generates server and client TLS certificates along with the CA
certificate use to sign them. The private key to the CA is never saved,
allowing for safely importing the CA into a certificate chain without
fear of compromise of the CA. If any server or client key is compromised,
the entire CA should be thrown out and new server, client, and CA certificates
should be generated.

## Usage
```
$ quicktls -h
Usage of quicktls:
  -clients=0: Number of client certificates to generate
  -exp=25920h0m0s: Time until Certificate expiration
  -o="": Output directory
  -org="QuickTLS": Organization in the certificate
  -rsa=4096: Number of RSA bits
```

Generate client certificate and server certificate for example.com
```
$ quicktls -clients=1 example.com
$ ls
ca.pem  client-0.cert  client-0.key  example.com.cert  example.com.key
```
