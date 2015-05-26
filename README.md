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

## Use Cases

### Docker Private Registry
This utility can be used to easily create TLS certificates for a Docker
registry, including for TLS client authentication. The client certificates
and server certificate do not need to use the same CA, but it is faster to
set up for basic use cases with only a few clients or when sharing a private
key might be considered appropriate.

#### Generate the certificates (with only 1 client)
```
$ quicktls -clients 1 registry.example.com
$ ls
ca.pem  client-0.cert  client-0.key  registry.example.com.cert  registry.example.com.key
```

#### Install on machine running Docker daemon
```
$ sudo cp ca.pem /etc/docker/certs.d/registry.example.com/ca.crt
$ sudo cp client-0.cert /etc/docker/certs.d/registry.example.com/client.cert
$ sudo cp client-0.key /etc/docker/certs.d/registry.example.com/client.key
```

#### Setup private registry

*with nginx*

Copy files to nginx machine
```
$ cp registry.example.com.cert cert-registry.example.com.pem
$ cp registry.example.com.key key-registry.example.com.pem
$ cp ca.pem client-registry.example.com.pem
```

Update `server` section of nginx config
```
server {
  listen 443;
  server_name registry.example.com;
  ssl on;
  ssl_certificate /etc/nginx/ssl/cert-registry.example.com.pem;
  ssl_certificate_key /etc/nginx/ssl/key-registry.example.com.pem;
  ssl_client_certificate /etc/nginx/ssl/client-registry.example.com.pem;
  ssl_verify_client on;
  ...
}
```
