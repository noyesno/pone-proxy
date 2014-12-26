
openssl=openssl
openssl_install=/path/to/openssl/dir

all: ca.crt server.crt client.crt

#all: server-private.pem server-public.pem


#----------------------------------------------------------------------#

#Ref: http://nategood.com/client-side-certificate-authentication-in-ngi

client-ssl: ca.crt server.crt client.crt

ca.key ca.crt:
	# Create the CA Key and Certificate for signing Client Certs
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 365 -key ca.key -out ca.crt

server.key server.csr:
	# Create the Server Key, CSR, and Certificate
	openssl genrsa -out server.key 1024
	openssl req -new -key server.key -out server.csr


server.crt: server.csr
	# We're self signing our own server cert here.  This is a no-no in production.
	openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

client.key client.csr:
	# Create the Client Key and CSR
	openssl genrsa -out client.key 1024
	openssl req -new -key client.key -out client.csr

client.crt: client.csr
	# Sign the client certificate with our CA cert.  Unlike signing our own server cert, this is what we want to do.
	openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt

#----------------------------------------------------------------------#

#Ref: http://wiki.tcl.tk/9414 A Server Template


openssl.cfg:
	cp $(openssl_install)/ssl/openssl.cnf openssl.cfg

server-private.pem: openssl.cfg
	$(openssl) genrsa -out server-private.pem 1024

server-public.pem: server-private.pem openssl.cfg
	$(openssl) req -new -x509 -key server-private.pem -out server-public.pem -days 365 -config openssl.cfg
