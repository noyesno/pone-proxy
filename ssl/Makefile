
#Ref: http://wiki.tcl.tk/9414 A Server Template

openssl=openssl
openssl_install=/path/to/openssl/dir

all: server-private.pem server-public.pem


openssl.cfg:
	cp $(openssl_install)/ssl/openssl.cnf openssl.cfg

server-private.pem: openssl.cfg
	$(openssl) genrsa -out server-private.pem 1024

server-public.pem: server-private.pem openssl.cfg
	$(openssl) req -new -x509 -key server-private.pem -out server-public.pem -days 365 -config openssl.cfg

