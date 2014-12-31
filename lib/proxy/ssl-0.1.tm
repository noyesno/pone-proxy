# vim: syntax=tcl

proc ssl_init {} {
  package require tls


  #  -cafile   certs/ca.crt     \

  ::tls::init \
    -certfile ssl/certs/server.crt \
    -keyfile  ssl/certs/server.key \
    -ssl2 1 \
    -ssl3 1 \
    -tls1 1 \
    -require 0 \
    -request 0 \
    -command ssl_debug
}

proc ssl_debug {args} {
  puts "SSL: [join $args]"
}
