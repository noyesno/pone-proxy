
lappend auto_path ../lib
package require tls


::tls::init \
  -certfile certs/server.crt \
  -keyfile  certs/server.key \
  -cafile   certs/ca.crt     \
  -ssl2 1 \
  -ssl3 1 \
  -tls1 1 \
  -require 1 \
  -request 1 \
  -command debug

proc debug {args} {
  puts "SSL: [join $args]"
}


proc accept {sock host port} {
  puts [fconfigure $sock]
  fconfigure $sock -translation auto
  puts [fconfigure $sock]
  #puts "-------------"
  #puts [tls::handshake $sock]
  puts "-------------"
  puts [tls::status $sock]
  puts "-------------"
  puts [tls::status -local $sock]
  puts "-------------"


  while {[gets $sock line]>0} {
    puts [list $line [string length $line]]
  }
  puts "..."

  puts $sock "HTTP/1.1 200 OK"
  puts $sock ""
  puts $sock "Hello Client"
  flush $sock


  close $sock
}


::tls::socket -server accept 9999

vwait forever

