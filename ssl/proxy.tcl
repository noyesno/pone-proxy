
lappend auto_path lib
package require tls


::tls::init \
  -certfile ssl/server-public.pem \
  -keyfile  ssl/server-private.pem \
  -ssl2 1 \
  -ssl3 1 \
  -tls1 0 \
  -require 0 \
  -request 0


proc accept {sock host port} {
  while {[gets $sock line]>=0} {
    puts $line
  }

  puts "-------------"
  puts [tls::handshake $sock]
  puts "-------------"
  puts [tls::status $sock]
  puts "-------------"
  puts [tls::status -local $sock]
  puts "-------------"

  close $sock
}


::tls::socket -server accept 9999

vwait forever

