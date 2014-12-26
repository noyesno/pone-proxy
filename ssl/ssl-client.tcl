
lappend auto_path ../lib
package require tls

::tls::init \
  -cafile   certs/ca.crt     \
  -certfile certs/client.crt \
  -keyfile  certs/client.key \
  -ssl2 1 \
  -ssl3 1 \
  -tls1 1 \
  -require 1 \
  -request 1 \
  -command debug

proc debug {args} {
  puts "SSL: [join $args]"
}

set sock [::tls::socket localhost 9999]
#puts [tls::handshake $sock]
puts $sock "Hello Server"
puts $sock ""
flush $sock
while {[gets $sock line]>=0} {
  puts $line
}
close $sock
