
lappend auto_path ../lib
package require tls

::tls::init \
  -cafile   certs/ca.crt     \
  -certfile certs/client.crt \
  -keyfile  certs/client.key \
  -ssl2 0 \
  -ssl3 1 \
  -tls1 0 \
  -require 0 \
  -request 0 \
  -command debug

proc debug {args} {
  puts "SSL: [join $args]"
}

lassign $argv host port

set sock [::tls::socket $host $port]
#puts [tls::handshake $sock]
puts $sock "GET https://duckduckgo.com/"
puts $sock ""
flush $sock
while {[gets $sock line]>=0} {
  puts $line
}
close $sock
