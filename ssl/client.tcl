
lappend auto_path lib
package require tls

set sock [::tls::socket localhost 9999]
puts $sock Hello
puts $sock World
close $sock
