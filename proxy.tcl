
#Ref: Tcl nano proxy server http://wiki.tcl.tk/8833
#Ref: Socks proxy http://wiki.tcl.tk/17263

#------------------------------------------------------------------#
::tcl::tm::path add lib
lappend auto_path ./lib

source conf/config.tcl

#------------------------------------------------------------------#
package require polyfill
package require proxy::socks5
#package require proxy::http
package require proxy::httpfsm
package require proxy::ssl

#------------------------------------------------------------------#


set host "" ; set port ""

for {set i 0} {$i<$argc} {incr i} {
  set arg [lindex $argv $i]

  switch -- $arg {
    -c      { source [lindex $argv [incr i]] }
    -l      -
    -listen {
      lassign [lreverse [split [lindex $argv [incr i]] ":"]] port host 
    }
  }
}

if {$host eq ""} { set host 0.0.0.0 } 
if {$port eq ""} { set port 8080 } 



array set ::buffer [list]
array set ::vwait_vars [list]

proc read_reply_headers {serversock clientsock dir host} {
  # Is there any potential buffer full attack?
  while {[chan gets $serversock line]>=0} {
    # TODO: check buffer size
    lappend ::buffer($serversock) $line
    if {[string length $line]==0} {
      set ::vwait_vars(proxy,$serversock) connected
      chan event $serversock readable ""
      return
    }
  }

  if [chan eof $serversock] {
    set ::vwait_vars(proxy,$serversock) eof
    chan event $serversock readable ""
  }
}

proc relay_close {from to dir host size {err ""}} {
  if {$err ne ""} {
    puts "Relay Error: $err"
  }
  puts "RELAY_CLOSE $from $to $dir $host $size $err"
  # chan close $from read
  # chan close $to   write
  # TODO: not support half close in 8.5
  polyfill::close $from read
  polyfill::close $to   write
}

proc relay_write {to dir host} {
  puts "DEBUG: relay_write $dir $host [string length $::buffer($to)]"
  chan puts -nonewline $to $::buffer($to)
  chan event $to writable ""
  array unset ::buffer $to
}

proc relay {from to dir host} {
    if {[chan eof $from]} {
	# TODO: error handling
	# TODO: keep parent socket connection to reuse
	# TODO
	append ::buffer($to) ""
	relay_write $to $dir $host

        catch {chan close $from}
        catch {chan close $to}
    } else {
        #- set size [chan pending input $from]
        #- puts "DEBUG: [list $from -> $to $size]"
	#- if {$size > 0} {
        #-   chan copy $from $to -size $size
        #- }

        # puts "DEBUG: pending [list [chan pending input $from] [chan pending output $from] [chan pending input $to] [chan pending output $to]]"
        set data [chan read $from]
	set size [string length $data]
	if {$size > 0} {
          puts [list $dir $host $size]
	  append ::buffer($to) $data
	  chan event $to writable [list relay_write $to $dir $host]
          # chan puts -nonewline $to $data
        }
    }
}

proc is_site_allowed {site} {
  foreach pattern $::config(sites.allowed) {
    # TODO: lowercase first 
    # ...
    if {$pattern eq "*" || [string match -nocase "*$pattern*" $site]} {
      return  true
    }
  }
  return false
}




proc accept_socks5 {sock request} {
  binary scan $request {cc} ver nmethod

  binary scan [read $sock $nmethod] {c*} methods

  if {$nmethod == 1} {
    puts "DEBUG $nmethod $methods"
    chan puts -nonewline $sock [binary format {cc} $ver [lindex $methods 0]]
    chan flush $sock
  }

  binary scan [read $sock 4] {cccc} ver cmd rsv atyp

  puts "DEBUG: cmd = $cmd , atyp = $atyp"

  set host ""
  switch $atyp {
    1 {
      # IP4
      read $sock 4
    }
    3 {
      # Domain Name
      binary scan [read $sock 1] {c} size
      set host [read $sock $size]
      puts "DEBUG: host = $host"
    }
    4 {
      # IP6
      read $sock 16
    }
    default {
      puts "DEBUG: not match"
    }
  }

  binary scan [read $sock 2] {S} port
  puts "DEBUG: connect $host:$port"
  # TODO: 


  if [catch {set serversock [socket $host $port]} err] {
    puts "Warn: fail to connect to $host:$port"
    close $clientsock
  }

  puts "DEBGUG: [fconfigure $serversock]"

# -peername {173.252.120.6 edge-star-shv-12-frc3.facebook.com 443}
# -sockname {10.15.140.230 pcgiopl-icc41.internal.synopsys.com 39717}

  lassign [fconfigure $serversock -peername] remote_ip remote_host remote_port
  lassign [fconfigure $serversock -sockname] bind_ip bind_host bind_port
  puts "DEBGUG: remote = $remote_ip $remote_host $remote_port"
  puts "DEBGUG: bind   = $bind_ip   $bind_host   $bind_port"

  puts "DEBUG: socks5 response"
  #set data [binary format {c c c c ca* S} $ver 0x00 0x00 0x03 [string length $bind_ip] $bind_ip $bind_port]
  set data [binary format {c c c c I S} $ver 0x00 0x00 0x01 0x00 $bind_port]
  chan puts -nonewline $sock $data
  puts "DEBUG: socks5 [binary encode hex $data]"

  chan flush $sock
  puts "DEBUG: socks5 response flush"

  set clientsock $sock

  puts "DEBUG: socks5 response copy"
  chan configure $clientsock -blocking 0 -buffering none -translation binary
  chan configure $serversock -blocking 0 -buffering none -translation binary
  chan copy $clientsock $serversock -command [list relay_close $clientsock $serversock -> $host]
  chan copy $serversock $clientsock -command [list relay_close $serversock $clientsock <- $host]
}

proc accept_reject {clientsock request} {
  append request [chan read $clientsock 64]
  lassign [fconfigure $clientsock -peername] client_addr client_host client_port
  puts "reject $clientsock $client_addr:$client_port $request"
  close $clientsock
}

proc accept {clientsock clienthost clientport} {
  #-- puts "Connection fom $clienthost:$clientport"

  #puts [fconfigure $clientsock]
  chan configure $clientsock -blocking 0
  chan configure $clientsock -translation binary -encoding binary
  #puts [fconfigure $clientsock]

  chan event $clientsock readable [list accept_read $clientsock $clienthost $clientport]

  return
}

proc accept_read {clientsock clienthost clientport} {
  set request [read $clientsock 2] 
  set nbytes  [string length $request]
  if {$nbytes!=2} {
    puts "Invalid Connection: $clienthost:$clientport # $nbytes , [expr {[eof $clientsock]?"eof":""}]"
    close $clientsock
    return
  }

  if {[string index $request 0] eq "\x05"} {
    #-- puts "DEBUG: sock5 detected"
    #accept_socks5 $clientsock $request
    accept_socks5_async $clientsock $request
    return
  }

  if {$::config(proxy.http) || $::config(server.http)} {
    # TODO: CHECK $request
    accept_http_async $clientsock $request
    return
  }

  accept_reject $clientsock $request

  return
}








proc relay_connect {clientsock host port proto} {
    if [catch {set serversock [socket $host $port]} err] {
      puts "Warn: fail to connect to $host:$port"
      close $clientsock
    }

    chan puts $clientsock "HTTP/1.1 200 Tunnel Established"
    chan puts "$proto 200 Tunnel Established"
    #chan puts $clientsock "Proxy-Agent: Tcl Proxy"
    chan puts $clientsock ""
    chan flush $clientsock

    if [eof $serversock] {
      puts "Warn: EOF server sock $serversock"
    }

    puts "INFO: relay $clientsock $serversock"

    chan configure $clientsock -blocking 0 -buffering none -translation binary
    chan configure $serversock -blocking 0 -buffering none -translation binary
    chan copy $clientsock $serversock -command [list relay_close $clientsock $serversock -> $host]
    chan copy $serversock $clientsock -command [list relay_close $serversock $clientsock <- $host]
}







if {$::config(ssl)} {
  ssl_init
  ::tls::socket -server accept -myaddr $host $port
} else {
  socket -server accept -myaddr $host $port
}

puts "Proxy started on $host:$port"

vwait forever

