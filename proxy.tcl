
#Ref: Tcl nano proxy server http://wiki.tcl.tk/8833
#Ref: Socks proxy http://wiki.tcl.tk/17263

#------------------------------------------------------------------#
::tcl::tm::path add lib
lappend auto_path ./lib

source conf/config.tcl

#------------------------------------------------------------------#
package require polyfill
package require proxy::socks5
package require proxy::http
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

proc accept {clientsock clienthost clientport} {
  puts "Connection fom $clienthost:$clientport"

  #puts [fconfigure $clientsock]
  fconfigure $clientsock -translation auto -encoding binary
  #puts [fconfigure $clientsock]

  set request [read $clientsock 2] 

  if {[string index $request 0] eq "\x05"} {
    puts "DEBUG: sock5 detected"
    #accept_socks5 $clientsock $request
    accept_socks5_async $clientsock $request
  }

  #close $clientsock
  return
  set request [chan gets $clientsock]


    binary scan $request H* hex

    #-- puts "bytes: [string length $request]"
    #-- puts "bytes: $hex"
    #-- puts "bytes: [binary encode hex $request]"


    set dest   [lindex $request 1]
    set method [lindex $request 0]
    #chan configure $clientsock -translation binary

    puts "Request from $clienthost:$clientport -> $request"

    if [regexp {\w+ /.*} $request] {
      puts  $clientsock "HTTP/1.1 200 OK"
      puts  $clientsock ""
      puts  $clientsock "Hello"
      close $clientsock
      return
    }

    switch -- $method {
      CONNECT {
        pone::proxy::http::accept $clientsock $request
        accept_connect $clientsock $request
      }
      GET  -
      POST {
        pone::proxy::http::accept $clientsock $request
        accept_http    $clientsock $request
      }
      default {
        puts "FAIL: $method $request"
        accept_invalid $clientsock $request
      }
    }
}

# CONNECT www.google.com:443 HTTP/1.1
proc accept_connect {clientsock request} {
    set dest   [lindex $request 1]
    set method [lindex $request 0]
    set proto  [lindex $request 2]

    if [regexp {^([^:/]+)(?::([0-9]+))?} $dest -> host port] {
      puts "DEBUG: accept_connect $host $port $proto"
    }

    if {![is_site_allowed $host]} {
      puts "DEBUG: refuse $host"
      chan close $clientsock
      return
    }


    # proxy_connect $clientsock $host $port $proto $phost $pport
    relay_connect $clientsock $host $port $proto
}


proc proxy_connect {clientsock host port proto phost pport} {
    set serversock [socket $phost $pport]

    #- puts $clientsock "HTTP/1.1 200 Tunnel Established"
    #- puts "$proto 200 Tunnel Established"
    #- #puts $clientsock "Proxy-Agent: Tcl Proxy"
    #- puts $clientsock ""
    #- flush $clientsock
    #

    # this line can move to before puts $serversock
    chan configure $serversock -blocking 0

    set host_shadowed [string reverse $host]
    set host_shadowed $host
    chan puts $serversock "$method $host_shadowed:$port $proto"

    while {[chan gets $clientsock line]>=0} {
      puts "DEBUG: $line"
      if  [string equal -nocase -length 5 $line "Host:"] {
        puts $serversock "Host: $host_shadowed"
      } else {
        #puts $serversock [string reverse $line]
        chan puts $serversock $line
      }

      if {[string length $line]==0} break
    }
    chan flush $serversock



    set    ::buffer($serversock) ""
    chan event $serversock readable [list read_reply_headers $serversock $clientsock <- $host]

    set timer [after 3000 "set ::vwait_vars(proxy,$serversock) timeout"]
    vwait vwait_vars(proxy,$serversock)
    after cancel $timer

    switch -- $::vwait_vars(proxy,$serversock) {
      timeout {
	# ...
	puts "DEBUG: Connect Timeout"
      }
      eof {
	# ...
	puts "WARN: Connect EOF. Possibbly Wall Met"

	# DONT try to send message to client. It will not be shown.
	# Or, the message need to be based on HTTPS protocal
	

	chan puts $clientsock "HTTP/1.1 400 Closed"
	chan puts $clientsock ""
	chan puts $clientsock "Wall Met"
	chan flush $clientsock

	catch {chan close $serversock}
	catch {chan close $clientsock}
	#TODO: how to handle keep-alive in such situation
	return
      }
      connected {
        set status_line [lindex $::buffer($serversock) 0] 

        set    ::buffer($serversock) [join $::buffer($serversock) "\r\n"]
        append ::buffer($serversock) "\r\n"

        puts "DEBUG: $::buffer($serversock)"
	if {[string first 200 $status_line]>0} {
	  # Established
	  puts "DEBUG: Connection Established"
	} else {
	  # Has Response, But Fail
	  puts "DEBUG: Connection Response Invalid"
	}

      }
    }

    unset ::vwait_vars(proxy,$serversock)

    chan configure $clientsock -blocking 0 -buffering none -translation binary
    chan configure $serversock -blocking 0 -buffering none -translation binary

    chan puts -nonewline $clientsock $::buffer($serversock)
    chan flush $clientsock
    unset ::buffer($serversock)

    # relay both direction
    # TODO: use fileevent readable for clientsock to support keep-alive???
    # XXX: Proxy-Connection: keep-alive means not auto close client sock???
    # INFO: Tcl 8.5.2 error out 'channel $to is busy'
    chan copy $clientsock $serversock -command [list relay_close $clientsock $serversock -> $host]
    chan copy $serversock $clientsock -command [list relay_close $serversock $clientsock <- $host]

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


proc accept_http {clientsock request} {
    set dest   [lindex $request 1]
    set method [lindex $request 0]

    #set port "" 
    if [regexp {^([^:]+)://([^:/]+)(?::([0-9]+))?} $dest -> scheme host port] {
      puts "accept_http $scheme://$host:$port"
    } else {
      puts "DEBUG: match fail $dest"
    }
    if {$port eq ""} {set port 80}

    if {![is_site_allowed $host]} {
      #puts "DEBUG: refuse $host"
      chan close $clientsock
      return
    }


    if [catch {set serversock [socket $host $port]} err] {
      puts "Warn: fail to connect to $host:$port"
      close $clientsock
    }


    pone::proxy::http::relay_request $clientsock $serversock

    chan configure $clientsock -blocking 0 -buffering none -translation binary
    chan configure $serversock -blocking 0 -buffering none -translation binary
    chan event $clientsock readable [list relay $clientsock $serversock -> $host]
    chan event $serversock readable [list relay $serversock $clientsock <- $host]
}

proc accept_invalid {clientsock request} {
    set dest   [lindex $request 1]
    set method [lindex $request 0]

    puts "Invalid: $request"
    chan copy $clientsock stdout
    close $clientsock
}





if {$::config(ssl)} {
  ssl_init
  ::tls::socket -server accept -myaddr $host $port
} else {
  socket -server accept -myaddr $host $port
}

puts "Proxy started on $host:$port"

vwait forever

