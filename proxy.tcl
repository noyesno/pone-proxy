

#Ref: Tcl nano proxy server http://wiki.tcl.tk/8833
#Ref: Socks proxy http://wiki.tcl.tk/17263


source config.tcl
source lib/polyfill.tcl

switch [llength $argv] {
    0 {
        lassign {0.0.0.0 8080} host port
    }
    1 {
        lassign [list 0.0.0.0 $argv] host port
    }
    2 {
        lassign $argv host port
    }
}

set listenport [expr {[llength $argv] ? [lindex $argv 1] : 8080}]

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
	relay_write $to

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
    if [string match -nocase "*$pattern*" $site] {
      return  true
    }
  }
  return false
}

proc accept {clientsock clienthost clientport} {
    puts "Connection fom $clienthost:$clientport"
    set request [chan gets $clientsock]
    set dest   [lindex $request 1]
    set method [lindex $request 0]
    #chan configure $clientsock -translation binary

    puts "Request from $clienthost:$clientport -> $request"
    switch -- $method {
      CONNECT {
        accept_connect $clientsock $request
      }
      GET  -
      POST {
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

    set header [list]

    while {[chan gets $clientsock line]>=0} {
      if {[string length $line]==0} break

      set pos [string first ":" $line]
      set key [string trim [string range $line 0 $pos-1]]
      set val [string trim [string range $line $pos+1 end]]
      lappend header $key $val
    }

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

    set serversock [socket $host $port]
    chan puts $serversock $request
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

socket -server accept -myaddr $host $port
puts "Proxy started on $host:$port"

vwait forever

