# vim: syntax=tcl

package provide proxy::http 0.1


namespace eval pone::proxy::http {}

proc pone::proxy::http::get {sock key} {
  variable {}

  return [dict get ${} $key]
}

proc pone::proxy::http::accept {sock {request ""}} {
  variable {}

  dict set {} $sock req header [dict create] ;# request
  dict set {} $sock res header [dict create] ;# response

  dict set {} $sock res status  "HTTP/1.1 2OO OK"

  if [eof $sock] {
    puts "client closed: [binary encode hex $request]"
    return 1
  }

  if {$request eq ""} {
    set request [chan gets $sock]
  }

  set method [lindex $request 0]
  set dest   [lindex $request 1]

  if {[lsearch $::config(http.method.allow) $method]<0} {
    puts "FAIL: invalid http request: $method $request"
    return 0
  }

  if {[string index $dest 0] eq "/"} {
  }

  lassign [fconfigure $sock -peername] client_addr client_host client_port
  puts "HTTP-DEBUG: $client_host:$client_port -> $request"
  dict set {} $sock req request $request

  read_header $sock
  auth        $sock

  if {[string index $dest 0] eq "/"} {
    serve $sock $method $dest
    return 1
  }

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
  return 1
}

proc pone::proxy::http::serve {sock method path} {
  puts  $sock "HTTP/1.1 200 OK"
  puts  $sock ""
  puts  $sock "Hello"

  # close $sock

  accept $sock
  return
}

proc pone::proxy::http::response {sock} {
  variable {}

  set val [dict get ${} $sock res status]
  chan puts $sock $val
  puts "RES: $val"
  dict for {key val} [dict get ${} $sock res header] {
    chan puts $sock "$key: $val"
    puts "RES: $key: $val"
  }
  chan puts $sock ""
  chan flush $sock
}

proc pone::proxy::http::relay_request {sock psock} {
  variable {}

  #TODO: remove Proxy-*
  chan puts $psock [dict get ${} $sock req request]
  dict for {key val} [dict get ${} $sock req header] {
    if {[string equal -nocase -length 6 $key "Proxy-"]} continue
    chan puts $psock "$key: $val"
  }
  chan puts $psock ""
  chan flush $psock
}

proc pone::proxy::http::read_header {sock} {
  variable {}

  # TODO: performance
  set header [dict create]


  dict set header "Proxy-Authenticate"  ""
  dict set header "Proxy-Authorization" ""

  while {[chan gets $sock line]>=0} {
    if {[string length $line]==0} break

    set pos [string first ":" $line]
    set key [string trim [string range $line 0 $pos-1]]
    set val [string trim [string range $line $pos+1 end]]
    dict set header $key $val
  }

  dict set {} $sock req header $header
  puts "DEBUG: $header"
  return $header
}

#
# WWW Server
# ----------
# S->C: WWW-Authenticate: Basic realm="WallyWorld"
# C->S: Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
#
# [binary encode base64 $userid:$password]
#
# Proxy Sever
# -----------
# S->C: "Proxy-Authenticate"
# C->S: "Proxy-Authorization"
#
proc pone::proxy::http::auth {sock} {
  variable {}

  if {!$::config(http.auth)} return


  set credentials [dict get ${} $sock req header "Proxy-Authorization"]
  lassign $credentials scheme userpass

  if {$scheme eq "Basic"} {
    lassign [split [binary decode base64 $userpass] ":"] user password
    puts "user = $user , password = $password"
    return 1
  }

  set realm "Pone Proxy"
  dict set {} $sock res status "HTTP/1.1 407 Proxy Authentication Required"
  dict set {} $sock res header "Proxy-Authenticate" "Basic realm=\"$realm\""
  dict set {} $sock res header "Content-Length" 0

  #-- TODO:
  #-- TODO:
  if {$::config(http.auth.keep-alive)} {
    response $sock
    accept   $sock
    return
  } else {
    response $sock
    close $sock
    return -level 3 0
  }


}

proc pone::proxy::http::accept_invalid {clientsock request} {
    set dest   [lindex $request 1]
    set method [lindex $request 0]

    puts "Invalid: $request"
    chan copy $clientsock stdout
    close $clientsock
}

proc pone::proxy::http::accept_http {clientsock request} {
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

# CONNECT www.google.com:443 HTTP/1.1
proc pone::proxy::http::accept_connect {clientsock request} {
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

# not used
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
