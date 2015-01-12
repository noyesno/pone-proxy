# vim: syntax=tcl

package provide proxy::httpfsm 0.1

package require pone::fsm

fsm::define http {
  {-          accept   request serve   proxy connect reply  relay close}
  {readable   request  request -       -     -       -      -     -}
  {keep-alive -        -       accept  -     -       -      -     -}
}


fsm::bind http accept {

  set sock    [fsm::var $fsm sock]
  set request [fsm::var $fsm request]
  fsm::var $fsm request ""

  set ret [pone::proxy::http::accept $sock $request]


  if {$ret} {
    fileevent $sock readable [subst {
      fileevent $sock readable ""
      fsm::next $fsm readable
    }]
  } else {
    fsm::goto $fsm close
  }
  return
}

fsm::bind http request {
  set sock    [fsm::var $fsm sock]

  set ret [pone::proxy::http::read_header $sock]

  if {$ret==0} {
    fileevent $sock readable [subst {
      fileevent $sock readable ""
      fsm::next $fsm readable
    }]
    return
  }

  pone::proxy::http::auth $sock

  set req  [pone::proxy::http::get $sock req]
  set method [dict get $req method]
  set dest   [dict get $req path]

  if {[string index $dest 0] eq "/"} {
    fsm::goto $fsm serve
  }  else {
    fsm::goto $fsm proxy
  }

  return
}


fsm::bind http serve {
  set sock    [fsm::var $fsm sock]

  set req    [pone::proxy::http::get $sock req]
  set method [dict get $req method]
  set dest   [dict get $req path]

  pone::proxy::http::serve $sock $method $dest

  # TODO: check keep-alive
  # close $sock
  fileevent $sock readable [subst {
    fileevent $sock readable ""
    fsm::goto $fsm accept
  }]

  #TODO:  fsm::goto $fsm close
}

fsm::bind http proxy {
  set sock    [fsm::var $fsm sock]

  set req    [pone::proxy::http::get $sock req]
  set method [dict get $req method]
  set dest   [dict get $req path]

  pone::proxy::http::proxy $sock $method $dest
}


fsm::bind http relay {
  set sock       [fsm::var $fsm sock]
  set serversock [fsm::var $fsm serversock]
  set host       [fsm::var $fsm host]
  set port       [fsm::var $fsm port]

  set clientsock $sock

  #puts "DEBUG-SOCKS5: socks5 response copy"


  chan configure $clientsock -blocking 0 -buffering none -translation binary
  chan configure $serversock -blocking 0 -buffering none -translation binary

  fileevent $clientsock readable ""
  fileevent $clientsock writable ""
  fileevent $serversock readable ""
  fileevent $serversock writable ""

  #chan copy $clientsock $serversock -command [list relay_close $clientsock $serversock -> $host]
  #chan copy $serversock $clientsock -command [list relay_close $serversock $clientsock <- $host]

  chan copy $clientsock $serversock -command [list fsm::goto $fsm close "" $clientsock $serversock -> $host]
  chan copy $serversock $clientsock -command [list fsm::goto $fsm close "" $serversock $clientsock <- $host]
}

fsm::bind http close {
  lassign $args from to dir host size err

  if {$err ne ""} {
    puts "Error: fcopy: $err $from $dir $to $host"
  }

  if {$dir ne ""} {
    puts "DEBUG-HTTP: close $from $dir $to $host , $size bytes relay"
  }

  set clientsock [fsm::var $fsm sock]
  set serversock [fsm::var $fsm serversock -default ""]

  dict for {sock -} [list $from 0 $to 0 $serversock 0 $clientsock 0] {
    if {$sock ne ""} {
      if [catch {close $sock} err] {
        puts "DEBUG: close $sock fail"
      }
    }
  }
}

proc accept_http_async {sock request} {
  fconfigure $sock -blocking 0 -translation auto

  set fsm [fsm::init http]
  fsm::var $fsm sock    $sock
  fsm::var $fsm request $request

  fsm::start $fsm accept
}



namespace eval pone::proxy::http {}

proc pone::proxy::http::get {sock key} {
  variable {}

  return [dict get ${} $sock $key]
}

proc pone::proxy::http::accept {sock {request ""}} {
  variable {}

  dict set {} $sock req header [dict create] ;# request
  dict set {} $sock res header [dict create] ;# response

  dict set {} $sock res status  "HTTP/1.1 2OO OK"


  append request [chan gets $sock]

  if [eof $sock] {
    puts "client closed: [binary encode hex $request]"
    return 0
  }

  set method [lindex $request 0]
  set dest   [lindex $request 1]

  dict set {} $sock req method $method
  dict set {} $sock req path   $dest

  if {[lsearch $::config(http.method.allow) $method]<0} {
    puts "FAIL: invalid http request: $method $request"
    return 0
  }

  if {[string index $dest 0] eq "/"} {
  }

  lassign [fconfigure $sock -peername] client_addr client_host client_port
  puts "DEBUG-HTTP: $client_host:$client_port -> $request"
  dict set {} $sock req request $request

  set header [dict create]
  dict set header "Proxy-Authenticate"  ""
  dict set header "Proxy-Authorization" ""
  dict set {} $sock req header $header

  return 1
}

proc pone::proxy::http::proxy {args} {
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
  set body "Hello $method $path"

  puts $sock "HTTP/1.1 200 OK"
  puts $sock "Content-Length: [string bytelength $body]"
  puts $sock ""
  puts -nonewline $sock $body
  flush $sock

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

  while {[chan gets $sock line]>=0} {
    if {[string length $line]==0} {
      return 1
    }

    set pos [string first ":" $line]
    set key [string trim [string range $line 0 $pos-1]]
    set val [string trim [string range $line $pos+1 end]]
    dict set {} $sock req header $key $val
  }

  return 0
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
