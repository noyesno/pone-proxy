# vim: syntax=tcl

package provide proxy::httpfsm 0.1

package require pone::fsm

fsm::define http {
  {-          accept   request serve   proxy connect reply  relay close}
  {readable   request  request -       -     -       -      -     -}
  {keep-alive -        -       accept  -     -       -      -     -}
}

# TODO: add a dispatch

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




  if {!$::config(proxy.http)} {
    fsm::goto $fsm close
    return
  }

  lassign [fconfigure $sock -peername] client_addr client_host client_port

  if {![pone::proxy::acl::check $client_addr]} {
    fsm::goto $fsm close
    return
  }

  set req    [pone::proxy::http::get $sock req]
  set method [dict get $req method]
  set dest   [dict get $req path]
  set proto  [dict get $req proto]

  pone::proxy::http::proxy $sock $method $dest $proto
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
      } else {
        #puts "DEBUG: close $sock succ"
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



namespace eval pone::proxy::http {
  variable {}       [dict create]
  variable handlers [dict create]
}

# register * ?-fiter? ?-rank 10? [list hname hargv]
proc pone::proxy::http::register {pattern args} {
  variable handlers

  set is_filter 0
  set rank      1
  set hname     [lindex $args end 0]
  set hargv     [lindex $args end 1]

  for {set i 0 ; set argc [llength $args] ; incr argc -1} { $i<$argc } {incr i} {
    set arg [lindex $args $i]
    switch -- $arg {
      -filter { set is_filter 1 }
      -rank   { set rank [lindex $args [incr i]] }
      default {
        #
      }
    }
  }

  dict set handlers $pattern [list $rank $is_filter $hname $hargv]
}

namespace eval pone::proxy::http::handler {
  #
  pone::proxy::http::register * -rank 0 [list pone::proxy::http::handler::default ]
  pone::proxy::http::register /checkin  -rank 1 [list pone::proxy::http::checkin]
  pone::proxy::http::register /checkout -rank 1 [list pone::proxy::http::checkout]
}

proc pone::proxy::http::checkin {sock} {

  lassign [fconfigure $sock -peername] client_addr client_host client_port
  pone::proxy::acl::allow $client_addr

  set body [pone::proxy::http::get $sock]

  append body  "\n" "Pone Door Opended For $client_addr!"

  puts $sock "HTTP/1.1 200 OK"
  puts $sock "Content-Type: text/plain"
  puts $sock "Content-Length: [string bytelength $body]"
  puts $sock ""
  puts -nonewline $sock $body
  flush $sock
}

proc pone::proxy::http::checkout {sock} {

  lassign [fconfigure $sock -peername] client_addr client_host client_port
  pone::proxy::acl::deny $client_addr

  set body [pone::proxy::http::get $sock]
  append body  "\n" "Pone Door Closed For $client_addr!"

  puts $sock "HTTP/1.1 200 OK"
  puts $sock "Content-Type: text/plain"
  puts $sock "Content-Length: [string bytelength $body]"
  puts $sock ""
  puts -nonewline $sock $body
  flush $sock
}

proc pone::proxy::http::handler::default {sock args} {
  set body [pone::proxy::http::get $sock]

  puts $sock "HTTP/1.1 200 OK"
  puts $sock "Content-Type: text/plain"
  puts $sock "Content-Length: [string bytelength $body]"
  puts $sock ""
  puts -nonewline $sock $body
  flush $sock
}


proc pone::proxy::http::get {sock {key ""}} {
  variable {}

  if {$key eq ""} {
    return [dict get ${} $sock]
  }

  return [dict get ${} $sock $key]
}

proc pone::proxy::http::accept {sock {request ""}} {
  variable {}

  append request [chan gets $sock]

  if [eof $sock] {
    puts "client closed: [binary encode hex $request]"
    return 0
  }

  if {[catch {llength $request}] || [llength $request]!=3} {
    # invalide HTTP request
    puts "Invaid HTTP request: [binary encode hex $request]"
    return 0
  }

  set method [lindex $request 0]
  set dest   [lindex $request 1]
  set proto  [lindex $request 2]

  if {[lsearch $::config(http.method.allow) $method]<0} {
    puts "FAIL: invalid http request: $method $request"
    return 0
  }

  # use a ::ini::
  dict set {} $sock req request $request
  dict set {} $sock req header [dict create] ;# request
  dict set {} $sock res header [dict create] ;# response
  dict set {} $sock res status  "HTTP/1.1 2OO OK"
  dict set {} $sock req method $method
  dict set {} $sock req path   $dest
  dict set {} $sock req proto  $proto

  lassign [fconfigure $sock -peername] client_addr client_host client_port
  #TODO: has reverse dns lookup here?
  puts "DEBUG-HTTP: $client_host/$client_addr:$client_port -> $request"

  set header [dict create]
  dict set header "Proxy-Authenticate"  ""
  dict set header "Proxy-Authorization" ""
  dict set {} $sock req header $header

  return 1
}

proc pone::proxy::http::proxy {sock method dest proto} {
    switch -- $method {
      CONNECT {
        accept_connect $sock $method $dest $proto
      }
      GET  -
      POST {
        accept_http    $sock $method $dest $proto
      }
      default {
        accept_invalid $sock $method $dest $proto
      }
    }
  return 1
}

proc pone::proxy::http::serve {sock method path} {
  variable handlers

  set handler_matched [list]
  dict for {pattern val} $handlers {
    if {[string match $pattern $path]} {
      lappend handler_matched $val
    }
  }

  set handler_matched [lsort -decr -index 0 -integer $handler_matched]

  foreach handler $handler_matched {
    lassign $handler rank is_filter hname hargv
    $hname $sock {*}$hargv
    if {!($is_filter ne "" && $is_filter)} {
      break
    }
  }

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

proc pone::proxy::http::accept_invalid {clientsock method dest proto} {
    puts "FAIL: Unsupported proxy method: $method $dest $proto"
    chan copy $clientsock stdout
    close $clientsock
}

proc pone::proxy::http::accept_http {clientsock method dest proto} {

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
proc pone::proxy::http::accept_connect {clientsock method dest proto} {

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
