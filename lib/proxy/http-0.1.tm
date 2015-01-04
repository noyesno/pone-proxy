# vim: syntax=tcl

package provide pone-proxy-http 0.1


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
    puts "client closed"
    return
  }

  if {$request eq ""} {
    set request [chan gets $sock]
  }

  dict set {} $sock req request $request

  read_header $sock
  auth        $sock

  return 1
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

