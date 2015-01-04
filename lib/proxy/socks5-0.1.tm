# vim: syntax=tcl

namespace eval fsm {
  variable .schema  [dict create]
  variable .lut     [dict create]
  variable .bind    [dict create]
  variable .inst    [dict create]

}

proc fsm::define {name schema} {
  variable .schema
  variable .lut

  dict set .schema $name $schema

  for {set i 1 ; set ni [llength [lindex $schema 0]]} {$i < $ni} {incr i} {
    set s [lindex $schema 0 $i]
    for {set j 1 ; set nj [llength $schema]} {$j < $nj} {incr j} {
      set e [lindex $schema $j 0]
      set next_state [lindex $schema $j $i]
      if [dict exists ${.lut} $name $s $e] continue
      if {$next_state eq "-" || $next_state eq ""} continue
      dict set .lut $name $s $e $next_state
    }
  }
  return
}

proc fsm::init {name {state ""}} {
  variable .inst

  set id "fsm[info cmdcount]"

  dict set .inst $id name  $name
  dict set .inst $id state ""
  dict set .inst $id args  ""

  return $id
}

proc fsm::start {fsm {state ""}} {
  # TODO: set state $state

  goto $fsm $state
  return
}

proc fsm::goto {fsm {state ""} {event ""}} {
  variable .lut
  variable .inst
  variable .bind

  set name [dict get ${.inst} $fsm name]
  set next_state $state

  dict set .inst $fsm state $next_state

  if {![dict exists ${.bind} $name $next_state body]} {
    return
  }

  set body [dict get ${.bind} $name $next_state body]

  if {$body ne ""} {
    $body $fsm $next_state $state $event
  }
  return
}

proc fsm::next {fsm {event "-"} {state "-"}} {
  variable .lut
  variable .inst
  variable .bind

  puts "DEBUG: next $state + $event => ..."
  if {$state eq "" || $state eq "-"} {
    set state [dict get ${.inst} $fsm state]
  }

  set name [dict get ${.inst} $fsm name]

  set next_state [dict get ${.lut} $name $state $event]
  puts "DEBUG: next $state + $event => $next_state"

  goto $fsm $next_state $event
  return
}

proc fsm::bind {name state {body ""}} {
  variable .bind

  set body_proc "::fsm::{[list state-body $name $state [info cmdcount]]}"
  #TODO: unset this

  proc $body_proc {fsm state pstate pevent} $body

  dict set .bind $name $state body $body_proc
  return
}

proc fsm::var {fsm var args} {
  variable .inst

  if [llength $args] {
    dict set .inst $fsm args $var [lindex $args 0]
    return
  }

  set ret [dict get ${.inst} $fsm args $var]

  return $ret
}


fsm::define t {
  {-   s1 s2 s3 s4}
  {e1  s2 s3 s4 s5}
  {e2  s2 s3 s1 s3}
}

set fsm [fsm::init t]
fsm::next $fsm e2 s3
fsm::next $fsm e2 s4


fsm::define socks5 {
  {-         accept   request connect reply relay}
  {readable  request  -       -       -     -}
  {-         -        connect -       -     -}
  {connected -        -       reply   -     -}
  {-         -        -       -       relay -}
}


fsm::bind socks5 accept {

  set sock    [fsm::var $fsm sock]
  set request [fsm::var $fsm request]

  binary scan $request {cc} ver nmethod

  binary scan [read $sock $nmethod] {c*} methods

  fsm::var $fsm version $ver

  if {$nmethod == 1} {
    puts "DEBUG $nmethod $methods"
    chan puts -nonewline $sock [binary format {cc} $ver [lindex $methods 0]]
    chan flush $sock
  }


  fileevent $sock readable [subst {
    fileevent $sock readable ""
    fsm::next $fsm readable
  }]
  return
}

fsm::bind socks5 request {
  set sock    [fsm::var $fsm sock]

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

  fsm::var $fsm host $host
  fsm::var $fsm port $port

  fsm::next $fsm  ;# connect
  return
}


fsm::bind socks5 connect {
  set sock    [fsm::var $fsm sock]
  set host    [fsm::var $fsm host]
  set port    [fsm::var $fsm port]

  if [catch {set serversock [socket -async $host $port]} err] {
    puts "Warn: fail to connect to $host:$port"
    close $clientsock
  }

  fsm::var $fsm serversock $serversock

  fileevent $serversock writable [subst {
    fileevent $serversock writable ""
    fsm::next $fsm connected
  }]
}

fsm::bind socks5 reply {

  set sock       [fsm::var $fsm sock]
  set serversock [fsm::var $fsm serversock]
  puts "DEBGUG: [fconfigure $serversock]"

  set sock    [fsm::var $fsm sock]
  set ver     0x05

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

  fsm::next $fsm ;# relay
}

fsm::bind socks5 relay {
  set sock       [fsm::var $fsm sock]
  set serversock [fsm::var $fsm serversock]
  set host       [fsm::var $fsm host]
  set port       [fsm::var $fsm port]

  set clientsock $sock

  puts "DEBUG: socks5 response copy"
  chan configure $clientsock -blocking 0 -buffering none -translation binary
  chan configure $serversock -blocking 0 -buffering none -translation binary
  chan copy $clientsock $serversock -command [list relay_close $clientsock $serversock -> $host]
  chan copy $serversock $clientsock -command [list relay_close $serversock $clientsock <- $host]
}

fsm::bind socks5 close {
}

proc accept_socks5_async {sock request} {
  fconfigure $sock -blocking 0

  set fsm [fsm::init socks5]
  fsm::var $fsm sock    $sock
  fsm::var $fsm request $request

  fsm::start $fsm accept
}

