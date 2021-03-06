# vim: syntax=tcl

package provide proxy::socks5 0.1

package require pone::fsm

fsm::define socks5 {
  {-         accept   request connect reply  relay close}
  {readable  request  -       -       -      -     -}
  {-         -        connect -       -      -     -}
  {connected -        -       reply   relay  -     -}
  {fail      -        -       reply   close  -     -}
  {-         -        -       -       -      close -}
}


fsm::bind socks5 accept {

  set sock    [fsm::var $fsm sock]
  set request [fsm::var $fsm request]

  lassign [fconfigure $sock -peername] client_addr client_host client_port

  if {![pone::proxy::acl::check $client_addr]} {
    puts "DEBUG-SOCKS5: deny $client_addr"
    fsm::goto $fsm close
    return
  }



  binary scan $request {cc} ver nmethod

  binary scan [read $sock $nmethod] {c*} methods

  fsm::var $fsm version $ver

  if {$nmethod == 1} {
    #-- puts "DEBUG $nmethod $methods"
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

  set buf [read $sock 4]
  if {[string length $buf]!=4} {
    puts "IO Error: [binary encode hex $buf]"
    close $sock
    return
  }

  binary scan $buf {cccc} ver cmd rsv atyp

  # puts "DEBUG-SOCKS5: cmd = $cmd , atyp = $atyp"

  set host ""
  switch $atyp {
    1 {
      # IP4
      read $sock 4
    }
    3 {
      # Domain Name
      binary scan [read $sock 1] {c} size
      # TODO:
      set host [read $sock $size]
      # puts "DEBUG-SOCKS5: $size host = $host"
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
  lassign [fconfigure $sock -peername] client_addr client_host client_port
  puts "DEBUG-SOCKS5: request $client_addr:$client_port -> $host:$port"
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

  fsm::var $fsm serversock ""

  if [catch {set serversock [socket -async $host $port]} err] {
    puts "Warn: fail to connect to $host:$port"
    # close $clientsock
    fsm::next $fsm fail
    return
  }

  fsm::var $fsm serversock $serversock

  fileevent $serversock writable [subst {
    fileevent $serversock writable ""
    fsm::next $fsm connected
  }]
}

fsm::bind socks5 reply {

  set sock       [fsm::var $fsm sock]


# -peername {173.252.120.6 edge-star-shv-12-frc3.facebook.com 443}
# -sockname {10.15.140.230 pcgiopl-icc41.internal.synopsys.com 39717}

  set bind_port 0
  switch -- $pevent {
    connected {
      set serversock [fsm::var $fsm serversock]
      #-- puts "DEBUG: [fconfigure $serversock]"
      set reply_stat 0x00 ;# succeeded
      lassign [fconfigure $serversock -peername] remote_ip remote_host remote_port
      lassign [fconfigure $serversock -sockname] bind_ip bind_host bind_port
      #-- puts "DEBGUG: remote = $remote_ip $remote_host $remote_port"
      #-- puts "DEBGUG: bind   = $bind_ip   $bind_host   $bind_port"
    }
    fail {
      set reply_stat 0x04 ;# Host unreachable
      #
    }
  }

  set ver        0x05
  #puts "DEBUG-SOCKS5: response"
  #set data [binary format {c c c c ca* S} $ver 0x00 0x00 0x03 [string length $bind_ip] $bind_ip $bind_port]
  set data [binary format {c c c c I S} $ver $reply_stat 0x00 0x01 0x00 $bind_port]
  chan puts -nonewline $sock $data
  #puts "DEBUG-SOCKS5: socks5 [binary encode hex $data]"

  chan flush $sock
  #puts "DEBUG-SOCKS5: socks5 response flush"

  fsm::next $fsm $pevent;# relay
}

fsm::bind socks5 relay {
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

fsm::bind socks5 close {
  lassign $args from to dir host size err

  if {$err ne ""} {
    puts "Error: fcopy: $err $from $dir $to $host"
  }

  puts "DEBUG-SOCKS5: close $from $dir $to $host , $size bytes relay"

  set clientsock [fsm::var $fsm sock -default ""]
  set serversock [fsm::var $fsm serversock -default ""]

  dict for {sock -} [list $from 0 $to 0 $serversock 0 $clientsock 0] {
    if {$sock ne ""} {
      if [catch {close $sock} err] {
        puts "DEBUG: close $sock fail"
      }
    }
  }
}

proc accept_socks5_async {sock request} {
  fconfigure $sock -blocking 0

  set fsm [fsm::init socks5]
  fsm::var $fsm sock    $sock
  fsm::var $fsm request $request

  fsm::start $fsm accept
}

