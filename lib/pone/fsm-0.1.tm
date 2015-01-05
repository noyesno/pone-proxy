# vim: syntax=tcl

package provide pone::fsm 0.1

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

proc fsm::goto {fsm {state ""} {event ""} args} {
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
    $body $fsm $next_state $state $event {*}$args
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

  proc $body_proc {fsm state pstate pevent args} $body

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


# Ref: http://wiki.tcl.tk/40097
#      Determining whether the script is the main script of the program
if {!([info exists argv0] && [file tail $::argv0] eq [file tail [info script]])} {
  # Is not main script
  return
}

fsm::define t {
  {-   s1 s2 s3 s4}
  {e1  s2 s3 s4 s5}
  {e2  s2 s3 s1 s3}
}

set fsm [fsm::init t]
fsm::next $fsm e2 s3
fsm::next $fsm e2 s4


