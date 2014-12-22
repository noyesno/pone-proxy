
namespace eval ::polyfill {

  array set half_close [list]

proc close {chan {dir "both"}} {
  variable half_close

  if {![info exists half_close($chan)]} {
    set half_close($chan) [expr 0x03]
  }
  switch -- $dir {
    "read"  {
      set half_close($chan) [expr {$half_close($chan)&0x01}]
    }
    "write" {
      set half_close($chan) [expr {$half_close($chan)&0x02}]
    }
    "both"  {
      set half_close($chan) 0
    }
    default {
      error "Not supported"
    }
  }

  if {$half_close($chan)==0} {
    unset half_close($chan)
    puts "DEBUG: ::close $chan"
    chan close $chan
  }
}

} ; #end namespace polyfill
