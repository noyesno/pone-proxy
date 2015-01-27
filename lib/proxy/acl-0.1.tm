# vim: syntax=tcl

package provide proxy::acl 0.1

namespace eval pone::proxy::acl {
  variable ACL      [dict create]

  proc allow {client_addr} {
    variable ACL

    dict set ACL $client_addr proxy 1
    dict set ACL $client_addr mtime [clock seconds]
  }

  proc deny {client_addr} {
    variable ACL

    # catch { dict unset ACL $client_addr proxy }

    dict unset ACL $client_addr
  }

  proc check {client_addr} {
    variable ACL

    if {[dict exists $ACL $client_addr proxy] && [dict get $ACL $client_addr proxy]} {
      dict set ACL $client_addr atime [clock seconds]
      return 1
    }

    return 0
  }
}
