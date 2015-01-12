
array set ::config {
  ssl 0
  sites.allowed {
   *
  } 

  debug.http.header 1
  proxy.http           0
  http.method.allow    "GET POST CONNECT"

  http.auth            1
  http.auth.keep-alive 1
}
