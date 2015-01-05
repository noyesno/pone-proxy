
array set ::config {
  ssl 0
  sites.allowed {
   *
  } 

  debug.http.header 1

  http.auth            1
  http.auth.keep-alive 1
}
