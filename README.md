MockHTTPInC
===========

MockHTTPInC is a library that wants to make in-depth testing of HTTP client code possible. The library provides:
- a HTTP server that can be instructed to handle requests in certain ways (e.g. returning a prebaked response, request a SSL client certificate etc.).
- a HTTPS server that supports the full SSL/TLS handshake, client certificates, session renegotiation and session resumption
- a simple HTTP/HTTPS proxy 

The library is based on code originally written to test the serf HTTP client (http://serf.googlecode.com). 

    Given(mh)
      GetRequest(
        URLEqualTo("/index.html"))
      Respond(
        WithCode(200),
        WithHeader("Connection", "Close"),
        WithBody("blabla"))
    SubmitGiven
