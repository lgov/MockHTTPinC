MockHTTPInC
===========

MockHTTPInC is a library that wants to make in-depth testing of HTTP client code possible. The library provides:
- a HTTP server that can be instructed to handle requests in certain ways (e.g. returning a prebaked response, request a SSL client certificate etc.).
- a HTTPS server that supports the full SSL/TLS handshake, client certificates, session renegotiation and session resumption
- a simple HTTP/HTTPS proxy 

Getting started
---------------

Include these 4 source files in your project:
- MockHTTP.c
- MockHTTP.h
- MockHTTP_private.h
- MockHTTP_server.c

MockHTTPInC depends on these libraries:
- Apache's apr and apr-util libraries. (http://apr.apache.org)
- OpenSSL (http://www.openssl.org)

At this time the code conforms to the C99 standard. The code has been written with C89 in mind, but we use variadic macros (a C99 feature) to facilitate test writing.

Write a first test
------------------

    #include "MockHTTP.h"

    ...

    {
        MockHTTP *mh = mhInit();

        Given(mh)
          GetRequest(
            URLEqualTo("/index.html"))
          Respond(
            WithCode(200), WithHeader("Connection", "Close"), WithBody("body"))
        EndGiven
    }


History
-------

The library is based on code originally written to test the serf HTTP client (http://serf.googlecode.com). 
