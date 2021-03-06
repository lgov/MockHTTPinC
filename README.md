MockHTTPinC
===========

MockHTTPinC is a C library that helps testing HTTP client code.

The library provides:
- a HTTP server that can be instructed to handle requests in certain ways: returning a prebaked response, abort the connection etc.
- support for both HTTP/1.0 and HTTP/1.1 including pipelining and chunked encoding
- macro's to make writing expectations and verifying the results straightforward
- strong HTTPS support: full SSL/TLS handshake, client certificates and session renegotiation
- SSL tunnel support

The library will provide (but does not at this time):
- a simple HTTP proxy
- SSL session resumption
- Basic and Digest authentication
- Deflate/GZip content encoding support

MockHTTPinC does not come with or mandate the use of a specific unit test framework. Instead it should integrate fine with the unit test framework your project is currently using.


MockHTTPinC is currently used by the serf project (See the [project page at google code](http://serf.googlecode.com) ). Serf is a high performance http client library, the MockHTTPinC project was originally started to test all of its features. 
As a consequence, the current feature set of MockHTTPinC is focussed on low-level testing (the http client library) and not so on higher-level testing (the application using the http client library). This will improve in the future.

Getting started
---------------

There are two ways to include MockHTTPinC in your project.

The first is by building a static or dynamic library. You'll need CMake 2.8.8 or later. From the directory that contains the root of the MockHTTPinC project run:

    $ cmake .

    $ make

    $ make check
    
    $ make install


MockHTTPinC also provides an amalgamation file, which contains all the C code in one big file. You'll only need to include these 2 source files in your project:
- MockHTTP_amalgamation.c
- MockHTTP.h

The MockHHTTP_amalgamation.c is included in the release tarball. If you're using the source tree, you can create the file by running the script create_amalgamation.py.


MockHTTPinC depends on these libraries:
- Apache's apr and apr-util libraries. (http://apr.apache.org)
- OpenSSL (http://www.openssl.org)

At this time the code conforms to the C99 standard. The code has been written with C89 in mind, but we use variadic macros (a C99 feature) to facilitate test writing.

Write a first test
------------------

In these examples we will use the CuTest framework (https://github.com/asimjalis/cutest) as unit testing library, you'll recognize its functions by the *Cu* prefix.


**Step 1**: Include MockHTTPinC's main header file, create a test function and set up the mock HTTP server on the default port 30080.

    #include "MockHTTP.h"

    static void test_simple_request_response(CuTest *tc)
    {
      MockHTTP *mh;

      mh = mhInit();
      InitMockServers(mh)
        SetupServer(WithHTTP)
      EndInit

**Step 2**: Use the macro's to instruct the mock HTTP server to expect a GET request to url /index.html. Also, tell the server how to respond when that request arrives.

      Given(mh)
        GETRequest(URLEqualTo("/index.html"))
          Respond(
            WithCode(200), WithHeader("Connection", "Close"),
            WithBody("response body"))
      EndGiven

**Step 3**: Run the code that's expected to eventually send a GET request to the server.

      ctx = connectToTCPServer("http://localhost:30080");
      sendRequest(ctx, "GET", "/index.html", headers, "body of the request");
      response = readResponse(ctx);

      // ... test that the response was received correctly

**Step 4**: Use the macro's to verify that all requests were received in the correct order, at least the one request in this simple example.

      Verify(mh)
        CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
      EndVerify
    }



Documentation
-------------

More documentation is available in [docs/apidocs.md](docs/apidocs.md).



License
-------

The MockHTTPinC project is distributed under the Apache License, version 2.0.



Contributions
-------------
I welcome any contributions that improve this project: bug reports, documentation fixes, code, more tests etc. If you are thinking of using MockHTTPinC in your project and have questions or want to discuss improvements just send me an email.

Note: all code contributions should be made available under the Apache License, version 2.0.
