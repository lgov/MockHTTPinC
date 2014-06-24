How to use MockHTTPinC ?
========================

The purpose of this library is to facilitate testing of clients that use 
HTTP to talk with a server.

A complete test scenario would look like this:

1. Initialize the client and the MockHTTPinC library
2. Setup and start the mock HTTP server
3. Configure the client to use the mock server
4. Define how the mock server should respond to HTTP requests it receives.
5. Use the client under test, which will:
   * send HTTP requests to the mock server
   * read and handle the HTTP responses from the mock server
6. Verify that the client has done its work correctly:
   * verify that all the expected HTTP requests were received correctly at the mock server
   * verify that all HTTP responses from the mock server were handled correctly by the client
7. Cleanup the client and MockHTTPinC resources

In the next sections we'll explain how to use the MockHTTPinC API in each of this steps with some examples.


1. Initialize the client and the MockHTTPinC library
----------------------------------------------------

Initializing the client is out of scope for this document. Initialize MockHTTPinC by calling `mhInit()`. This function will return a baton representing a MockHTTP session. You'll have to pass to any MockHTTPinC API call you make later.
A MockHTTP session typically lives for the duration of one test scenario, and should not be reused.

```c
#include "MockHTTP.h"

MockHTTP *mh = mhInit();
```

If your client needs to know the hostname and port of the mock server during initialization, then proceed to the next step first.


2. Setup and run the mock server
--------------------------------

Next up is starting up the mock server and optional proxy. Here you'll see for the first time the fluent-style language we introduced in MockHTTPinC, using standard C macro's.

The macro language provides two benefits over a normal C API:
1. Named parameters
2. Optional parameters and defaults

For these macro's to work you'll have to wrap them in a block using one of the block opening statements `InitMockServers(mh)` ... `EndInit`, `Given(mh)` ... `EndGiven`, `Verify(mh)` ... `EndVerify` , where `mh` is the pointer holding the MockHTTP baton.

Example of setting up a mock server and a mock proxy:
```c
InitMockServers(mh)
  SetupServer(WithHTTP, WithPort(12345), InMainThread)
  SetupProxy(WithHTTP, WithPort(54321))
EndInit
```

Each MockHTTP session can manage one server and one proxy. Both server and proxy are event driven and can handle many TCP connections at the same time (tested with 1000+ connections) but are limited to one thread.



`SetupServer` and `SetupProxy` accept any of the following named parameters.


First, choose if the server and proxy should support HTTP or HTTPS:

* `WithHTTP`: Makes the server accept HTTP requests and send HTTP responses.

* `WithHTTPS`: Makes the server support HTTPS.



These are options that can be used with both HTTP/HTTPS server and proxy:

* `WithID(name)`: optional, give the server a name. Default server name is "server", default proxy name is "proxy". The server ID is not used at this time, but may be in the future when we'll support starting multiple servers per session.
    
* `WithPort(portnr)`: starts up the server on this port. If the port is not available, the server will increase the port number until it finds one that's available. Default port for a server is 30080, for a proxy its 38080.
   
* `WithMaxKeepAliveRequests(max)`: Defines the maxinum number of requests the server will receive on one TCP connection before it closes the connection. The mock server will set the Connection: close header on the last response. Default is 0: unlimited.

* `InMainThread`: Starts up a server or proxy in the main thread. This requires that you call mhRunServerLoop or mhRunServerLoopCompleteRequests regularly for the server to process events (accept inconing connections, receive and send data etc.), so it'll only work when testing a non-blocking client. This is the default.

* `InSeparateThread`: Starts up the server or proxy in a new thread. The new thread will have its own event loop which processes events continously, so this is the path to choose when testing a blocking client.



Options specific to HTTPS servers:

* `WithCertificateKeyFile(path)`: Path of the PEM-encoded private key file for the server certificate.
   
* `WithCertificateFiles(...)`: List of paths to the certificate file(s).
* `WithCertificateFileArray(paths)`: Array of paths to the certifcate file(s), terminated by a NULL path. The certificate files provided by either of these two named parameters will be sent by the server to the client during the SSL handshake. For a successful SSL handshake, you'll need to pass the server certificate and any intermediate and root CA certificate not trusted by the client.

* `WithCertificateFilesPrefix(path_prefix)`: This prefix will be prepended to any path provided to `WithCertificateFiles` or `WithCertificateFileArray`, enables you to use relative paths in these two parameters.

* `WithOptionalClientCertificate`: Setting this option will make the server ask for a client certificate during the SSL handshake, but the handshake will not fail if the client does not provide a certificate.
   
* `WithRequiredClientCertificate`:With this option the server will require that the client provides a client certificate for a successful handhake to happen.


With the next options the server can be configured to only advertize specific versions of SSL and/or TLS. If no parameters are expliclity provided, the server advertises SSLv3, TLSv1, TLSv1.1 and TLSv1.2 if supported by the OpenSSL library.

* `WithSSLv2`: Enable SSLv2.
* `WithSSLv3`: Enable SSLv3.
* `WithTLSv1`: Enable TLSv1.
* `WithTLSv11`: Enable TLSv1.1.
* `WithTLSv12`: Enable TLSv1.2.



3. Configure the client to use the mock server
----------------------------------------------

The actual port number on which the server and proxy are listening can be retrieved by calling respectively:
```c
server_port = mhServerPortNr(mh);
```
and
```c
proxy_port = mhProxyPortNr(mh);
```
These will return the port numbers of the default server and proxy. 

If you have given the server a non-default ID, use:
```c
server_port = mhServerByIDPortNr(mh, "my_server_name");
```



4. Define how the mock server should respond to HTTP requests it receives
-------------------------------------------------------------------------

When the server receives a request from the system under test, it will try to match this request with templates defined in the test definition. When a match is found, the server will take the response associated with the template and return it to the client. In the absence of a specific defined response, the server will return a default response.

The following code will instruct the server to respond with a 200 OK response with empty chunked response body, when a GET request arrives for resource /index.html with chunked response "1" containing a "Host" header with value "localhost".

```c
    Given(mh)
      GETRequest(URLEqualTo("/index.html"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", "localhost"))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven
```

All request templates and responses must be defined in a `Given(mh)` ... `EndGiven` block. You can have multiple of such blocks in your code, and they can be defined even after the test has started and the server has responded to requests.


Request matching
----------------

Defining a template starts with a call to `HTTPRequest`, or one of its variants. This macro take a non-empty set of rules as parameters. A request will match a template if all its rules match.

* `HTTPRequest(...)`: Matches any HTTP 1.0 and HTTP 1.1 request.

* `GETRequest(...)`, `POSTRequest(...)`, `HEADRequest(...)`: Matches any HTTP 1.0 and HTTP 1.1 request with a method equal to resp. GET, POST or HEAD. This is short for `HTTPRequest(MethodEqualTo("GET"), ...)`.


**Request line matching rules**

* `MethodEqualTo(exp)`: Matches if the request's method equals EXP.

* `URLEqualTo(exp)`: Matches if the request's url equals EXP (case sensitive).

* `URLNotEqualTo`: Matches if the request's url does not equal EXP (case sensitive).


**Header matching rules**

* `HeaderEqualTo(header, exp)`: Matches if header HEADER is set on the request and its value equals EXP (case sensitive).

* `HeaderNotEqualTo(header, exp)`: Matches if header HEADER is not set on the request or if its value DOES NOT equal EXP (case sensitive).

* `HeaderSet(header)`: Matches if header HEADER is set on the request.

* `HeaderNotSet(header)`: Matches if header HEADER is NOT set on the request.


**Request body matching rules**

* `BodyEqualTo(exp)`: Matches if the request's body equals EXP. This is after any decoding, e.g. if chunked encoding is used all chunks are combined to one body before matching.

* `RawBodyEqualTo(exp)`: Matches if the request's body, in its raw form, equals EXP. This is before decoding, e.g. with chunked headers included.

* `BodyChunksEqualTo(chunk1, chunk2, ...)`: Matches if the request's body is chunk encoded and the chunks exactly match parameters chunk1, chunk2 ... .

* `IncompleteBodyEqualTo(exp)`: Matches if the first part of the request's body equals EXP. This will make the server try to match partially received request bodies, where normally it waits until the full body is received.

TODO: remove these before release.
* `ChunkedBodyEqualTo(exp)`:
* `NotChunkedBodyEqualTo(exp)`:



**HTTPS specific matching rules**

* `ClientCertificateIsValid`:

* `ClientCertificateCNEqualTo`:

* `ConnectionSetup`:


Building a response
-------------------

* `DefaultResponse`:

* `Respond`:

* `WithCode`:

* `WithHeader`:

* `WithBody`:

* `WithChunkedBody`:

* `WithRequestBody`:

* `WithConnectionCloseHeader`:

* `WithRawData`:


Specifying non-response actions
-------------------------------

* `SetupSSLTunnel`:

* `SSLRenegotiate`:

* `CloseConnection`:



6. Verify that the client has done its work correctly
-----------------------------------------------------

    Verify(mh)
      assertTrue(VerifyAllExpectationsOk);
    EndVerify

    VerifyAllRequestsReceived

    VerifyAllRequestsReceivedInOrder

    VerifyAllExpectationsOk

    VerifyConnectionSetupOk

    VerifyStats

    ErrorMessage


7. Cleanup the client and MockHTTPinC resources
-----------------------------------------------

Cleanup the MockHTTPinC session by calling mhCleanup, pass it the baton returned by mhInit during initializatin. This will stop the mock server and free all memory it used, including all request template definitions, test statistics etc.

```c
mhCleanup(mh);
```

MockHTTPinC is not very conservative in its use of memory, it is assumed that the session is cleaned up after each test and a new empty session is created for the next test.
