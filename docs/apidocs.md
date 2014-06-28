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

* `GETRequest(...)`, `POSTRequest(...)`, `HEADRequest(...)`, 
  `PUTRequest(...)`, `DELETERequest(...)`, `OPTIONSRequest(...)`: Matches any HTTP 1.0 and HTTP 1.1 request with a method equal to resp. GET, POST, HEAD, PUT, DELETE or OPTIONS. This is short for `HTTPRequest(MethodEqualTo("GET"), ...)`.


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

* `ChunkedBodyEqualTo(exp)`: Matches if the request's body is chunk encoded and it equals EXP, after decoding.

* `NotChunkedBodyEqualTo(exp)`: Matches if the request's body is NOT chunk encodeded and it equals EXP.


Connection setup matching
-------------------------

Some specific checks need to happen on connection level, not per request. This can be achieved with the `ConnectionSetup` macro. Its use is similar to the `HTTPRequest` macro.

Example:
```c
Given(mh)
  ConnectionSetup(ClientCertificateIsValid,
                  ClientCertificateCNEqualTo("Serf Client"))
EndGiven
```
It's clear from the example that the ConnectionSetup template does not accept a response, its only purpose is to validate certain connection-level conditions. Note that the connection is not aborted when this validation fails. It's only after the test is run, in a call to  `VerifyConnectionSetupOk` that the given conditions are validated.

**HTTPS specific matching rules**

* `ClientCertificateIsValid`: Matches if the client certificate provided during SSL handshake by the client is valid: the issuer is in the provided list of trusted certificates (see `WithCertificateFiles`).

* `ClientCertificateCNEqualTo(exp)`: Matches if the Common Name of the client certificate matches EXP (case sensitive).


Building a response
-------------------

When the mock server matches an incoming request with one of the templates, it will return the response message defined for the request template. The mock server will return a default "200 OK" response if a request template matched but no response was defined. When the mock server receives a request that it can't match, it will return a "500 Internal Server Error" message.

Defining a response starts with a call to `Respond`, or `DefaultResponse`. This macro take a non-empty set of parameters. Each parameter is a builder method, which configures one aspect of the response. The builder functions are evaluated late, during response construction.

* `DefaultResponse(...)`: Build a response and set it as the default for matched requests.

* `Respond(...)`: Build a response, attach it to the most recently defined request template (see `HTTPRequest`)

**Response parameters**

* `WithCode(code)`: Sets the HTTP response code. The default code of a response to a matched request is 200 OK.

* `WithHeader(header, value)`: Sets the header HEADER with value VALUE on the response.

* `WithRequestHeader(header)`: If set, copy header HEADER and its value to the response.

* `WithConnectionCloseHeader`: Adds a "Connection: close" header to the response and makes the mock server close the connection after sending the response.

* `WithBody(body)`: Sets the response body to string BODY. This will automatically add a Content-Length header with BODY length as value.

* `WithChunkedBody(...)`: Sets the response body as a list of chunks e.g. WithChunkedBody("chunk1", "chunk2"). This will automatically add a "Transfer-Encoding: chunked" header to the response.

* `WithRequestBody`: Constructs the response body by copying the body of the request.

* `WithBodyRepeatedPattern(pattern, repeat)`: Constructs the response body by repeating the string PATTERN REPEAT times. This is an easy way to create very large response bodies.

* `WithRawData(data, len)`: Constructs the response from raw data of length LEN. DATA  should be a complete well formed HTTP/1.x response, including status line, headers and/or body.


Specifying non-response actions
-------------------------------
Each request template can have one optional response and one optional extra action. The latter instructs the mock server to execute a certain action after sending the response to the client.

* `SSLRenegotiate`: Instructs the HTTPS mock server to initiate a SSL renegotiation. The MockHTTP session will go to an error state when the renegotiation fails.

* `CloseConnection`: Instructs the mock server to close the connection.


Other methods
-------------

* `OnConditionThat(cond,builder)`: This method can be used to wrap a request matching rule or a response builder method, and only apply to rule or method when COND evaluates to  true`.

Example:
```c
InitMockServers(mh)
  SetupServer(WithHTTPS, WithID("server"), WithPort(30080),
              WithCertificateFilesPrefix("test/certs")),
              WithCertificateKeyFile(keyfile),
              WithCertificateKeyPassPhrase("test"),
              WithCertificateFileArray(certfiles),
              OnConditionThat(check_cert == test_clientcert_mandatory, WithRequiredClientCertificate),
              OnConditionThat(check_cert == test_clientcert_optional, WithOptionalClientCertificate))
EndInit
```
The example sets up the mock server with either option `WithRequiredClientCertificate` or `WithOptionalClientCertificate` depending on the value of variable `check_cert`.


Setting up a proxy
------------------

While proxying HTTP requests is not supported at this time, the MockHTTPinC library has built-in SSL tunnel support. The support is not automatic, but can be configured using a response action:

* `SetupSSLTunnel`: Instructs the HTTP mock proxy server to set up an SSL tunnel to the server.

Example of setting up a mock server and a mock proxy:
```c
// Setup the proxy
InitMockServers(mh)
  SetupProxy(WithHTTP, WithPort(54321))
EndInit

Given(mh)
  // Setup an SSL tunnel in response to a CONNECT request received at the proxy.
  RequestsReceivedByProxy
    HTTPRequest(MethodEqualTo("CONNECT"))
      Respond(WithCode(200), WithChunkedBody(""))
      SetupSSLTunnel
EndGiven
```

You'll notice the new statement `RequestsReceivedByProxy`. This statement specifies that all following request templates are matched to requests arriving at the proxy, not at the server. By default request templates are matched at the server end only, this can be made explicit using the `RequestsReceivedByServer` statement.


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
