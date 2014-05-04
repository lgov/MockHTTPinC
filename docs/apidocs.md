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

Initializing the client is out of scope for this document. Initialize MockHTTPinC by calling mhInit(). This function will return a baton representing a MockHTTP session. You'll have to pass to any MockHTTPinC API call you make later.
A MockHTTP session typically lives for the duration of one test scenario, and is not intended to be reused.

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

For these macro's to work you'll have to wrap them in a block using one of the block opening statements InitMockServers(mh) ... EndInit, Given(mh) ... EndGiven, Verify(mh) ... EndVerify , where mh is the pointer holding the MockHTTP baton.

Example of setting up a mock server and a mock proxy:

    InitMockServers(mh)
      SetupServer(WithHTTP, WithPort(12345), InMainThread)
      SetupProxy(WithHTTP, WithPort(54321))
    EndInit


Each MockHTTP session can manage one server and one proxy at this time. Both server and proxy are event driven and can handle many TCP connections at the same time (tested with 1000+ connections) but are limited to one thread. 

Both server and proxy can be started in the main thread, or each in a separate thread. 
Running them in the main thread  only works with a non-blocking client, as it require that the event handling loop is started from time to time. Blocking clients can only be tested by starting server and proxy in a separate thread.


SetupServer and SetupProxy accept any of the following named parameters:


First, choose if the server and proxy should support HTTP or HTTPS:

* `WithHTTP`: Makes the server accept HTTP requests and send HTTP responses.

* `WithHTTPS`: Makes the server support HTTPS.


These are options that can be used with both HTTP/HTTPS server and proxy:

* `WithID(name)`: optional, give the server a name. Default server name is "server", default proxy name is "proxy". The server ID is not used at this time, but may be in the future when we'll support starting
    
* `WithPort(portnr)`: starts up the server on this port. If the port is not available, the server will increase the port number until it finds one that's available. Default port for a server is 30080, for a proxy it's 38080.
   
* `WithMaxKeepAliveRequests(max)`: Defines the maxinum number of requests the server will receive on one TCP connection before it closes the connection. The mock server will set the Connection: close header on the last response. Default is 0: unlimited.

* `InMainThread`: Starts up a server or proxy in the main thread. This requires that you call mhRunServerLoop or mhRunServerLoopCompleteRequests regularly for the server to process events (accept inconing connections, receive and send data etc.). This is the default.

* `InSeparateThread`: Starts up the server or proxy in a new thread. The new thread will have its own event loop which processes events continously.


Options specific to HTTPS servers

* `WithCertificateFilesPrefix(path_prefix)`:
   
* `WithCertificateKeyFile(path)`:
        Path of the PEM-encoded private key file for the server certificate.
   
* `WithCertificateFiles(...)`:
   
* `WithCertificateFileArray(files)`:
   
* `WithOptionalClientCertificate`:
   
* `WithRequiredClientCertificate`:
   
* `WithSSLv2`: Enable SSLv2, availability and default setting depends on OpenSSL version
* `WithSSLv3`: Enable SSLv3, availability and default setting depends on OpenSSL version
* `WithTLSv1`: Enable TLSv1, availability and default setting depends on OpenSSL version
* `WithTLSv11`: Enable TLSv1.1, availability and default setting depends on OpenSSL version
* `WithTLSv12`: Enable TLSv1.2, availability and default setting depends on OpenSSL version
 
* `WithSSLCipherSuite` (_not yet implemented_)


2. Configure the client to use the mock server
----------------------------------------------

The actual port number on which the server and proxy are listening can be retrieved by calling respectively:

    server_port = mhServerPortNr(mh);
    
    proxy_port = mhProxyPortNr(mh);
    
This will return the port number of the default server and proxy. If you have given the server a non-default ID, use:

    server_port = mhServerByIDPortNr(mh, "my_server_name");


3. Define how the mock server should respond to HTTP requests it receives.
--------------------------------------------------------------------------
 
    Given(mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven


Match requests

      GETRequest, POSTRequest, HEADRequest, HTTPRequest(method,...)

      URLEqualTo

      BodyEqualTo

      RawBodyEqualTo

      HeaderEqualTo

      HeaderNotEqualTo

      HeaderSet

      HeaderNotSet

      NotChunkedBodyEqualTo

      ChunkedBodyEqualTo

      ChunkedBodyChunksEqualTo

      IncompleteBodyEqualTo

      ClientCertificateIsValid

      ClientCertificateCNEqualTo

      ConnectionSetup

Specifying response

      DefaultResponse

      Respond

      WithCode

      WithHeader

      WithBody

      WithChunkedBody

      WithRequestBody

      WithConnectionCloseHeader

      WithRawData


Specifying actions

      SetupSSLTunnel

      SSLRenegotiate

      CloseConnection

6. Verify that the client has done its work correctly:
------------------------------------------------------

    Verify(mh)
      assertTrue(VerifyAllExpectationsOk);
    EndVerify

    VerifyAllRequestsReceived

    VerifyAllRequestsReceivedInOrder

    VerifyAllExpectationsOk

    VerifyConnectionSetupOk

    VerifyStats

    ErrorMessage

