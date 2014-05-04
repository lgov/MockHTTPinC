How to use MockHTTPinC ?
========================

The purpose of this library is to facilitate testing of clients that use 
HTTP to talk with a server.

A complete test scenario would look like this:

1. Initialize the client and the MockHTTPinC library

2. Setup and start the mock HTTP server

3. Define how the mock server should respond to HTTP requests it receives.

4. Configure the client to use the mock server

5. Use the client under test, which will:
   a. send HTTP requests to the mock server
   b. read and handle the HTTP responses from the mock server

6. Verify that the client has done its work correctly:
   a. verify that all the expected HTTP requests were received correctly at the mock server
   b. verify that all HTTP responses from the mock server were handled correctly by the client

7. Cleanup the client and MockHTTPinC resources


In the next sections we'll explain how to use the MockHTTPinC API in each of this steps with some examples.


1. Initialize the client and the MockHTTPinC library
----------------------------------------------------

Initializing the client is out of scope for this document. Initialize MockHTTPinC by calling mhInit(). This function will return a baton which you'll have to pass to any MockHTTPinC API call you make later.

    #include "MockHTTP.h"
    
    MockHTTP *mh = mhInit();

If your client needs to know the hostname and port of the mock server during initialization, then proceed to the next step first.


2. Setup and run the mock server
--------------------------------



 
    InitMockServers(tb->mh)
      SetupServer(WithHTTP, WithID("server"), WithPort(30080))
    EndInit
 
General options
   
    WithID: optional, give the server a name.
    
    WithPort
   
    WithMaxKeepAliveRequests
   
    InSeparateThread

    InMainThread


Options specific to HTTP servers
 
    WithHTTP: sets up a HTTP server.
 
 
Options specific to HTTPS servers
   
    WithHTTPS
   
    WithCertificateFilesPrefix
   
    WithCertificateKeyFile
        Path of the PEM-encoded private key file for the server certificate.
   
    WithCertificateFiles
   
    WithCertificateFileArray
   
    WithOptionalClientCertificate
   
    WithRequiredClientCertificate
   
    WithSSLv2: Enable SSLv2, availability and default setting depends on OpenSSL version
    WithSSLv3: Enable SSLv3, availability and default setting depends on OpenSSL version
    WithTLSv1: Enable TLSv1, availability and default setting depends on OpenSSL version
    WithTLSv11: Enable TLSv1.1, availability and default setting depends on OpenSSL version
    WithTLSv12: Enable TLSv1.2, availability and default setting depends on OpenSSL version
 
    WithSSLCipherSuite (not yet implemented)
   
    
Stubbing
--------
 
    Given(tb->mh)
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


Verifying

    Verify(mh)
      assertTrue(VerifyAllExpectationsOk);
    EndVerify

    VerifyAllRequestsReceived

    VerifyAllRequestsReceivedInOrder

    VerifyAllExpectationsOk

    VerifyConnectionSetupOk

    VerifyStats

    ErrorMessage

