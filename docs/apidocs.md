How to use MockHTTPinC ?
========================

(work in progress)


Setting up and running the mock server(s)
-----------------------------------------
 
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

