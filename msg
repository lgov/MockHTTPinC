Add RawBodyEqualTo.
This required some refactoring because we didn't actually keep the raw data.

* _mhRequestInit: Rename to _mhInitRequest, ove to MockHTTP_server.c
* keep body and chunks in an array of iovec, update all code to follow this
  change
* mhMatchRawBodyEqualTo, raw_body_matcher,
  RawBodyEqualTo: New, allow matching of body as it was received by the 
                  server + add some new tests.
