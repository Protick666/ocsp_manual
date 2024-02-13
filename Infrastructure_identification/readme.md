## Readme

* This spreadsheet has the complete information about the OCSP responders that use CDNs/Third party infrastructure:
  * https://docs.google.com/spreadsheets/d/1-uPaKf16Wn0qMQJDTqMs7Lyr6NSdT_XQZWlyqJE8U0s/edit#gid=0
    * The columns: CDN name, has nonce, is non-existent response signed, is delegated response, graph pattern
      * graph pattern: diff means nonce and w/o nonce response times are clearly separated. same means they overlap


* This spreadsheet has the complete information about the CAs CDN usage for maintaining their CRLs:
  * https://docs.google.com/spreadsheets/d/1k5ymG71T1VI0GdJvW2HYdbVjGKyEaE6a5yZIiqIZJ5M/edit#gid=0
    * The columns: CA, CRL, Infrastructure owner organization, uses CDN?
      

* request_sender.py
  * This script identifies where the OCSP responder is served from (section 3 of paper)
    * Sends 50 consequtive requests using nonce, no-nonce and random certificate serial numbers and saves the response times
    * This spreadsheet visualizes the graphs for different CDNs:
      * https://docs.google.com/spreadsheets/d/1xLUFaBoFcOfD9lwnZBdACEEi2FcZ6GiB_kC2dMMp_jY/edit#gid=0


* data/origin.json
  * This file contains following information about all the OCSP responders
    * org: the organization that owns the OCSP infrastructure
    * delegation: if the response is delegated
    * Type-1: CA owns the infra, Type-3: CA relies on CDNs, Type-2: CA relies on third party 






