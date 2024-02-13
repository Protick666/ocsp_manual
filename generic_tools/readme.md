## Readme

* Code: serial_crawler.py
  * Crawl certificates using the certstream module
  * Stores upto 1000 certificates for each OCSP url in redis
    * The **ocsp_urls** holds the list of ocsp urls
    * The **day_index-ocsp_url** key holds the list of certificates corresponding to the ocsp_url. 
      * Each entry holds the following tuple (serial, finger_print, akid)

