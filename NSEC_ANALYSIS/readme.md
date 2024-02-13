## Readme

* crl_processor.py
  * Downloads the CRLs for each CA
  * Parses the CRLs and sorts the revoked certificates for each CA and store them

* nsec_matcher.py
  * all the certificates collected from ctlogs are in stored in /net/data/ctlogs-serial-only/certs
  * this script analyzed the dataset, for each certificate, it finds out the corresponding nsec record (we already have the revoked certificate list with the crl_processor script)
  * We have a mapping from nsec records to the number of cerficate that ar mapped to it in nsec_map.json (/home/protick/proxyrack/ccadb/nsec_map.json)






