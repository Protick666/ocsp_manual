## Readme

* runner.py
  * Runs firefox with selenium and loads the top-100 K Tranco domains
  * Download the correct gecko driver for your os and place it in the drivers folder
  * Captures the network pcaps and saves them
    * The dataset resides in /net/data/dns-ttl/ocsp_multi_ec2 in Pharah in 50 sized chunks
* zeekify.py
  * Turns the pcaps in zeek files. Refer to https://docs.zeek.org/en/master/index.html for more details
  * The zeek files are here: /net/data/dns-ttl/pcap/zeek_logs/ec2
* analyzer.py
  * Analyzes the zeek files and finds out the following information for each TLS connection
    * dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_start, ocsp_dns_end, ocsp_http_start, ocsp_http_end, server_name, ocsp_host 
    * The dataset is in /home/protick/proxyrack/ocsp_simulation/simulation_results_multi_ec2
* perform_analyzer.py
  * The coalesce directory is in /home/protick/proxyrack/ocsp_simulation/coalese
  * analyze_info function
    * calculates the OCSP http reponse time and OCSP dns time for all the TLS connections 
  * analyze_ec2_mult
    * caluculates the vanilla and proactive performance gains for all TLS connections (refer to the paper for more details)
  * implement the is_cdn function:
    * match with already existing list of ocsp responders and their CDN usage google sheet. if the entry is not there, handle it manually. I individually looked at the OCSP responders and found out their CDN usage by looking at their infrastructure owner (getting the ownder of the IP address) and looking at the DNS resolution chain
* zipf_cache_simulation.py
  * finds zipf caching benefits for NSSEC caching
  * I will fill in more details

