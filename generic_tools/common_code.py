import redis
import json

def get_ocsp_hosts(redis_host):
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    return [item.decode() for item in ocsp_urls_set]


def get_asns():
    f = open('../misc_data/luminati_data/successful_asns.json')
    asn_list = json.load(f)
    return asn_list
