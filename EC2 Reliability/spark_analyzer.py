import pyspark
from pyspark import SparkContext, SparkConf
import json
import json

def reader(d):
    try:
        return json.loads(d)
    except:
        return

def to_list(a):
    return [a]


def append(a, b):
    a.append(b)
    return a


def extend(a, b):
    a.extend(b)
    return a

def get_chunks(lst):
    i, j = 0, 0
    ans_lst = []
    while i < len(lst):
        j = i + 1
        while(j < len(lst)):
            current_timestamp = lst[j][1]
            prev = lst[j - 1][1]
            # todo why 6
            if abs(current_timestamp - prev) > 4.2 * 60 * 60:
                break
            else:
                j += 1
        ans_lst.append(lst[i: j])
        i = j

    return ans_lst

def extract(lst):
    return [e[0] for e in lst]


IS_LOCAL = False
MODE = "Latency"
# MODE = "Error"
from collections import defaultdict

conf = SparkConf() \
        .setAppName("validation-details")

sc = SparkContext(conf=conf)

if not IS_LOCAL:
    path = "hdfs:///user/tijay/ocsp/nononce/*/*/*/scans.txt"
else:
    path = "nonounce_scan/*/*/*/scans.txt"

# TODO case
net_error = {
    "recv failure": "data_recv_failure",
    "not resolve host": "host_resolution",
    "resolving timed out": "host_resolution",
    "timed out": "time_out",
    "time-out": "time_out",
    "failed to connect": "connection_failure",
    "empty reply": "empty_reply",
    "unable to get local issuer certificate": "unable_to_get_issuer_certificate"
  }

def find_error(e):
    try:
        element = e['response']
        if element['http_code'] == 200:
            return "200"
        else:
            if element['err_reason'] != '':
                # print(element['err_reason'])
                for key in net_error:
                    temp_str = element['err_reason']
                    temp_str = temp_str.lower()
                    if key in temp_str:
                        return net_error[key]
                return 'net_error_unknown'
            elif element['http_code'] != 200:
                return 'non_200_{}'.format(element['http_code'])
            else:
                return 'undefined'
    except:
        return 'undefined'



def find_latency_v2(e):
    try:
        element = e['response']
        if element['http_code'] != 200:
            return "-1"
        return (element['namelookup_time'], element['total_time'])
    except:
        return '-1'

# url ->
from datetime import datetime


def time_trans(time_str):
    dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    dt = dt.replace(minute=0, second=0, microsecond=0)
    return int(dt.timestamp())

def get_year(time_str):
    dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    dt = dt.replace(minute=0, second=0, microsecond=0)
    return int(dt.year)


def fill_err(counter_long, counter_short, ln, code):

    if ln <= 12:
        counter_short[code] += 1
    else:
        counter_long[code] += 1



def flatten_lst(lst):
    a = [e[0] for e in lst]
    return a


rdd = sc.textFile(path).map(reader).filter(lambda v: v is not None)

rdd = rdd.filter(lambda v: 'response' in v and 'http_code' in v['response'] and len(v["vantage_point"]) > 0)

rdd = rdd.filter(lambda v: 'pki.goog' not in v['ocsp_url'])

if MODE == "Latency":
    rdd = rdd.map(lambda v: ((v['vantage_point'], v['ocsp_url'], get_year(v['timestamp'])), (find_latency_v2(v)))).combineByKey(to_list, append, extend)
else:
    rdd = rdd.map(lambda v: ((v['vantage_point'], v['ocsp_url'], get_year(v['timestamp'])), (find_error(v)))).combineByKey(to_list, append, extend)

import random

if not IS_LOCAL:
    rdd.map(json.dumps).saveAsTextFile("hdfs:///user/protick/url_v28")
else:
    rdd.map(json.dumps).saveAsTextFile("m{}".format("pro"))

