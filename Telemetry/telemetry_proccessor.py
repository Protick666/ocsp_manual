import json
from collections import defaultdict
import numpy as np
# cdf_multiple([tls_time, ocsp_req_time], ['TLS handshake time', 'OCSP response time'], 'OCSP response time vs TLS handshsake time', 'Milliseconds')

def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


def datify(element):
    return "{}-{}-{}".format(element[0: 4], element[4: 6], element[6: 8])


def get_date_ticks(x, interval=30):
    ticks = []
    labels = []

    for index in range(len(x)):
        element = x[index]
        if index % interval == 0:
            labels.append(datify(element))
            ticks.append(index + 1)

    return ticks, labels


def process_generic(bucket_to_index, data_path):

    '''
        TODO internal_error ache, but excluded in the analysis, look at code why an internal error might result
    '''
    # date_to_key_to_list

    date_to_key_to_count = defaultdict(lambda: defaultdict(lambda: 0))

    # bucket_to_index = {
    #     "Timed out": 0,
    #     "Successful": 1,
    #     "Failed": 2,
    # }

    bucket_to_count = defaultdict(lambda: 0)
    total = 0
    all_samples = 0

    files = get_leaf_files("data/telemetry/{}".format(data_path))


    for file in files:
        f = open(file)
        d = json.load(f)
        a = 1
        a = 1
        for e in d['data']:
            for element in e['histogram']:
                total += element
            semi_total = 0
            for key in bucket_to_index:
                bucket_to_count[key] += e['histogram'][bucket_to_index[key]]
                semi_total += e['histogram'][bucket_to_index[key]]
                date_to_key_to_count[e['date']][key] += e['histogram'][bucket_to_index[key]]
                all_samples += e['histogram'][bucket_to_index[key]]

    a = 1
    semi_total = 0
    labels = []
    values = []

    for key in bucket_to_count:
        labels.append(key)
        values.append(bucket_to_count[key])
        semi_total += bucket_to_count[key]

    for key in bucket_to_count:
        bucket_to_count[key] = (bucket_to_count[key] / semi_total) * 100

    return bucket_to_count, date_to_key_to_count, all_samples




def truncate_last_element(list_of_lists):
    ans = []
    for l in list_of_lists:
        ans.append(l[: -1])
    return ans

def get_flattened_arr(counter):
    arr = []
    tot = 0
    for val in counter:
        arr.append((val, counter[val]))
        tot += counter[val]
    arr.sort()
    return arr, tot


def find_percentile(counter, frac):
    arr, tot = get_flattened_arr(counter)
    temp = 0
    for element in arr:
        temp += element[1]
        if temp / tot >= frac:
            return element[0]

def process_http_result():

    bucket_to_index = {
        "Timed out": 0,
        "Successful": 1,
        "Failed": 2,
    }

    bucket_to_count, date_to_key_to_count, all_samples = process_generic(bucket_to_index, 'telemetry_ocsp_response')
    # multi_line_drawer_day_wise(bucket_to_index=bucket_to_index, date_to_key_to_count=date_to_key_to_count)



def process_stapled_result():

    bucket_to_index = {
        "stapled_good": 1,
        "not_present": 2,
        "stapled_expired": 3,
        "stapled_other_error": 4,
    }

    # bucket_to_index = {
    #     "canceled": 0,
    #     "ok": 1,
    #     "failed": 2,
    #     "internal-error": 3,
    # }

    bucket_to_count, date_to_key_to_count, all_samples = process_generic(bucket_to_index, 'telemetry_stapling')
    # multi_line_drawer_day_wise(bucket_to_index=bucket_to_index, date_to_key_to_count=date_to_key_to_count)


def curtail_keys(d):
    t = {}
    for key in d:
        if key <= 1000:
            t[key] = d[key]
    return t