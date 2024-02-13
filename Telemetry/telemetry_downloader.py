from datetime import datetime, timedelta

import requests
import json

today = datetime.today() - timedelta(1)

dump_directory = "telemetry_ocsp_response/"

from pathlib import Path
Path(dump_directory).mkdir(parents=True, exist_ok=True)

def generate_dates(start, end):
    if type(start) == type("s"):
        start = datetime.strptime(start, "%Y-%m-%d")
    if type(end) == type("s"):
        end = datetime.strptime(end, "%Y-%m-%d")

    date_list = []

    current_date = start
    while current_date <= end:
        date_list.append(current_date.strftime("%Y%m%d"))
        current_date += timedelta(days=1)

    concatenated_dates = "%2C".join(date_list)
    return concatenated_dates

def can_connect(version, target_date):
    s = "https://aggregates.telemetry.mozilla.org/aggregates_by/submission_date/channels/nightly/?version={}&metric=SSL_OCSP_STAPLING&application=Firefox&dates={}".format(
        version, target_date.strftime("%Y%m%d"))
    r = requests.get(s)

    return r.status_code == 200

def get_starting_date(version):
    i, j = 0, 730

    while i <= j:
        mid = (i + j) // 2
        target_date = today - timedelta(days=mid)

        if can_connect(version, target_date):
            if mid == j:
                return mid
            if can_connect(version, target_date - timedelta(days=1)):
                i = mid + 1
            else:
                return mid
        else:
                j = mid - 1
    return None

def get_json(version, starting, ending):
    dates = generate_dates(starting, ending)
    s = "https://aggregates.telemetry.mozilla.org/aggregates_by/submission_date/channels/nightly/?version={}&metric=CERT_VALIDATION_HTTP_REQUEST_RESULT&application=Firefox&dates={}".format(
        version, dates)
    r = requests.get(s)
    return json.loads(r.content.decode())

def process(version):
    delta_of_starting_date = get_starting_date(version)
    mid_way = delta_of_starting_date // 3

    json_1 = get_json(version, today - timedelta(days=mid_way), today)
    json_2 = get_json(version, today - timedelta(days=mid_way * 2), today - timedelta(days=mid_way + 1))
    json_3 = get_json(version, today - timedelta(days=delta_of_starting_date), today - timedelta(days=mid_way * 2 + 1))

    return json_1, json_2, json_3, delta_of_starting_date


for v in range(60, 110):
    try:
        a, b, c, delta = process(v)
        a['data'] = a['data'] + b['data'] + c['data']
        s = set()
        for e in a['data']:
            s.add(e['date'])
        print(v, delta, len(s))

        with open("{}/{}.json".format(dump_directory, v), "w") as ouf:
            json.dump(a, fp=ouf)

    except Exception as e:
        print(v, str(e))