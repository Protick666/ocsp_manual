import json
import time
from multiprocessing.dummy import Pool as ThreadPool

f = open("data/ca_to_sorted_serials.json")
ca_to_sorted_serials = json.load(f)

f = open("data/skid_to_ca.json")
skid_to_ca = json.load(f)

from collections import defaultdict
nsec_to_count = defaultdict(lambda : 0)

ocsp_to_count = defaultdict(lambda : 0)
skid_to_ocsp_urls = defaultdict(lambda : set())
# skid_to_ocsp = defaultdict(lambda : 0)

def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files



def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans

skid = None

def find_nsec_identifier_bigger(sorted_serials, serial_in_int, ca):
    if len(sorted_serials) == 0:
        return "{}-0".format(ca)

    if serial_in_int < sorted_serials[0]:
        return "{}-0".format(ca)
    if serial_in_int > sorted_serials[-1]:
        return "{}-{}".format(ca, len(sorted_serials))

    i, j = 0, len(sorted_serials) - 1

    while i <= j:
        mid = (i + j) // 2

        if mid != 0:
            l_range = sorted_serials[mid - 1]
            r_range = sorted_serials[mid ]
            if l_range <=  serial_in_int <= r_range:
                return "{}-{}".format(ca, mid)
        if mid != len(sorted_serials) - 1:
            l_range = sorted_serials[mid]
            r_range = sorted_serials[mid + 1]
            if l_range <=  serial_in_int <= r_range:
                return "{}-{}".format(ca, mid + 1)

        if serial_in_int > sorted_serials[mid]:
            i = mid + 1
        else:
            j = mid - 1

    return "-1"

def find_nsec(serial_in_int):
    global fp_to_ca
    global ca_to_sorted_serials
    global skid

    if skid.upper() not in skid_to_ca:
        return "-1"
    ca = skid_to_ca[skid.upper()]
    if ca not in ca_to_sorted_serials:
        return "-1"
    sorted_serials = ca_to_sorted_serials[ca]
    return find_nsec_identifier_bigger(sorted_serials, serial_in_int, ca)

def analyze_chunk(chunk):
    global nsec_to_count
    init_time = time.time()
    for line_ in chunk:
        line = line_.strip()
        segments = line.split(",")
        serial_in_int = segments[-1].strip()
        serial_in_int = int(serial_in_int)
        nsec = find_nsec(serial_in_int=serial_in_int)
        nsec_to_count[nsec] += 1
    print("Ending chunk, taking {}".format((time.time() - init_time) / 60))


def analyze_chunk_v2(chunk):
    global nsec_to_count, ocsp_to_count, skid, skid_to_ocsp_urls
    init_time = time.time()

    ocsp_urls = set()

    for line_ in chunk:
        line = line_.strip()
        segments = line.split(",")
        ocsp_url = segments[0].strip()
        ocsp_to_count[ocsp_url] = ocsp_to_count[ocsp_url]  + 1
        ocsp_urls.add(ocsp_url)
    skid_to_ocsp_urls[skid].update(ocsp_urls)
    print("Ending chunk, taking {}".format((time.time() - init_time) / 60))


def process_file(file):
    global skid
    init_time = time.time()
    f = open(file)
    lines = f.readlines()
    line_chunks = chunks(lines, 10000)
    skid = file.split("/")[-1]
    pool = ThreadPool(50)
    results = pool.map(analyze_chunk, line_chunks)
    pool.close()
    pool.join()


def init_file_analyzer():
    global nsec_to_count, ocsp_to_count, skid_to_ocsp_urls
    files_to_read = get_files_from_dir("/net/data/ctlogs-serial-only/certs/")

    for file in files_to_read:
        process_file(file)

    with open("nsec_map.json.json", "w") as ouf:
        json.dump(nsec_to_count, fp=ouf)


init_file_analyzer()