from csv import reader
import json
from multiprocessing.dummy import Pool as ThreadPool
from collections import defaultdict


def read_csv():
    ca_crls = defaultdict(lambda : set())
    with open('data/AllCertificateRecordsReport_fresh.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        index = 0
        for row in csv_reader:
            if index == 0:
                index += 1
                continue

            ca_owner = row[0]
            ca_sub_owner = row[41]
            full_url = row[42]
            partioned_urls = row[43]

            ca_crls[ca_owner].add(full_url)
            try:
                urls = json.loads(partioned_urls)
                for url in urls:
                    ca_crls[ca_owner].add(url)
            except:
                pass

    return ca_crls

# a = read_csv()
# a = 1


def download_crl(crl_tuple):
    import socket
    import urllib.request
    import random
    try:
        from pathlib import Path
        ca, crl = crl_tuple
        socket.setdefaulttimeout(200)
        dump_directory = "data/crls/{}/".format(ca)
        Path(dump_directory).mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(crl, "{}{}".format(dump_directory, random.randint(1, 1000000000000000)))
        print(crl_tuple)
    except Exception as e:
        pass

def download_files():
    ca_crls = read_csv()

    crl_tuples = []
    for ca in ca_crls:
        for crl in ca_crls[ca]:
            crl_tuples.append((ca, crl))

    pool = ThreadPool(50)
    results = pool.map(download_crl, crl_tuples)
    pool.close()
    pool.join()

    return ca_crls

def open_crl():
    import OpenSSL
    from OpenSSL import crypto

    with open('data/crls/8.crl', "rb") as in_file:
        crl_obj = crypto.load_crl(crypto.FILETYPE_ASN1, in_file.read())
        pem_crl_data = crypto.dump_crl(crypto.FILETYPE_PEM, crl_obj)
        crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, pem_crl_data)

        revoked_objects = crl_object.get_revoked()

        for rvk in revoked_objects:
            print(rvk.get_serial().decode())


    revoked_objects = crl_object.get_revoked()
    a = 1


def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files
def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files

serial_numbers = set()
def analyze_revoked_lists(crl):
    global serial_numbers
    import OpenSSL
    from OpenSSL import crypto

    with open(crl, "rb") as in_file:
        try:
            crl_obj = crypto.load_crl(crypto.FILETYPE_ASN1, in_file.read())
            pem_crl_data = crypto.dump_crl(crypto.FILETYPE_PEM, crl_obj)
            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, pem_crl_data)
            print("xxx", crl_object.to_cryptography().last_update, crl_object.to_cryptography().next_update)
            revoked_objects = crl_object.get_revoked()

            for rvk in revoked_objects:
                serial_numbers.add(rvk.get_serial().decode())
            a = 1
        except Exception as e:
            print("mama")
            pass
    print(crl)


def proc_crls(ca):
    crl_files = get_files_from_dir("data/crls/{}/".format(ca))

    if len(crl_files) == 0:
        return

    pool = ThreadPool(50)
    results = pool.map(analyze_revoked_lists, crl_files)
    pool.close()
    pool.join()

    global serial_numbers
    serial_number_list = list(serial_numbers)
    serial_number_list.sort()

    from pathlib import Path
    dump_directory = "data/serials/{}/".format(ca)
    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    with open("{}revoked_serials_sorted.json".format(dump_directory), "w") as ouf:
        json.dump(serial_number_list, fp=ouf)

    serial_numbers = set()

# proc_crls(ca='Microsoft Corporation')
# a = 1

def process_init(ca_crl):
    for ca in ca_crl:
        proc_crls(ca)
        print("Done with {}".format(ca))

def sanitychecker():
    import json
    files = get_leaf_files("data/serials/")
    ca_names = []
    arr = []
    for file in files:
        ca_name = file.split("/")[2]
        ca_name = ca_name.strip()
        ca_names.append(ca_name.upper())

    f = open("data/fp_to_ca.json")
    d = json.load(f)
    ca_names_temp = []
    for key in d:
        ca_names_temp.append(d[key].upper())

    for e in ca_names_temp:
        if e not in ca_names:
            print("BAD", e)
        else:
            print("GOOD", e)


def read_nums():
    import json
    files = get_leaf_files("data/serials/")
    arr = []
    for file in files:
        try:
            ca_name = file.split("/")[2]
            f = open(file)
            d = json.load(f)
            if len(d) == 0:
                continue
            arr.append((int(len(d)), ca_name))
            #print(ca_name, len(d))
        except:
            pass

    arr.sort(reverse=True)
    for e in arr:
        print(e)

def get_fp_to_ca_name():
    fp_to_ca = {}
    with open('data/AllCertificateRecordsReport_fresh.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        # 0 CA owner, 41 Subordinate CA Owner, 42 full crl issued by this CA, Json array of partitoned CRLs
        index = 0
        for row in csv_reader:
            if index == 0:
                index += 1
                continue

            ca_owner = row[0]
            ca_sub_owner = row[41]
            fingerprint = row[7]
            fingerprint = fingerprint.upper()

            if "/" in ca_owner:
                ca_owner = ca_owner.split("/")[0]

            ca_owner = ca_owner.strip()
            ca_owner = ca_owner.upper()
            fp_to_ca[fingerprint] = ca_owner

    a = 1
    with open("data/fp_to_ca.json", "w") as ouf:
        json.dump(fp_to_ca, fp=ouf)

    return fp_to_ca

f = open("data/ca_to_sorted_serials.json")
d = json.load(f)
a = 1

ca_to_sorted_serials = {}
def process_sorted(file):
    global ca_to_sorted_serials
    arr = []
    try:
        ca_name = file.split("/")[2]
        ca_name = ca_name.strip()
        ca_name = ca_name.upper()
        f = open(file)
        d = json.load(f)

        for e in d:
            try:
                arr.append(int(e, 16))
            except:
                pass
        arr.sort()
        ca_to_sorted_serials[ca_name] = arr
        # print(ca_name, len(d))
    except:
        pass


def get_ca_to_sorted_serials():

    import json
    global ca_to_sorted_serials
    files = get_leaf_files("data/serials/")
    pool = ThreadPool(50)
    results = pool.map(process_sorted, files)
    pool.close()
    pool.join()
    with open("data/ca_to_sorted_serials.json", "w") as ouf:
        json.dump(ca_to_sorted_serials, fp=ouf)

    return ca_to_sorted_serials

def intro():
    ca_crl = download_files()
    process_init(ca_crl)
    ca_to_sorted_serials = get_ca_to_sorted_serials()


intro()

