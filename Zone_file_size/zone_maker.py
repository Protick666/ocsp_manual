# from ccadb.zeek_nsec_amalgum import get_ca_to_sorted_serials
import json



algo_to_keys = {
        "RSA_1024": ["Kexample.com.+005+20932.key", "Kexample.com.+005+21100.key"],
        "RSA_2048": ["Kexample.com.+005+26088.key", "Kexample.com.+005+44056.key"],
        "ECDSA_384": ["Kexample.com.+014+41189.key", "Kexample.com.+014+55391.key"],
        "ECDSA_256": ["Kexample.com.+013+41075.key", "Kexample.com.+013+12812.key"]
    }

def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files

def sanitize_ca(ca):
    ca = ca.replace(" ", "-")
    ca = ca.replace("/", "-")
    return ca

def change_zone_file(lst, ca):
    # $INCLUDE Kexample.com.+013+48233.key

    source_file = "zones/zone_source"

    lines_to_write = []
    substring_to_look_for = '; Other TXT records'

    with open(source_file) as f1:
        for line in f1:
            lines_to_write.append(line)
            if substring_to_look_for in line:
                for i in lst:
                    lines_to_write.append("{} IN TXT \"revoke\"\n".format(i))

    # $INCLUDE Kexample.com.+013+48233.key
    for algo in algo_to_keys:
        temp_lines = lines_to_write.copy()
        for key in algo_to_keys[algo]:
            temp_lines.append("$INCLUDE {}\n".format(key))

        dest_dir = "zones_v4/{}/{}/".format(algo, sanitize_ca(ca))
        dest_file = "{}example.com.zone".format(dest_dir)
        from pathlib import Path
        Path(dest_dir).mkdir(parents=True, exist_ok=True)

        with open(dest_file, "w") as f1:
            for line in temp_lines:
                f1.write(line)

def make_zone_files():
    ca_to_sorted_serials = get_ca_to_sorted_serials()
    for ca in ca_to_sorted_serials:
        change_zone_file(ca_to_sorted_serials[ca], ca)

import subprocess

def execute_cmd(command):
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    # time.sleep(5)
    return output, error


def sign_zone_file(file):

    try:
        cmd = "dnssec-signzone  -N INCREMENT -o example.com -t {}".format(file)
        output, error = execute_cmd(cmd)
        print("Done with {} --- {}:{}".format(file, output, error))
    except Exception as e:
        print("Error with {} --- {}".format(file, e))

    return file, output

def sign_zone_files():
    # dnssec-signzone  -N INCREMENT -o example.com -t twat/example.com.zone
    files = get_leaf_files("zones_v4")

    file_to_output = {}

    from multiprocessing import Pool

    with Pool() as pool:
        for result in pool.imap_unordered(sign_zone_file, files):
            f_name, output = result
            file_to_output[f_name] = output

    import json

    with open("mother_meta.json", "w") as ouf:
        json.dump(file_to_output, fp=ouf)


# sign_zone_files
# sign_zone_files()

def get_file_sizes():
    import os
    from collections import defaultdict
    files = get_leaf_files("zones_v4")
    ca_to_algo_to_size_in_mb = defaultdict(lambda : defaultdict(lambda : -1))
    for file in files:
        if '.signed' not in file:
            continue
        segments = file.split("/")
        ca = segments[-2]
        algo = segments[-3]
        ca_to_algo_to_size_in_mb[ca][algo] = os.path.getsize(file) * .000001

    import json
    with open("dnssec_file_size.json", "w") as ouf:
        json.dump(ca_to_algo_to_size_in_mb, fp=ouf)


