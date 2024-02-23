import json
import random
import numpy as np
from collections import defaultdict

'''
    Total Queries: 360M
    Total Certs: 317,520,864
    Experiment setup: made a ZIPF distribution from the certificates using Shape parameter used: 1.2. 

'''

per_second_requests = 100000
total_time_in_seconds = 3600
total_queries = total_time_in_seconds * per_second_requests

f = open("mother_arr_shuffled.json")
mother_arr = json.load(f)
MOTHER_LEN = len(mother_arr)
print("tweet {}".format(MOTHER_LEN))


def Zipf(a: np.float64, min: np.uint64, max: np.uint64, size=None):
    """
    Generate Zipf-like random variables,
    but in inclusive [min...max] interval
    """
    if min == 0:
        raise ZeroDivisionError("")

    v = np.arange(min, max + 1)  # values to sample
    p = 1.0 / np.power(v, a)  # probabilities
    p /= np.sum(p)  # normalized
    v = v.astype(int)
    return np.random.choice(v, size=size, replace=True, p=p)


f = open("z_low.json")
z_low = json.load(f)
DISTRO_LEN = len(z_low)
print("done part 3")


# /home/protick/proxyrack/ocsp_simulation


def choose_from_distro(disro):
    rn = random.randint(0, DISTRO_LEN - 1)
    return disro[rn] - 1


modes = ['low', 'random']

root = {}

for mode in modes:
    nested = {}
    nested['distinct_serial_set'] = set()
    nested['distinct_nsec'] = set()
    root[mode] = nested


def process_and_return_ans(index, data):
    if index < len(mother_arr):
        val = mother_arr[index]
        data['distinct_serial_set'].add(index)
        data['distinct_nsec'].add(val)
    return (len(data['distinct_serial_set']), len(data['distinct_nsec']))


def find_distro():
    ans = []
    ind = 0

    for query in range(total_queries):
        try:
            ind += 1
            temp = [ind]
            random_index = random.randint(0, MOTHER_LEN - 1)
            z_low_index = choose_from_distro(z_low)

            temp.append(process_and_return_ans(index=random_index, data=root['random']))
            temp.append(process_and_return_ans(index=z_low_index, data=root['low']))

            if ind % 1000 == 0 or ind <= 10000:
                # print("yo {}/{} - {}".format(ind, total_queries, temp))
                file1 = open("anslist_v2.txt", "a")
                file1.write("{} {} {} {} {}\n".format(temp[0], temp[1][0], temp[1][1], temp[2][0], temp[2][1]))
            # ans.append(temp)
        except Exception as e:
            print(e)



def log_scale():
    print("loading")
    f = open("distro_final.json")
    d = json.load(f)
    print("loaded")

    init = 1
    ans = []
    while (init <= len(d)):
        ans.append((init, d[init - 1]))
        init = init * 2
    with open("log_data_2.json", "w") as ouf:
        json.dump(ans, fp=ouf)


def k_scale():
    print("loading")
    f = open("distro_final.json")
    d = json.load(f)
    print("loaded")

    init = 1000
    ans = [d[0]]
    while (init <= len(d)):
        ans.append(d[init - 1])
        init = init + 1000
        print(init, len(d))
    with open("k_scale.json", "w") as ouf:
        json.dump(ans, fp=ouf)


find_distro()