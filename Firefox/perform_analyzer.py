from collections import defaultdict

def analyze_info():
    vantages = ["mumbai", "ohio", "paris", "sydney", "sao-paolo"]

    ocsp_arr = defaultdict(lambda : defaultdict(lambda: list()))
    dns_arr = defaultdict(lambda: defaultdict(lambda: list()))
    print("uo")
    for vantage in vantages:
        print(vantage)
        # currently in /home/protick/proxyrack/ocsp_simulation/coalese
        f = open("coalese/{}/amulgum_v2.json".format(vantage))
        d = json.load(f)

        for e in d:
            dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name, ocsp_host = e
            is_cdn = find_if_cdn(ocsp_host)

            if "demdex" in server_name or "mozilla" in server_name:
                continue
            try:
                ocsp_response = ocsp_2 - ocsp_1
                ocsp_arr[vantage][is_cdn].append(ocsp_response)
            except:
                pass
            try:
                ocsp_dns = ocsp_dns_2 - ocsp_dns_1
                dns_arr[vantage][is_cdn].append(ocsp_dns)
            except:
                pass
    with open("ec2_overhead/ocsp_response_v2.json", "w") as ouf:
        json.dump(ocsp_arr, fp=ouf)
    with open("ec2_overhead/dns_response_v2.json", "w") as ouf:
        json.dump(dns_arr, fp=ouf)


def calc_analysis(dns_start, client_hello_time, established_time, encrypted_data_time_app, ocsp_2, simulated_ocsp_end):
    tot_time_wrt_hello = encrypted_data_time_app - client_hello_time
    tot_time_wrt_dns = encrypted_data_time_app - dns_start
    delta = None

    if ocsp_2 <= established_time and simulated_ocsp_end <= established_time:
        delta = 0
    elif ocsp_2 <= established_time <= simulated_ocsp_end:
        delta = simulated_ocsp_end - established_time

    elif simulated_ocsp_end <= established_time <= ocsp_2:
        real_end = min(ocsp_2, encrypted_data_time_app)
        delta =  established_time - real_end

    else:
        if ocsp_2 <= encrypted_data_time_app:
            delta = simulated_ocsp_end - ocsp_2
        else:
            if simulated_ocsp_end > encrypted_data_time_app:
                delta = 0
            else:
                delta = simulated_ocsp_end - encrypted_data_time_app

    wrt_dns = (delta) / tot_time_wrt_dns
    wrt_hello = (delta) / tot_time_wrt_hello

    mom = {
        "tot_time_wrt_hello": tot_time_wrt_hello,
        "tot_time_wrt_dns": tot_time_wrt_dns,
        "ocsp_end": ocsp_2,
        "encrypted_data_time_app": encrypted_data_time_app,
        "established_time": established_time,
        "simulated_ocsp_end": simulated_ocsp_end,
        "wrt_dns": wrt_dns,
        "wrt_hello": wrt_hello,
        "delta": delta
    }

    return mom


def analyze_single_entry_final(tuple, ans_lst):
    global domain_resolver_to_response_time
    global resolver_str
    try:
        # print("Inside")
        e = tuple
        # dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name, meta, _ = e
        dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name, ocsp_host = e

        if "demdex" in server_name or "mozilla" in server_name:
            return None

        is_cdn = find_if_cdn(ocsp_host)

        things_needed = [ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, established_time, client_hello_time, dns_start, dns_end, encrypted_data_time_app]
        for e in things_needed:
            if e is None:
                return None


        simulated_ocsp_end = dns_end + ocsp_dns_2 - ocsp_dns_1
        simulated_in_place_ocsp_end = ocsp_dns_2

        ans1 = calc_analysis(dns_start=dns_start, client_hello_time=client_hello_time,
                             established_time=established_time, encrypted_data_time_app=encrypted_data_time_app,
                             ocsp_2=ocsp_2, simulated_ocsp_end=simulated_ocsp_end)
        ans2 = calc_analysis(dns_start=dns_start, client_hello_time=client_hello_time,
                             established_time=established_time, encrypted_data_time_app=encrypted_data_time_app,
                             ocsp_2=ocsp_2, simulated_ocsp_end=simulated_in_place_ocsp_end)


        ans_lst.append((ans1, ans2, is_cdn))

    except Exception as e:
        print(e)
        return None


def analyze_ec2_mult():
    print("yo")
    from collections import defaultdict
    vantages = ["mumbai", "ohio", "paris", "sydney", "sao-paolo"]
                            #        vantage               is_cdn               proactive/vanilla
    vantage_to_meta_lst = defaultdict(lambda : defaultdict(lambda : defaultdict(lambda: list())))

                                # is_cdn           # proactive/vanilla
    all_over_list = defaultdict(lambda : defaultdict(lambda: list()))

    overheads = defaultdict(lambda : defaultdict(lambda: list()))

    for vantage in vantages:
        # currently in /home/protick/proxyrack/ocsp_simulation/coalese
        f = open("coalese/{}/amulgum_v2.json".format(vantage))
        d = json.load(f)
        lst = []

        for e in d:
            try:
                analyze_single_entry_final(tuple=e, ans_lst=lst)
            except Exception as e:
                print(e)
                pass

        for e in lst:
            vantage_to_meta_lst[vantage][e[-1]]['proactive'].append(e[0])
            vantage_to_meta_lst[vantage][e[-1]]['vanilla'].append(e[1])
            all_over_list[e[-1]]['proactive'].append(e[0])
            all_over_list[e[-1]]['vanilla'].append(e[1])


    mother_list = {
        "all": all_over_list,
        "vanatge": vantage_to_meta_lst
    }

    with open("ec2_overhead/ec2_overheadall_meta_cdn_wise.json", "w") as ouf:
        json.dump(mother_list, fp=ouf)