'use strict';
let LIVE = true

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
var async = require('async');
var _ = require('lodash');
var axios = require('axios');

require('log-timestamp');

const fs = require('fs');
const {v4 : uuidv4} = require('uuid');
const { Telegraf } = require('telegraf')
var envs = require('envs');

let target_exp = 2000

// denoting pharah machines 0 - 3
var instance_id = 1
var api_ip = null
var URL = null
var mid_identifier = null
let app = null

if (instance_id === 1) {
    app = new Telegraf("5218575778:AAGjs0CStM2A8mmQ1Jr_LtmuIOo_7kP-_Dw");
}
else if(instance_id===2) {
    app = new Telegraf("5124273386:AAHut6JvYno4VSPr_yflqcxnkfuPey8lkww");
}
else if (instance_id===3) {
    app = new Telegraf("5180589187:AAGw-F0wqOv9uk5hoHh6seob7s45uWn9Ss0");
}
else if (instance_id===4) {
    app = new Telegraf("5217580252:AAFf1IU8Q_jyW5y2qOklvvMFxOi8eq_Z6OE");
}


let read_path_global = null
let read_path_local = null
if (LIVE) {
    read_path_global = '/home/protick/ocsp_dns_django/ttl_data_set-live-v3-local-False.json'
    read_path_local = '/home/protick/ocsp_dns_django/ttl_data_set-live-v3-local-False.json'
}
else {
    read_path_global = '/Users/protick.bhowmick/WebstormProjects/ttl_exp/ttl_data_set-live-global-False.json'
    read_path_local = '/Users/protick.bhowmick/WebstormProjects/ttl_exp/ttl_data_set-live-v2-local-False.json'
}

// export NODE_OPTIONS=--max_old_space_size=16384
var username = 'lum-customer-c_9c799542-zone-protick-dns-remote';


// TWEAK -->
let ALLOWED_TIME_IN_MINUTES = 1
let COOL_DOWN_IN_MINUTES = 1
const CHUNK_SIZE = 100

let phase_one_list_dict = {}
let phase_one_dict = {}
let telemetry_dict = {}
let chunks = null
let chunk_index = 0
let time_gap_str = ""
let requests_completed = 0
let final_count_matched = 0


function get_chunks(perChunk, inputArray) {

    try {
        return inputArray.reduce((resultArray, item, index) => {
            const chunkIndex = Math.floor(index / perChunk)

            if (!resultArray[chunkIndex]) {
                resultArray[chunkIndex] = [] // start a new chunk
            }

            resultArray[chunkIndex].push(item)

            return resultArray
        }, [])
    }
    catch (e) {
        return []
    }
}


function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function send_telegram_message(message) {
    app.telegram.sendMessage(1764697018, message);
    // console.log(message)
}

function shuffle(array) {
    let counter = array.length;

    // While there are elements in the array
    while (counter > 0) {
        // Pick a random index
        let index = Math.floor(Math.random() * counter);

        // Decrease counter by 1
        counter--;

        // And swap the last element with it
        let temp = array[counter];
        array[counter] = array[index];
        array[index] = temp;
    }

    return array;
}


async function change_bind_config(file_version, exp_id, ttl) {

    let bind_url = `http://${api_ip}:8000/update-bind/v2/`;
    await axios.get(bind_url, { params: {'file_version': file_version, 'exp_id': exp_id} })
        .then(response => {
            console.log("Bind change " + file_version + response);
            //console.log(response.data);
        })
        .catch(error => {
            console.log("Bind change error")
            console.log(error);
            axios.get(bind_url, { params: {'file_version': file_version, 'exp_id': exp_id} })
                .then(response => {
                    console.log("Bind change " + file_version + response);
                })
                .catch(error => {
                    console.log(error);
                });
        });
}

async function interim_checks(exp_id, bucket_id, event_str) {
    let uuid_str = uuidv4()

    let req_url = `http://${uuid_str}.${exp_id}.${event_str}.${bucket_id}.${mid_identifier}.${URL}`

    await axios.get(req_url)
        .then(response => {
            console.log("Interim check " + exp_id + " " + event_str);
            //console.log(response.data);
        })
        .catch(error => {
            console.log(error);
        });
}

async function bind_sanity_check(exp_id, expected_result, bucket_id, indentifier) {
    let a = String(Date.now());
    let uuid_str = uuidv4() + a;

    if (!(exp_id in telemetry_dict)) {
        telemetry_dict[exp_id] = {}
    }

    let ttl_in_sec = COOL_DOWN_IN_MINUTES * 60

    let req_url = `http://${uuid_str}.${exp_id}.${ttl_in_sec}.1.1.2.${URL}`
    //let req_url = `http://${uuid_str}.${bucket_id}.${URL}`

    await axios.get(req_url)
        .then(response => {
            telemetry_dict[exp_id][indentifier] = response.data
        })
        .catch(error => {
            telemetry_dict[exp_id][indentifier] = "error"
        });
}


function get_luminati_ip_hash(headers) {
    for(let i = 0; i < headers.length; i++) {
        if(headers[i] === 'x-luminati-ip') {
            return headers[i + 1];
        }
    }
    return "-1"
}

function store_phase1_data(exp_id, domain, data, req_url, req_send_time) {
    // Tran discuss
    let ip_hash = get_luminati_ip_hash(data.request.res.rawHeaders)
    let all_headers = data.request.res.rawHeaders.join()
    let response_data = data.data
    if (!(exp_id in phase_one_dict)) {
        phase_one_dict[exp_id] = {}
    }

    if (!(domain.id in phase_one_dict[exp_id])) {
        phase_one_dict[exp_id][domain.id] = {}
    }

    phase_one_dict[exp_id][domain.id]['1-time-start'] = req_send_time
    phase_one_dict[exp_id][domain.id]['ip_hash'] = ip_hash
    phase_one_dict[exp_id][domain.id]['asn'] = domain.asn
    phase_one_dict[exp_id][domain.id]['req_url'] = req_url
    phase_one_dict[exp_id][domain.id]['1-time'] = Date.now()

    phase_one_dict[exp_id][domain.id]['1-header'] = all_headers
    phase_one_dict[exp_id][domain.id]['1-response'] = response_data
}

function store_phase2_data(exp_id, domain, data, req_url, req_send_time) {
    //let server = get_server(data.data)

    let all_headers = data.request.res.rawHeaders.join()
    let response_data = data.data

    if (!(domain.id in phase_one_dict[exp_id])) {
        return
    }

    phase_one_dict[exp_id][domain.id]['2-time-start'] = req_send_time
    phase_one_dict[exp_id][domain.id]['2-time'] = Date.now()
    phase_one_dict[exp_id][domain.id]['2-header'] = all_headers
    phase_one_dict[exp_id][domain.id]['2-response'] = response_data

    final_count_matched += 1
}

function get_prev_ip_hash(exp_id, domain) {
    return phase_one_dict[exp_id][domain.id]['ip_hash'];
}

function get_prev_url(exp_id, domain) {
    return phase_one_dict[exp_id][domain.id]['req_url']
}

async function asnLookup_phase_1(domain, exp_id, phase, executed, bucket_number) {

    try {
        var luminati_session_id = (10000000 * Math.random()) | 0;
        let a = String(Date.now());
        let uuid_str = uuidv4() + a;
        let req_url = `http://${uuid_str}.${exp_id}.${COOL_DOWN_IN_MINUTES}.${domain.asn}.${bucket_number}.${mid_identifier}.${URL}`
        let req_send_time = Date.now()
        // Tran discuss
        require('axios-https-proxy-fix').get(req_url,
            {
                proxy: {
                    host: 'zproxy.lum-superproxy.io',
                    port: '22225',
                    auth: {
                        username: username + '-asn-' + domain.asn + '-session-' + luminati_session_id,
                        password: 'cbp4uaamzwpy'
                    }
                },
                timeout: 5000,
                forever:true

            }
        )
            .then(function (data) {
                    if (!(exp_id in phase_one_list_dict)) {
                        phase_one_list_dict[exp_id] = []
                    }
                    phase_one_list_dict[exp_id].push(domain)
                    store_phase1_data(exp_id, domain, data, req_url, req_send_time)
                    executed(null, domain.id);
                },
                function (err) {
                    executed(err, domain.id);
                    //console.error(err);
                });

    } catch (e) {
        executed(e, domain.id);
    }
}


async function asnLookup_phase_2(domain, exp_id, phase, executed, bucket_number) {

    try {

        var luminati_session_id = (10000000 * Math.random()) | 0;
        let prev_ip_hash = get_prev_ip_hash(exp_id, domain)
        let prev_url = get_prev_url(exp_id, domain)
        let req_url = prev_url
        let req_send_time = Date.now()

        require('axios-https-proxy-fix').get(req_url,
            {
                proxy: {
                    host: 'zproxy.lum-superproxy.io',
                    port: '22225',
                    auth: {
                        username: username + '-asn-' + domain.asn + '-session-' + luminati_session_id + '-ip-' + prev_ip_hash,
                        password: 'cbp4uaamzwpy'
                    }
                },
                timeout: 5000
            }
        )
            .then(function (data) {
                    store_phase2_data(exp_id, domain, data, req_url, req_send_time)
                    executed(null, domain.id);
                },
                function (err) {
                    executed(err, domain.id);
                    //console.error(err);
                });

    } catch (e) {
        executed(e, domain.id);
    }

}


async function do_phase_one_two(asn_instance_list_shuffled, exp_id, phase, bucket_number) {

    const init = Date.now()
    // predo asnlist !!

    if (phase === 2) {
        chunks = get_chunks(CHUNK_SIZE, asn_instance_list_shuffled)
    }

    for (let step = 0; step < chunks.length; step++) {
        let chunk = null
        if (phase === 2) {
            chunk = chunks[step];
        }
        else {
            chunk = chunks[chunk_index];
            chunk_index += 1
            if (chunk_index >= chunks.length) {
                chunk_index = 0;
            }
        }

        var cargoQueue = null;

        if(phase === 1) {
            cargoQueue = async.cargoQueue( function(task, executed){
                asnLookup_phase_1(task[0], exp_id, 1, executed, bucket_number)
            }, 100, 1);
        }
        else {
            cargoQueue = async.cargoQueue( function(task, executed){
                asnLookup_phase_2(task[0], exp_id,2, executed, bucket_number)
            }, 100, 1);
        }
        let chunk_practical = chunk
        if (phase === 1) {

            // TODO
            let time_now = Date.now()
            let minutes_taken_till_now = (time_now - init) / 60000;
            let time_left_in_minutes = ALLOWED_TIME_IN_MINUTES - minutes_taken_till_now
            if (time_left_in_minutes <= .2) {
                chunk_practical = chunk.slice(0, Math.min(Math.floor(CHUNK_SIZE/4), chunk.length))
            }
            requests_completed += chunk_practical.length
        }


        _.each(chunk_practical, function (task) {
            let d = null;
            if(phase === 1) {
                d = {asn: task[0], id: task[1]}
            }
            else {
                d = {asn: task.asn, id: task.id}
            }
            cargoQueue.push(d, (error, task_id) => {
                if (error) {
                    console.log(`An error occurred while processing task ${task_id} ${error}`);
                } else {
                    console.log(`Experiment ${exp_id} Phase ${phase} Finished processing task ${task_id}`);
                }
            });
        });

        cargoQueue.drain(() => {
            console.log('Phase ' + phase + ' All items are succesfully processed !');
        })

        await cargoQueue.drain()

        let time_now = Date.now()
        let minutes_taken_till_now = (time_now - init) / 60000;
        if (minutes_taken_till_now > ALLOWED_TIME_IN_MINUTES) {
            break;
        }
    }
}


function array_pivot_change(arr) {

    let pivot = Math.floor(Math.random() * (arr.length - 2));
    if(pivot === 0) {
        pivot += 1;
    }
    let first = arr.slice(0, pivot);
    let second = arr.slice(pivot, arr.length);

    return second.concat(first)

}


function get_asn_list() {
    let rawdata = null

    rawdata = fs.readFileSync(read_path_local);
    let asn_instance_list = JSON.parse(rawdata);
    return array_pivot_change(asn_instance_list);
}


async function save_telemetry(exp_id, phase, eventstring, time) {
    // telemetry_dict
    if (!(exp_id in telemetry_dict)) {
        telemetry_dict[exp_id] = {}
    }
    if (!(phase in telemetry_dict[exp_id])) {
        telemetry_dict[exp_id][phase] = {}
    }
    telemetry_dict[exp_id][phase][eventstring] = time

    if (eventstring === "end") {
        let total_time = telemetry_dict[exp_id][phase][eventstring] - telemetry_dict[exp_id][phase]['start']
        telemetry_dict[exp_id][phase]['total_time'] = total_time / 60000

        if (phase === 2) {
            let time_gap = telemetry_dict[exp_id][2]["start"] - telemetry_dict[exp_id][1]["end"]
            telemetry_dict[exp_id]['time_gap'] = time_gap / 60000
            time_gap_str =  time_gap_str + "_" + telemetry_dict[exp_id]['time_gap'].toString()

        }
    }
}

async function complete_bucket(bucket_number, phase, exp_id, asn_instance_list_shuffled) {
    if (phase === 1) {
        await change_bind_config("first", exp_id, null)
        await sleep(1000)
        await bind_sanity_check(exp_id,1, bucket_number, "phase_1_server1")
        await interim_checks(exp_id, bucket_number, "event-phase1-start")
        await save_telemetry(exp_id, phase, "start", Date.now())
        await do_phase_one_two(null, exp_id, 1, bucket_number);
        await save_telemetry(exp_id, phase, "end", Date.now())
        await interim_checks(exp_id, bucket_number,"event-phase1-end")
        await change_bind_config("remove", exp_id, null)
        await sleep(1000)
        await bind_sanity_check(exp_id,4, bucket_number, "phase_1_nxdomain")
    }
    else if(phase === 2) {
        await change_bind_config("second", exp_id, null)
        await sleep(1000)
        await bind_sanity_check(exp_id,2, bucket_number, "phase_2_server2")
        await interim_checks(exp_id, bucket_number, "event-sleep-end")
        await save_telemetry(exp_id, phase, "start", Date.now())
        await do_phase_one_two(phase_one_list_dict[exp_id], exp_id, 2, bucket_number)
        await save_telemetry(exp_id, phase, "end", Date.now())
        await interim_checks(exp_id, bucket_number,"event-phase2-end")
        await change_bind_config("remove", exp_id, null)
        await sleep(1000)
        await bind_sanity_check(exp_id, 4, bucket_number, "phase_2_nxdomain")
    }
}

//----------------------1---------live_node_15_1
async function init(exp_iteration, exp_id_prefix, total_buckets, time_stamp) {

    let asn_instance_list_shuffled = get_asn_list()

    send_telegram_message("First ASN " + asn_instance_list_shuffled[0][0])

    chunks = get_chunks(CHUNK_SIZE, asn_instance_list_shuffled)

    // await initiate_bind_server(total_buckets + 1, (COOL_DOWN_IN_MINUTES * 60))

    let bucket_start_index = (1 + (total_buckets * (instance_id - 1)))
    let bucket_end_index = bucket_start_index + total_buckets - 1

    for (let bucket_index = bucket_start_index; bucket_index <= bucket_end_index; bucket_index++) {

        let exp_id = `${exp_id_prefix}_${bucket_index}`

        send_telegram_message("Experiment started " + exp_id)

        let init = Date.now()

        await complete_bucket(bucket_index, 1, exp_id, null)

        let time_now = Date.now()
        let minutes_taken_till_now = (time_now - init) / 60000;

        if (minutes_taken_till_now < ALLOWED_TIME_IN_MINUTES) {
            let left_time = ALLOWED_TIME_IN_MINUTES - minutes_taken_till_now
            await sleep((left_time * 60 * 1000) + 1000)
        }
    }

    await sleep(1000)

    for (let bucket_index = bucket_start_index; bucket_index <= bucket_end_index; bucket_index++) {
        let exp_id = `${exp_id_prefix}_${bucket_index}`
        let init = Date.now()

        await complete_bucket(bucket_index, 2, exp_id, null)

        let time_now = Date.now()
        let minutes_taken_till_now = (time_now - init) / 60000;
        if (minutes_taken_till_now < ALLOWED_TIME_IN_MINUTES) {
            let left_time = ALLOWED_TIME_IN_MINUTES - minutes_taken_till_now;
            await sleep((left_time * 60 * 1000) + 1000);
        }
    }

    var base_dir_to_save = `results_new_exp_v2_${COOL_DOWN_IN_MINUTES}/${mid_identifier}/` + time_stamp.toString();

    if (!fs.existsSync(base_dir_to_save)) {
        fs.mkdirSync(base_dir_to_save, { recursive: true });
    }

    for (let key in phase_one_dict) {
        let meta_data = {}
        meta_data['ttl'] = COOL_DOWN_IN_MINUTES * 60
        meta_data['chunk_size'] = CHUNK_SIZE

        let store_dict = {}
        store_dict['exp_id'] = key
        store_dict['meta_data'] = meta_data
        store_dict['dict_of_phases'] = phase_one_dict[key]

        if (key in telemetry_dict) {
            store_dict['telemetry'] = telemetry_dict[key]
        }

        console.log(base_dir_to_save)
        let data = JSON.stringify(store_dict);
        fs.writeFileSync(`${base_dir_to_save}/${key}-out.json`, data);
    }
}

// needed changes -> paramters: mode -> (domain, api_ip), ttl (changing), r_code
// node script mode

async function init_mama() {
    let allowed_ttls = [1, 5, 15, 30, 60]
    let allowed_mids = [2]

    var ttl_to_count = {
        60: 1,
        30: 2,
        15: 4,
        5: 12,
        1: 60
    }

    for (var j = 0; j < allowed_mids.length; j++) {
        mid_identifier = allowed_mids[j];
        for (var i = 0; ; i++) {
            var index = i % 5;
            COOL_DOWN_IN_MINUTES = allowed_ttls[index];
            ALLOWED_TIME_IN_MINUTES = 1
            let TOTAL_BUCKETS = (COOL_DOWN_IN_MINUTES / ALLOWED_TIME_IN_MINUTES) + 1
            let total_iterations = ttl_to_count[COOL_DOWN_IN_MINUTES]

            for(let i = 1; i <= total_iterations; i++) {
                send_telegram_message("Starting for " + instance_id + " exp " + i + "ttl " + COOL_DOWN_IN_MINUTES)
                phase_one_list_dict = {}
                phase_one_dict = {}
                telemetry_dict = {}
                time_gap_str = ""
                chunks = null
                chunk_index = 0
                final_count_matched = 0
                requests_completed = 0
                let exp_id_prefix = null

                let time_stamp = parseInt(Date.now() / 1000)

                if (LIVE) {
                    exp_id_prefix = `zeus_reload_${COOL_DOWN_IN_MINUTES}_${time_stamp}`;
                }
                else {
                    exp_id_prefix = `zeus_reload_${COOL_DOWN_IN_MINUTES}_${time_stamp}`;
                }

                await init(i, exp_id_prefix, TOTAL_BUCKETS, time_stamp);
                await sleep(1000)
            }
        }
    }
}

// TODO change
var server_mode = process.argv[2]
if (server_mode === '1') {
    api_ip = '50.16.6.90'
    URL = 'securekey.app'
}
else if  (server_mode === '2') {
    api_ip = '52.44.221.99'
    URL = 'exp.net-measurement.net'
}

else {
    process.exit()
}

init_mama()