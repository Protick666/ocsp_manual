@load base/protocols/conn

redef ignore_checksums = T;

module TEST;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		ts:               time             &log;
		uid:              string           &log;
		id:               conn_id          &log;

        client_hello_time: time &log &optional;
        server_hello_time: time &log &optional;
        change_cipher_time_client: time &log &optional;
        change_cipher_time_server: time &log &optional;
        stapled_ocsp_time: time &log &optional;
        established_time: time &log &optional;
        encrypted_data_time: time &log &optional;
        server_key_time: time &log &optional;
        client_key_time: time &log &optional;
        server_signature_time: time &log &optional;
        encrypted_data_time_app: time &log &optional;
        logged: bool &default=F;

	};
	global log_ocsp: event(rec: Info);
}

redef record connection += {
	test: Info &optional;
};

function get_time(t: time, base: time): time
	{
        if (t < base) {

            return t;
        }
        else {

            return base;
        }
	}

function set_session(c: connection)
	{
	if ( ! c?$test )
		{
		c$test = [$ts=network_time(), $uid=c$uid, $id=c$id];
		}
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="ssl_ext_v1", $policy=log_policy]);
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=5
	{
    set_session(c);
    if (!c$test?$server_hello_time) {
        c$test$server_hello_time = network_time();
    }

	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
    set_session(c);

    if (!c$test?$client_hello_time) {
        c$test$client_hello_time = network_time();
    }

	}

event ssl_change_cipher_spec(c: connection, is_client: bool) &priority=5
	{
	    set_session(c);

        if (is_client) {
            if (!c$test?$change_cipher_time_client) {
                c$test$change_cipher_time_client = network_time();
            }
        }
        else  {
            if (!c$test?$change_cipher_time_server) {
                c$test$change_cipher_time_server = network_time();
            }
        }
    }

event ssl_established(c: connection) &priority=5
	{
    set_session(c);

    if (!c$test?$established_time) {
                c$test$established_time = network_time();
            }

	}

event ssl_stapled_ocsp(c: connection, is_client: bool, response: string) &priority=3
    {
    set_session(c);
    if (!c$test?$stapled_ocsp_time) {
                c$test$stapled_ocsp_time = network_time();
            }
    }

event ssl_ecdh_server_params(c: connection, curve: count, point: string) &priority=3
    {
        set_session(c);
        if (!c$test?$server_key_time) {
                    c$test$server_key_time = network_time();
                }
    }

event ssl_ecdh_client_params(c: connection, point: string) &priority=3
    {
    set_session(c);

	if (!c$test?$client_key_time) {
                    c$test$client_key_time = network_time();
                }

    }

event ssl_dh_client_params(c: connection, Yc: string) &priority=3
    {
    set_session(c);

	if (!c$test?$client_key_time) {
                    c$test$client_key_time = network_time();
                }

    }

event ssl_dh_server_params(c: connection, p: string, q: string, Yc: string) &priority=3
    {
    set_session(c);

	if (!c$test?$server_key_time) {
                    c$test$server_key_time = network_time();
                }

    }

event ssl_server_signature(c: connection, signature_and_hashalgorithm: SSL::SignatureAndHashAlgorithm, signature: string) &priority=5
    {
    set_session(c);

	if (!c$test?$server_signature_time) {
                    c$test$server_signature_time = network_time();
                }

    }

event ssl_encrypted_data(c: connection, is_orig: bool, record_version: count, content_type: count, length: count) &priority=5
    {
    set_session(c);

    if (content_type==23) {
        if (!c$test?$encrypted_data_time_app) {
            c$test$encrypted_data_time_app = network_time();
            if (!c$test$logged) {
                c$test$logged = T;
                Log::write(LOG, c$test);
            }
            }
        }
    }

