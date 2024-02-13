@load base/protocols/conn

redef ignore_checksums = T;

module HTTP_EXT;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		ts:               time             &log;
		uid:              string           &log;
		event_type:       string           &log;

		origin_uri:       string           &log      &optional;
		unescaped_uri:       string           &log      &optional;

	};
	global log_http_ext: event(rec: Info);
}


event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_http_ext, $path="http_ext_v1", $policy=log_policy]);

	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
	{

	local temp_log_req: Info = [$ts=network_time(), $uid=c$uid, $event_type="request"];
    temp_log_req$origin_uri = original_URI;
    temp_log_req$unescaped_uri = unescaped_URI;
    Log::write(LOG, temp_log_req);

    }

event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	    local temp_log_res: Info = [$ts=network_time(), $uid=c$uid, $event_type="response"];
        Log::write(LOG, temp_log_res);
    }
