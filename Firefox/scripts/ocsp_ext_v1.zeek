@load base/protocols/conn
redef ignore_checksums = T;
module OCSP_EXT;
export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		ts:               time             &log;
		uid:              string           &log;


		ocsp_request_time:	       time	            &log	   &optional;
		hashAlgorithm:              string           &log       &optional;
		issuerNameHash:              string           &log       &optional;
		issuerKeyHash:              string           &log       &optional;
		serialNumber:              string           &log       &optional;

	};
	global log_ocsp_ext: event(rec: Info);
}

redef record fa_file += {
	test: Info &optional;
};


event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_ocsp_ext, $path="ocsp_ext_v1", $policy=log_policy]);
	Files::register_for_mime_type(Files::ANALYZER_OCSP_REQUEST, "application/ocsp-request");
	Files::register_for_mime_type(Files::ANALYZER_OCSP_REPLY, "application/ocsp-response");
	}


event ocsp_request_certificate(f: fa_file, hashAlgorithm: string, issuerNameHash: string, issuerKeyHash: string, serialNumber: string)
	{
	    if ( ! f?$test )
		{
		    f$test = [$ts=network_time(), $uid=f$http$uid];
		}

	    f$test$ocsp_request_time = network_time();
	    f$test$hashAlgorithm = hashAlgorithm;

	    f$test$issuerNameHash = issuerNameHash;
	    f$test$hashAlgorithm = hashAlgorithm;
	    f$test$issuerKeyHash = issuerKeyHash;
	    f$test$serialNumber = serialNumber;

        Log::write(LOG, f$test);

	}




