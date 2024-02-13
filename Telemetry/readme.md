## Readme

* Telemetry_downloader
  * Downloads firefox telemetry data from nightly versions 60 - 110 (change as necessary)
  * change the metric in the query parameter, currently set to metric=CERT_VALIDATION_HTTP_REQUEST_RESULT. have a look at the dashboard for better understanding ogf different Telemetry data provided by Firefox
    * https://telemetry.mozilla.org/new-pipeline/dist.html#!cumulative=0&end_date=2022-06-27&include_spill=0&keys=__none__!__none__!__none__&max_channel_version=nightly%252F103&measure=CERT_VALIDATION_HTTP_REQUEST_RESULT&min_channel_version=nightly%252F55&processType=*&product=Firefox&sanitize=1&sort_by_value=0&sort_keys=submissions&start_date=2022-05-30&table=0&trim=1&use_submission_date=0
  * telemetry_ocsp_response and telemetry_stapling folders have the raw data
* Telemetry_processor 
  * Parses the raw telemetry data and aggregates events datewise
  * Change bucket_to_index as necessary.

  

