@load base/protocols/http/entities
@load ./json.bro

# const restconf_route = "http://<CONTROLLER_IP>:8181/restconf/config/fast-caltechdemo-flowmetadata:crosslayer-flow-metadata/flow-metadata/";
const restconf_route = "http://localhost:8080/";

type HTTPMetadata: record {
    host: string;
    uri: string;
    user_agent: string &optional;
    filename: string &optional;
    content_length: count &optional;
    mime_type: vector of string &optional;
};

type FlowMetadata: record {
    flow_id: string;
    http_metadata: HTTPMetadata;
};

function post(flow_ids: string_set, http: HTTP::Info) {
    print "flow", flow_ids;
    
    local meta = HTTPMetadata(
        $host = http$host,
        $uri = http$uri
    );

    # set the optional values
    if (http?$user_agent) {
        meta$user_agent = http$user_agent;
    }
    if (http?$filename) {
        meta$filename = http$filename;
    }
    if (http?$response_body_len) {
        meta$content_length = http$response_body_len;
    }
    if (http?$resp_mime_types) {
        meta$mime_type = http$resp_mime_types;
    }

    for (id in flow_ids) {
        local flow_meta = FlowMetadata(
            $flow_id = id,
            $http_metadata = meta
        );
        local json:string = JSON::convert(flow_meta);
        print json;

        when (local resp = ActiveHTTP::request([
            $url=restconf_route + id,
            $method="POST",
            $client_data=json,
            $addl_curl_args="-H \"Content-Type: application/json\""
        ])) {
            print "response", resp;
        }
    }
}

function flow_hash(f: fa_file) : string_set {
    local flows: string_set;
    for (c in f$conns) {
        add flows[
            cat(
                "<",
                get_port_transport_proto(c$orig_p),
                ",",
                c$orig_h,
                ",",
                port_to_count(c$orig_p),
                ",",
                c$resp_h,
                ",",
                port_to_count(c$resp_p),
                ">"
            )
        ];
    }
    return flows;
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    
    # ignore non-HTTP packets
    if (f$source != "HTTP") {
        print "ignore", f$source;
        return;
    }

    post(flow_hash(f), f$http);
}
