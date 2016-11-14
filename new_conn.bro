@load base/protocols/http/entities
@load ./json.bro
@load base/utils/files

const restconf_route = "http://$CONTROLLER_IP:8181/restconf/config/fast-caltechdemo-flowmetadata:crosslayer-flow-metadata/flow-metadata/";
# const restconf_route = "http://localhost:8080/";

type HTTPMetadata: record {
    host: string &optional;
    uri: string &optional;
    user_agent: string &optional;
    filename: string &optional;
    content_length: count &optional;
    mime_type: vector of string &optional;
};

type FlowMetadata: record {
    flow_id: string;
    src_ip: addr;
    dst_ip: addr;
    src_port: count;
    dst_port: count;
    ip_proto: count;
    http_metadata: HTTPMetadata;
};

type FlowMetadataContainer: record {
    flow_metadata: FlowMetadata;
};

redef record connection += {
    file_info: HTTPMetadata &optional;
};

function flow_hash(c: connection) : string {
    return cat(
                "<",
                get_port_transport_proto(c$id$orig_p),
                ",",
                c$id$orig_h,
                ",",
                port_to_count(c$id$orig_p),
                ",",
                c$id$resp_h,
                ",",
                port_to_count(c$id$resp_p),
                ">"
    );
}

function update_file_info(c: connection) {
    local id = flow_hash(c);
    local file_info = c$file_info;

    local ip_proto = get_port_transport_proto(c$id$orig_p);
    local ip_num = 0;
    if (ip_proto == tcp) {
        ip_num = 6;
    } else if (ip_proto == udp) {
        ip_num = 17;
    }

    local flow_meta = FlowMetadata(
        $flow_id = id,
        $src_ip = c$id$orig_h,
        $dst_ip = c$id$resp_h,
        $src_port = port_to_count(c$id$orig_p),
        $dst_port = port_to_count(c$id$resp_p),
        $ip_proto = ip_num,
        $http_metadata = file_info
    );
    local data = FlowMetadataContainer(
        $flow_metadata = flow_meta
    );
    local json:string = JSON::convert(data);
    print json;

    # escape the id at runtime using python's urllib
    local urlencoded_id = "$(python -c \"import urllib; print urllib.quote('" + id + "')\")";
    when (local resp = ActiveHTTP::request([
        $url="",
        $method="PUT",
        $client_data=json,
        $addl_curl_args="-H \"Content-Type: application/json\" --user \"admin\":\"admin\" " + restconf_route + urlencoded_id
    ])) {
        print "response", resp;
    }
}

event http_reply(c: connection, version: string, code: count, reason: string) {
    if (! c?$file_info) {
        c$file_info = HTTPMetadata(
            $host = c$http$host,
            $uri = c$http$uri
        );
        print "host:", c$http$host;
        print "uri:", c$http$uri;
    }
}

event http_header(c: connection, orig: bool, name: string, value: string) {
    if (! c?$file_info ) {
        return;
    }
    if (name == "CONTENT-TYPE") {
        print "content-type", value;
    
        local mime_types = find_all(value, /[a-z\-A-Z0-9]*\/[a-z\-A-Z0-9]*/);
        c$file_info$mime_type = split_string(join_string_set(mime_types, ","), /,/);
    } else if (name == "CONTENT-DISPOSITION") {
        local filename = extract_filename_from_content_disposition(value);
        c$file_info$filename = filename;

        print "filename", filename;
    } else if (name == "CONTENT-LENGTH") {
        c$file_info$content_length = to_count(value);

        print "size", value;
    } else if (name == "USER-AGENT") {
        c$file_info$user_agent = value;

        print "user-agent", value;
    } else {
        print name, value;
    }
}

event http_end_entity(c: connection, orig: bool) {
    if (! c?$file_info) {
        return;
    }
    update_file_info(c);
    delete c$file_info;
}

