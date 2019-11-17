##! Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
##! SPDX-License-Identifier: BSD-3-Clause

##! Implements base functionality for Bacnet analysis.
##! Generates the bacnet.log file, containing some information about the Bacnet headers.

module Bacnet;

export {
    redef enum Log::ID += {
        Log_BACNET
        };
    
    ## header info
    type BACNET: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        bvlc_function   : string &optional &log;    ##
        bvlc_len        : count &optional &log;     ##
        apdu_type       : string &optional &log;
        pdu_flags       : count &optional;
        service_choice  : string &optional &log;
        data            : string_vec &optional &log;
        };
    ## Event that can be handled to access the record as it is sent
    global log_bacnet: event(rec: BACNET);
    }

redef record connection += {
    bacnet: BACNET &optional;
    };

## define listening ports
const ports = {
    47808/udp
    };
redef likely_server_ports += {
    ports
    };

##!======================================================
##! convert bytes not covered in bytestring_to_count
##!======================================================
function bytes_to_count(len: count, input: string): count {
    local number: count = 0;
    switch(len) {
        case 3:
            number = bytestring_to_count(input[0])*(0x010000) + bytestring_to_count(input[1:3]);
            break;
        case 5:
            number = bytestring_to_count(input[0])*(0x0100000000) + bytestring_to_count(input[1:5]);
            break;
        case 6:
            number = bytestring_to_count(input[0])*(0x010000000000) + bytestring_to_count(input[1])*(0x0100000000) + bytestring_to_count(input[2:6]);
            break;
        case 7:
            number = bytestring_to_count(input[0])*(0x01000000000000) + bytestring_to_count(input[1])*(0x010000000000) + bytestring_to_count(input[2])*(0x0100000000) + bytestring_to_count(input[3:7]);
            break;
        default:
            number = bytestring_to_count(input);
            break;
        }        
        
    return number;
    }

event zeek_init() &priority=5 {
    Log::create_stream(Bacnet::Log_BACNET,
                        [$columns=BACNET,
                        $ev=log_bacnet,
                        $path="bacnet"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_BACNET, ports);
    }

event bacnet(c:connection, is_orig:bool,
            bvlc_function: count,
            bvlc_len: count,
            rest_of_data: string) {
    if(!c?$bacnet) {
        c$bacnet = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$bacnet$ts = network_time();
    c$bacnet$bvlc_function = bvlc_functions[bvlc_function];
    c$bacnet$bvlc_len = bvlc_len;
    
    local data: string_vec;
    local data_index: count = 0;
    local rest_of_data_len = |rest_of_data|;
    local rest_of_data_index: count = 0;
    switch(bvlc_function) {
        case 0x00:  ##! BVLC_RESULT
            data[data_index] = fmt("result=%s", results[bytestring_to_count(rest_of_data[0:2])]);
            break;
        case 0x05:  ##! REGISTER_FOREIGN_DEVICE
            data[data_index] = fmt("ttl=%d", bytestring_to_count(rest_of_data[0:2]));
            break;
        case 0x01,  ##! WRITE_BROADCAST_DISTRIBUTION_TABLE
            0x02,   ##! READ_BROADCAST_DISTRIBUTION_TABLE
            0x03:   ##! READ_BROADCAST_DISTRIBUTION_TABLE_ACK
            
            break;
        case 0x04,  ##! FORWARDED_NPDU
            0x09,   ##! DISTRIBUTE_BROADCAST_TO_NETWORK
            0x0a,   ##! ORIGINAL_UNICAST_NPDU
            0x0b:   ##! ORIGINAL_BROADCAST_NPDU
            if (bvlc_function == 0x04) {
                ##! local ip: count = count_to_v4_addr(bytestring_to_count(rest_of_data[rest_of_data_index: rest_of_data_index+4]));
                rest_of_data_index += 4;
                ##! local port: count = bytestring_to_count(rest_of_data[rest_of_data_index: rest_of_data_index+2]);
                rest_of_data_index += 2;
                }
            ##! NPDU
            local version: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
            rest_of_data_index += 1;
            local control: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
            rest_of_data_index += 1;
            ##! Network Service Data Unit
            if (control == 0x80) {
                local network_layer_message_type = bytestring_to_count(rest_of_data[rest_of_data_index]);
                rest_of_data_index += 1;
                data[data_index] = fmt("%s", network_layer_messages[network_layer_message_type]);
                break;
                }
            else if (control == 0x08 ||
                control == 0x0c ||
                control == 0x20 ||
                control == 0x24 ||
                control == 0x28
                ) {
                local network_address: count = bytestring_to_count(rest_of_data[rest_of_data_index: rest_of_data_index+2]);
                rest_of_data_index += 2;
                local mac_len: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
                rest_of_data_index += 1;
                if (control == 0x28) {
                    local source_network_address: count = bytestring_to_count(rest_of_data[rest_of_data_index: rest_of_data_index+2]);
                    rest_of_data_index += 2;
                    mac_len = bytestring_to_count(rest_of_data[rest_of_data_index]);
                    rest_of_data_index += 1;
                    }
                local source_destination_address: string = bytestring_to_hexstr(rest_of_data[rest_of_data_index: rest_of_data_index+mac_len]);
                rest_of_data_index += mac_len;
                if (control == 0x20 ||
                    control == 0x24 ||
                    control == 0x28) {
                    local hop_count: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
                    rest_of_data_index += 1;
                    }
                }
            local apdu_type = bytestring_to_count(rest_of_data[rest_of_data_index]);
            rest_of_data_index += 1;
            local apduType: count = apdu_type / 16;
            c$bacnet$apdu_type = apdu_types[apduType];
            local apduFlags: count = 0;
            if (apduType == 0) {
                rest_of_data_index += 1; ##! maximum APDU accepted
                }
            if (apduType != 1) {
                apduFlags = apdu_type % 16;
                rest_of_data_index += 1; ##! invoke ID
                if (apduFlags > 2) {
                    rest_of_data_index += 1; ##! sequence number
                    rest_of_data_index += 1; ##! proposed window size
                    }
                }
            local serviceChoice: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
            rest_of_data_index += 1;
            local len: count = 0;
            local identifier_info: count = 0;
            local object_type: count = 0;
            local instance_number: count = 0;
            local value: count = 0;
            switch (apduType) {
                case 0x01: ##! UNCONFIRMED_SERVICE_REQUEST
                    c$bacnet$service_choice = unconfirmed_services[serviceChoice];
                    switch(serviceChoice) {
                        case 0x00:  ##! i am
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            identifier_info = bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]);
                            ##! 22b shift/bitwise
                            object_type = identifier_info / 4194304;
                            instance_number = identifier_info % 4194304;
                            rest_of_data_index += len;
                            ##! max apdu length accepted
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            rest_of_data_index += len;
                            ##! segmentation
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            rest_of_data_index += len;
                            ##! vendor id
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            data[data_index] = fmt("vendor=%s", vendors[bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len])]);
                            rest_of_data_index += len;
                            break;
                        case 0x06,  ##! time synchronization
                            0x08,   ##! who is
                            0x09:   ##! UTC time synchronization
                            if (rest_of_data_index >= rest_of_data_len) {
                                break;
                                }
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            if (serviceChoice == 0x08) {
                                    data[data_index] = fmt("low_limit=%d", bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]));
                                }
                            else {
                                data[data_index] = fmt("date=%s %d/%d/%d", timesync_dow[bytestring_to_count(rest_of_data[rest_of_data_index+3])],
                                                        bytestring_to_count(rest_of_data[rest_of_data_index])+1900,
                                                        bytestring_to_count(rest_of_data[rest_of_data_index+1]),
                                                        bytestring_to_count(rest_of_data[rest_of_data_index+2]));
                                }
                            rest_of_data_index += len;
                            data_index += 1;
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            if (serviceChoice == 0x08) {
                                data[data_index] = fmt("low_limit=%d", bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]));
                                }
                            else {
                                data[data_index] = fmt("time=%d:%02d:%02d.%d", bytestring_to_count(rest_of_data[rest_of_data_index]),
                                                        bytestring_to_count(rest_of_data[rest_of_data_index+1]),
                                                        bytestring_to_count(rest_of_data[rest_of_data_index+2]),
                                                        bytestring_to_count(rest_of_data[rest_of_data_index+3]));
                                }
                            rest_of_data_index += len;
                            break;
                        }
                    break;
                case 0x04: ##! segment ack
                    break;
                default:
                    c$bacnet$service_choice = confirmed_services[serviceChoice];
                    switch(serviceChoice) {
                        case 0x02,  ##! event notification
                            0x0c,   ##! read property
                            0x0f,   ##! write property
                            0x1a:   ##! read range
                            if (rest_of_data_index >= rest_of_data_len || apduFlags > 2) {
                                break;
                                }
                            if (serviceChoice == 0x02) {
                                ##! process identifier
                                len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                                rest_of_data_index += 1;
                                rest_of_data_index += len; ##! PID
                                }
                            ##! object identifier
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            identifier_info = bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]);
                            rest_of_data_index += len;
                            ##! 22b shift/bitwise
                            object_type = identifier_info / 4194304;
                            instance_number = identifier_info % 4194304;
                            data[data_index] = fmt("object=%s", object_types[object_type]);
                            data_index += 1;
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            if (serviceChoice == 0x02) {
                                identifier_info = bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]);
                                object_type = identifier_info / 4194304;
                                instance_number = identifier_info % 4194304;
                                data[data_index] = fmt("object=%s", object_types[object_type]);
                                }
                            else {
                                local property_identifier: count = bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]);
                                data[data_index] = fmt("property=%s", property_identifiers[property_identifier]);
                                }
                            ##! don't parse list
                            if ("List" in data[data_index]) {
                                break;
                                }
                            rest_of_data_index += len;
                            data_index += 1;
                            ##! { bracket
                            rest_of_data_index += 1;
                            # get value on ack
                            if (serviceChoice == 0x0c && (apduType > 1 && apduType < 5)) {
                                identifier_info = bytestring_to_count(rest_of_data[rest_of_data_index]);
                                rest_of_data_index += 1;
                                len = identifier_info % 8;
                                local data_type: count = identifier_info / 16;
                                switch(data_type) {
                                    case 2,  ##! UINT
                                         9:  ##! ENUMERATION
                                        value = bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len]);
                                        switch(property_identifier) {
                                            case 2: ##! action
                                                data[data_index] = fmt("value=%s", action[value]);
                                                break;
                                            case 25: ##! limit enable
                                                data[data_index] = fmt("value=%s", limit_enable[value]);
                                                break;
                                            case 107: ##! segmentation support
                                                data[data_index] = fmt("value=%s", segmentation_supports[value]);
                                                break;
                                            case 112: ##! system status
                                                data[data_index] = fmt("value=%s", system_statuses[value]);
                                                break;
                                            default:
                                                data[data_index] = fmt("value=%d", value);
                                                break;
                                            }
                                        break;
                                    case 7,  ##! STRING
                                         8:  ##! BIT STRING
                                        ##! extended value
                                        if (len == 5) {
                                            len = bytestring_to_count(rest_of_data[rest_of_data_index]);
                                            rest_of_data_index += 1;
                                            }
                                        if (data_type == 7) {
                                            local char_set: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
                                            rest_of_data_index += 1;
                                            data[data_index] = fmt("value=%s", rest_of_data[rest_of_data_index:rest_of_data_index+len-1]);
                                            }
                                        else {
                                            ##! unused bits
                                            rest_of_data_index += 1;
                                            data[data_index] = fmt("value=0x%s", string_to_ascii_hex(rest_of_data[rest_of_data_index:rest_of_data_index+len-1]));
                                            }
                                        break;
                                    case 12: ##! OBJECT
                                        data[data_index] = fmt("value=%d", bytes_to_count(len, rest_of_data[rest_of_data_index:rest_of_data_index+len])%4194304);
                                        break;
                                    }
                                }
                            break;
                        case 0x0e: ##! read property multiple
                            break;
                        }
                    break;
                }
            break;
        case 0x0c: ##! SECURE_BVLL
            break;
    }
    c$bacnet$data = data;
    
    Log::write(Log_BACNET, c$bacnet);
    delete c$bacnet;
    }

event connection_state_remove(c: connection) &priority=-5 {
    if(c?$bacnet) {
        delete c$bacnet;
        }
    }
