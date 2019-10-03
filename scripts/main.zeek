## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

##! Implements base functionality for Bacnet analysis.
##! Generates the Bacnet.log file, containing some information about the Bacnet headers.

module Bacnet;

export {
    redef enum Log::ID += {
        Log_BACNET,
        Log_BACNET_NPDU,
        Log_BACNET_Original_Unicast_NPDU,
        Log_BACNET_Forwarded_Distribute_Original_Broadcast_NPDU,
        Log_BACNET_Register_Foreign_Device
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
        case 0x00: ##! BVLC_RESULT
            data[data_index] = fmt("result=%s", results[bytestring_to_count(rest_of_data[0:2])]);
            break;
        case 0x05: ##! REGISTER_FOREIGN_DEVICE
            data[data_index] = fmt("ttl=%d", bytestring_to_count(rest_of_data[0:2]));
            break;
        case 0x01, ##! WRITE_BROADCAST_DISTRIBUTION_TABLE
            0x02, ##! READ_BROADCAST_DISTRIBUTION_TABLE
            0x03: ##! READ_BROADCAST_DISTRIBUTION_TABLE_ACK
            
            break;
        case 0x04, ##! FORWARDED_NPDU
            0x09, ##! DISTRIBUTE_BROADCAST_TO_NETWORK
            0x0a, ##! ORIGINAL_UNICAST_NPDU
            0x0b: ##! ORIGINAL_BROADCAST_NPDU
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
            if (control == 0x08 ||
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
            if (apduType == 0) {
                rest_of_data_index += 1; ##! maximum APDU accepted
                }
            if (apduType != 1) {
                ##! c$bacnet$pdu_flags = apdu_type % 8;
                rest_of_data_index += 1; ##! invoke ID
                }
            local serviceChoice: count = bytestring_to_count(rest_of_data[rest_of_data_index]);
            rest_of_data_index += 1;
            local len: count = 0;
            switch (apduType) {
                case 1:     ##! UNCONFIRMED_SERVICE_REQUEST
                    c$bacnet$service_choice = unconfirmed_services[serviceChoice];
                    switch(serviceChoice) {
                        case 0x00:    ##! i am
                            
                            break;
                        case 0x06,    ##! time synchronization
                            0x08,     ##! who is
                            0x09:     ##! UTC time synchronization
                            if (rest_of_data_index >= rest_of_data_len) {
                                break;
                                }
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            if (serviceChoice == 0x08) {
                                data[data_index] = fmt("low_limit=%d", bytestring_to_count(rest_of_data[rest_of_data_index:rest_of_data_index+len]));
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
                                data[data_index] = fmt("high_limit=%d", bytestring_to_count(rest_of_data[rest_of_data_index:rest_of_data_index+len]));
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
                        case 0x02, ##! event notification
                            0x0c, ##! read property
                            0x0f, ##! write property
                            0x1a: ##! read range
                            if (rest_of_data_index >= rest_of_data_len) {
                                break;
                                }
                            ##! object identifier
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            data[data_index] = fmt("object=%s", object_types[bytestring_to_count(rest_of_data[rest_of_data_index:rest_of_data_index+2])/64]);
                            rest_of_data_index += len;
                            data_index += 1;
                            ##! property identifier
                            len = bytestring_to_count(rest_of_data[rest_of_data_index]) % 8;
                            rest_of_data_index += 1;
                            data[data_index] = fmt("property=%s", property_identifiers[bytestring_to_count(rest_of_data[rest_of_data_index])]);
                            rest_of_data_index += len;
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
