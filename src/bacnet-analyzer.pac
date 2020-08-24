## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

connection BACnet_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = BACnet_Flow(true);
    downflow = BACnet_Flow(false);
    };

%header{
    %}

flow BACnet_Flow(is_orig: bool) {
    # flowunit = BACnet_PDU(is_orig) withcontext(connection, this);
    datagram = BACnet_PDU(is_orig) withcontext(connection, this);

    function bacnet(bacnet: BACnet): bool %{
        if(::bacnet) {
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_bacnet(connection()->bro_analyzer(),
                            connection()->bro_analyzer()->Conn(),
                            is_orig(),
                            ${bacnet.header.bvlc_function},
                            ${bacnet.header.bvlc_len},
                            bytestring_to_val(${bacnet.rest_of_data})
                            );
            }

        return true;
        %}
    };

refine typeattr BACnet += &let {
    bacnet: bool = $context.flow.bacnet(this);
    };
