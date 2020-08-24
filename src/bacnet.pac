%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
    %}

analyzer BACnet withcontext {
    connection: BACnet_Conn;
    flow:       BACnet_Flow;
    };

%include bacnet-protocol.pac
%include bacnet-analyzer.pac
