%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
    %}

analyzer BACNET withcontext {
    connection:    BACNET_Conn;
    flow:        BACNET_Flow;
    };

%include bacnet-protocol.pac
%include bacnet-analyzer.pac
