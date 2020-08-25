## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

##############################
#         CONSTANTS          #
##############################

enum header {
    BACNET_IDENTIFIER    = 0x81
    };
    
enum bvlc_functions {
    BVLC_RESULT                             = 0x00,
    WRITE_BROADCAST_DISTRIBUTION_TABLE      = 0x01,
    READ_BROADCAST_DISTRIBUTION_TABLE       = 0x02,
    READ_BROADCAST_DISTRIBUTION_TABLE_ACK   = 0x03,
    FORWARDED_NPDU                          = 0x04,
    REGISTER_FOREIGN_DEVICE                 = 0x05,
    READ_FOREIGN_DEVICE_TABLE               = 0x06,
    READ_FOREIGN_DEVICE_TABLE_ACK           = 0x07,
    DELETE_FOREIGN_DEVICE_TABLE_ENTRY       = 0x08,
    DISTRIBUTE_BROADCAST_TO_NETWORK         = 0x09,
    ORIGINAL_UNICAST_NPDU                   = 0x0a,
    ORIGINAL_BROADCAST_NPDU                 = 0x0b,
    SECURE_BVLL                             = 0x0c
    };

##############################
##        RECORD TYPES       #
##############################

type BACnet_PDU(is_orig: bool) = case (is_orig) of {
    true  -> request    : BACnet_Request;
    false -> response   : BACnet_Response;
    } &byteorder=bigendian;

# switch for the request portion
type BACnet_Request = record {
    header  : BVLC;
    data    : case (header.header) of {
                BACNET_IDENTIFIER   -> bacnetHeaderVerify   : BACnet_Command(header);
                default             -> unknown              : bytestring &restofdata;
                };
    } &byteorder=bigendian;

# switch for the response portion
type BACnet_Response = record {
    header  : BVLC;
    data    : case (header.header) of {
                BACNET_IDENTIFIER   -> bacnetHeaderVerify   : BACnet_Command(header);
                default             -> unknown              : bytestring &restofdata;
                };
    } &byteorder=bigendian;

##! BACnet Virtual Link Control (BVLC)
type BVLC = record {
    header          : uint8; ##! header
    bvlc_function   : uint8; ##! function identifier
    bvlc_len        : uint16; ##! total length
    } &byteorder=bigendian;

# switch for the bvlc type
type BACnet_Command(header: BVLC) = case (header.bvlc_function) of  {
    BVLC_RESULT,
    WRITE_BROADCAST_DISTRIBUTION_TABLE,
    READ_BROADCAST_DISTRIBUTION_TABLE,
    READ_BROADCAST_DISTRIBUTION_TABLE_ACK,
    REGISTER_FOREIGN_DEVICE,
    READ_FOREIGN_DEVICE_TABLE,
    READ_FOREIGN_DEVICE_TABLE_ACK,
    DELETE_FOREIGN_DEVICE_TABLE_ENTRY,
    ORIGINAL_UNICAST_NPDU,
    FORWARDED_NPDU,
    DISTRIBUTE_BROADCAST_TO_NETWORK,
    ORIGINAL_BROADCAST_NPDU,
    SECURE_BVLL -> bacnet    : BACnet(header);
    default     -> unknown   : bytestring &restofdata;
    };

##! everything here
type BACnet(header: BVLC) = record {
    rest_of_data : bytestring &restofdata;
    } &byteorder=bigendian;
