#ifndef ANALYZER_PROTOCOL_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_H

#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "bacnet_pac.h"

namespace analyzer {
    namespace bacnet {
        class BACnet_Analyzer : public analyzer::Analyzer {
            public:
                BACnet_Analyzer(Connection* conn);
                virtual ~BACnet_Analyzer();

                virtual void Done();
                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);

                static analyzer::Analyzer* Instantiate(Connection* conn) { 
                    return new BACnet_Analyzer(conn);
                    }

            protected:
                binpac::BACnet::BACnet_Conn* interp;
            };
        }
    }

#endif
