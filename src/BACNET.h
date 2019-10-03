#ifndef ANALYZER_PROTOCOL_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_H

#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "bacnet_pac.h"

namespace analyzer {
    namespace bacnet {
        class BACNET_Analyzer : public analyzer::Analyzer {
            public:
                BACNET_Analyzer(Connection* conn);
                virtual ~BACNET_Analyzer();

                virtual void Done();
                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen);

                static analyzer::Analyzer* Instantiate(Connection* conn) { 
                    return new BACNET_Analyzer(conn);
                    }

            protected:
                binpac::BACNET::BACNET_Conn* interp;
            };
        } 
    }

#endif
