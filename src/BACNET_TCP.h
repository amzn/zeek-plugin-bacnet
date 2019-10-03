#ifndef ANALYZER_PROTOCOL_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_H

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "bacnet_pac.h"

namespace analyzer { 
    namespace bacnet {
        class BACNET_Analyzer : public tcp::TCP_ApplicationAnalyzer {
            public:
                BACNET_Analyzer(Connection* conn);
                virtual ~BACNET_Analyzer();

                virtual void Done();
                virtual void DeliverStream(int len, const u_char* data, bool orig);
                virtual void Undelivered(uint64 seq, int len, bool orig);

                virtual void EndpointEOF(bool is_orig);

                static analyzer::Analyzer* Instantiate(Connection* conn) { 
                    return new BACNET_Analyzer(conn);
                    }

            protected:
                binpac::BACNET::BACNET_Conn* interp;
                bool had_gap;
            };
        } 
    }

#endif
