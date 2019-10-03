#include "BACNET.h"
#include "events.bif.h"

using namespace analyzer::bacnet;

BACNET_Analyzer::BACNET_Analyzer(Connection* c): analyzer::Analyzer("BACNET", c) {
    interp = new binpac::BACNET::BACNET_Conn(this);
    }

BACNET_Analyzer::~BACNET_Analyzer() {
    delete interp;
    }

void BACNET_Analyzer::Done() {
    Analyzer::Done();
    }

void BACNET_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try {
        interp->NewData(orig, data, data + len);
        }
    catch(const binpac::Exception& e) {
        ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
        }
    }

