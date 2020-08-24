#include "BACnet.h"
#include "events.bif.h"

using namespace analyzer::bacnet;

BACnet_Analyzer::BACnet_Analyzer(Connection* c): analyzer::Analyzer("BACnet", c) {
    interp = new binpac::BACnet::BACnet_Conn(this);
    }

BACnet_Analyzer::~BACnet_Analyzer() {
    delete interp;
    }

void BACnet_Analyzer::Done() {
    Analyzer::Done();
    }

void BACnet_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try {
        interp->NewData(orig, data, data + len);
        }
    catch(const binpac::Exception& e) {
        ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
        }
    }

