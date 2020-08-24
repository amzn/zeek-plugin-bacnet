#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin { 
    namespace Zeek_BACnet {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_BACnet;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("BACnet", ::analyzer::bacnet::BACnet_Analyzer::Instantiate));

    plugin::Configuration config;
    config.name = "Zeek::BACnet";
    config.description = "BACnet protocol analyzer";
    return config;
    }
