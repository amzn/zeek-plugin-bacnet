#include "Plugin.h"

namespace plugin { 
    namespace Zeek_BACNET {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_BACNET;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("BACNET", ::analyzer::bacnet::BACNET_Analyzer::Instantiate));
    
    plugin::Configuration config;
    config.name = "Zeek::BACNET";
    config.description = "Bacnet Protocol analyzer";
    return config;
    }
