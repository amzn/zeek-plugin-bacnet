#ifndef ZEEK_PLUGIN_ZEEK_BACNET
#define ZEEK_PLUGIN_ZEEK_BACNET

#include <plugin/Plugin.h>
#include "BACnet.h"

namespace plugin {
    namespace Zeek_BACnet {
        class Plugin : public ::plugin::Plugin {
            protected:
                // Overridden from plugin::Plugin.
                virtual plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif
