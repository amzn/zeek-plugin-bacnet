## Zeek Plugin BACnet

When running as part of your Zeek installation this plugin will produce a `bacnet.log` file containing metadata extracted from any [BACnet](http://www.bacnet.org/) traffic observed on UDP port 47808.

## Installation and Usage

`zeek-plugin-bacnet` is distributed as a Zeek package and is compatible with the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command line tool.

## Sharing and Contributing

This code is made available under the [BSD-3-Clause license](https://github.com/amzn/zeek-plugin-bacnet/blob/master/LICENSE). [Guidelines for contributing](https://github.com/amzn/zeek-plugin-bacnet/blob/master/CONTRIBUTING.md) are available as well as a [pull request template](https://github.com/amzn/zeek-plugin-bacnet/blob/master/.github/PULL_REQUEST_TEMPLATE.md). A [Dockerfile](https://github.com/amzn/zeek-plugin-bacnet/blob/master/Dockerfile) has been included in the repository to assist with setting up an environment for testing any changes to the plugin.

## Related Work

* [ICSNPP-BACnet](https://github.com/cisagov/icsnpp-bacnet) - Another BACnet plugin implementation for Zeek
* [BACnet - Spicy](https://github.com/rsmmr/hilti/blob/master/bro/spicy/bacnet.spicy) - An implementation of BACnet in Spicy for Zeek

