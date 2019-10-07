## Zeek Plugin BACnet

Zeek network security monitor plugin that enables parsing of the [BACnet](http://www.bacnet.org/) standard building controls protocol. When running as part of your Zeek installation this plugin will produce a `bacnet.log` file containing metadata extracted from any BACnet traffic observed on UDP port 47808.

## Installation and Usage

`zeek-plugin-bacnet` is distributed as a Zeek package and is compatible with the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command line tool.

## Sharing and Contributing

This code is made available under the [BSD-3-Clause license](LICENSE). [Guidlines for contribuing](CONTRIBUTING.md) are available as well as a [pull request template](.github/PULL_REQUEST_TEMPLATE.md). A [Dockerfile](Dockerfile) has been included in the repository to assist with setting up an environment for testing any changes to the plugin.
