
# Spicy-based Analyzers for Zeek

This repository provides a [Zeek](https://github.com/zeek/zeek)
package installing a set of protocol & file analyzers implemented
through [Spicy](https://github.com/zeek/spicy).

Currently, the following analyzers are included:

    - DHCP
    - DNS
    - HTTP
    - PNG
    - TFTP
    - Wireguard

We are working to expand this set. If you have written a Spicy
analyzer that you would like to see included here, please file a pull
request.

## Prerequisites

In addition to Zeek, you will first need to install Spicy. Please
follow [its instructions](https://docs.zeek.org/projects/spicy/en/latest/installation.html).

Please also [install and configure](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
the Zeek package manager.

To check that everything is set up correctly, confirm that the output of
`zeek -N` looks like this:

    # zeek -N _Zeek::Spicy
    _Zeek::Spicy - Support for Spicy parsers (*.spicy, *.evt, *.hlto) (dynamic, version x.y.z)`

## Installation

### Install through package manager

The easiest, and recommended, way to install the new analyzers is
through the Zeek package manager:

    # zkg install zeek/spicy-analyzers

This will pull down the package, compile and test the analyzers, and
then install and activate them. To check that the new analyzers are
available, run `zeek -NN` afterwards, it should list all the included
Spicy analyzers:

    # zeek -NN _Zeek::Spicy
    [...]
    [Analyzer] spicy_TFTP (ANALYZER_SPICY_TFTP, enabled)
    [...]

The new analyzers are now available to Zeek and used by default when
the package is activated.

### Build manually

You can also build the analyzers yourself outside of the package
manager. After cloning this repository, make sure the Spicy tools are
in your `PATH`. Then build the analyzers like this:

    # (mkdir build && cd build && cmake .. && make -j)

The tests should now pass:

    # (cd tests && btest -j)

There's currently no scripted installation available. You can move the
pieces into the right places for Zeek like this:

    # mkdir -p $(spicy-config --zeek-module-path)
    # cp -r build/spicy-modules/*.hlto $(spicy-config --zeek-module-path)

    # mkdir -p $(spicy-config --zeek-prefix)/share/zeek/site/spicy-analyzers
    # cp -r analyzer/* $(spicy-config --zeek-prefix)/share/zeek/site/spicy-analyzers

Now `zeek -NN _Zeek::Spicy` should show similar output as above. To
activate the new analyzers, add `@load spicy-analyzers` to your
`local.zeek`.
