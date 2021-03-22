
# Spicy-based Analyzers for Zeek

This repository provides a [Zeek](https://github.com/zeek/zeek)
package installing a set of protocol & file analyzers implemented
through [Spicy](https://github.com/zeek/spicy).

Currently, the following analyzers are included:

- DHCP <sup>[1]</sup>
- DNS <sup>[1]</sup>
- HTTP <sup>[1]</sup>
- OpenVPN
- PNG
- Portable Executable (PE) <sup>[2]</sup>
- TFTP
- Wireguard

We are working to expand this set. If you have written a Spicy
analyzer that you would like to see included here, please file a pull
request.

<sup>[1] replaces the corresponding Zeek analyzer</sup>\
<sup>[2] replaces and extends the corresponding Zeek analyzer</sup>

## Prerequisites

In addition to Zeek, you will first need to install Spicy. Please
follow [its instructions](https://docs.zeek.org/projects/spicy/en/latest/installation.html).
Ensure that the Spicy toolchain is in your ``PATH``. For example, with
it installed to `/opt/spicy` and using `bash`:

    export PATH=/opt/spicy/bin:$PATH

Now `which` should be able to find `spicy-config`:

    # which spicy-config
    /opt/spicy/bin/spicy-config

Please also [install and configure](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
the Zeek package manager.

Finally, you will need the [Spicy plugin for
Zeek](https://github.com/zeek/spicy-plugin), which you can install
through the package manager:

    # zkg install zeek/spicy-plugin

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

### Install manually

You can also build the analyzers yourself outside of the package
manager. After cloning this repository, make sure that the Spicy tools are
in your `PATH`, and that the Spicy plugin for Zeek is in place, per
above. Then build the analyzers like this:

    # (mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/opt/spicy .. && make -j)

The tests should now pass:

    # make -C tests

You can then install the analyzers with:

    # make -C build install

Now `zeek -NN _Zeek::Spicy` should show similar output as above.

When you run Zeek, add `spicy-analyzers` to the command line to load
the analyzer scripts.

## Configuration

By default, all included analyzers will be activated, and they will
automatically disable any standard analyzers that they replace. If you
want to disable one of the Spicy analyzers, you can do so by calling
one of the built-in functions
[disable_protocol_analyzer/disable_file_analyzer()](https://docs.zeek.org/projects/spicy/en/latest/zeek.html#functions).
For example, to disable the HTTP analyzer, add this to your
`site.zeek`:

```.zeek
    event zeek_init()
        {
        Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_HTTP);
        }
```

You can find the `ANALYZER_*` value to use for an analyzer in the
output of `zeek -N _Zeek::Spicy`.

(Note that `disable_file_analyzer()` requires a current development
version of Zeek to be available.)

## License

These analyzers are open source and released under a BSD license.
