
# Meta-package for Spicy-based Analyzers for Zeek

This repository provides a [Zeek](https://github.com/zeek/zeek) meta-package
installing a set of protocol & file analyzers implemented through
[Spicy](https://github.com/zeek/spicy).

Currently, the following analyzers are included:

- [DHCP](https://github.com/zeek/spicy-dhcp) <sup>[1]</sup>
- [DNS](https://github.com/zeek/spicy-dns) <sup>[1]</sup>
- [Facefish Rootkit](https://github.com/corelight/zeek-spicy-facefish)
- [HTTP](https://github.com/zeek/spicy-http) <sup>[1]</sup>
- [IPSec](http://github.com/corelight/zeek-spicy-ipsec)
- [LDAP](http://github.com/zeek/spicy-ldap)
- [OpenVPN](http://github.com/corelight/zeek-spicy-openvpn)
- [PNG](https://github.com/zeek/spicy-png)
- [Portable Executable (PE)](https://github.com/zeek/spicy-pe) <sup>[2]</sup>
- [STUN](http://github.com/corelight/zeek-spicy-stun)
- [Tailscale VPN](http://github.com/corelight/zeek-spicy-wireguard)
- [TFTP](https://github.com/zeek/spicy-tftp)
- [Wireguard](http://github.com/corelight/zeek-spicy-wireguard)
- [ZIP archives](https://github.com/zeek/spicy-zip)

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

Since this package is a meta-package, the easiest, and recommended way to
install the analyzers is through the Zeek package manager:

    # zkg install zeek/spicy-analyzers

This will pull down the package and its dependencies, compile and test the
analyzers, and then install and activate them. To check that the new analyzers are
available, run `zeek -NN` afterwards, it should list all the included
Spicy analyzers:

    # zeek -NN _Zeek::Spicy
    [...]
    [Analyzer] spicy_TFTP (ANALYZER_SPICY_TFTP, enabled)
    [...]

The new analyzers are now available to Zeek and used by default when
the package is activated.

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

This package is open source and released under a BSD license. Please see the
individual analyzer package for their licenses.
