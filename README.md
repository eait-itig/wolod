# `wolod` - Wake-on-LAN over DHCP

`wolod` encapsualtes a WoL payload in a DHCP message to be
sent via a DHCP relay/helper for delivery to the layer 2 network.
This allows for WoL to be deployed across layer 3 networks without
the need to enable directed broadcast on the final router.

## Usage

```
usage: wolod [-LBu] [-c client-address] [-H chaddr]
        [-l local-addr] [-p local-port] [-P relay-port]
        [-s siaddr] [-t type] [-T lt] -r relay -h mac-addr
```

## Requirements

- This builds and runs on OpenBSD
