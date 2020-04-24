# `wolod` - Wake-on-LAN over DHCP

`wolod` encapsualtes a WoL payload in a DHCPINFORM message to be
sent via a DHCP relay/helper for delivery to the layer 2 network.
This allows for WoL to be deployed across layer 3 networks without
the need to enable directed broadcast on the final router.

## Usage

```
usage: wolod [-p port] [-l addr] -h eaddr relay [rport]
```

## Requirements

- This builds and runs on OpenBSD
- probably `eait-itig/dhcp-relay` on the last router
