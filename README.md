# `wolod` - Wake-on-LAN over DHCP

`wolod` encapsualtes a WoL payload in a DHCP message to be
sent via a DHCP relay/helper for delivery to the layer 2 network.
This allows for WoL to be deployed across layer 3 networks without
the need to enable directed broadcast on the final router.

## Usage

```
     wolod [-u] [-c client-address] [-H chaddr] [-l local-address]
           [-p local-port] [-P relay-port] [-t dhcp-msg-type] -h mac-address
           -r relay-address
```

## Requirements

- This builds and runs on OpenBSD
- probably `eait-itig/dhcp-relay` on the last router
