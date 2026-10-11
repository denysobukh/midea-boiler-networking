# Inspect this file and run these commands on the MikroTik, after the proxy
# reports "listening". No DNS override is required.
# Add source NAT first, then destination NAT. Restrict both to this appliance.
/ip firewall nat add chain=srcnat src-address=192.168.200.133 dst-address=192.168.200.164 protocol=tcp dst-port=28443 action=src-nat to-addresses=192.168.200.1 place-before=0 comment="midea-research-proxy-srcnat"
/ip firewall nat add chain=dstnat src-address=192.168.200.133 protocol=tcp dst-port=28443 dst-address=!192.168.200.164 action=dst-nat to-addresses=192.168.200.164 to-ports=28443 place-before=0 comment="midea-research-proxy-dstnat"
# NAT applies to NEW connections. Reconnect/reboot the boiler after adding
# these rules; existing sessions keep their previous NAT mapping.
# Inspect counters:
/ip firewall nat print stats where comment~"midea-research-proxy"
