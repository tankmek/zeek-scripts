# All rights reserved.
# Copyright 2018, Michael Edie
#//-----------------------------------------------------------
#// Detects when there is a connection to an external IP address
#// without a preceding DNS lookup.
#// This will look at every SYN packet. Use wisely.
#// Recommended usage: bro -C -r network.pcap dns-query-audit.bro
#// If you really want to install it in production:
#// echo '@load dns-query-audit.bro' >> $BROPREFIX/share/bro/site/local.bro
#// cp dns-query-audit.bro $BROPREFIX/share/bro/site
#//-----------------------------------------------------------
@load base/protocols/dns
@load base/protocols/conn
@load base/frameworks/notice
# Set expiration timeout on A record container
global  dns_addr: set [addr] &read_expire = 4 days;
# Whitelisted IPs
const localnet: set[subnet] = {
        192.168.14.0/24,
        192.168.28.0/24,
        192.168.27.0/24,
        192.168.29.0/24
} &redef;
# Create a custom notice type
export {

         redef enum Notice::Type += {
               DNS::No_Query_Before_Connection
       };
}
# Save DNS reply A record
event dns_A_reply (c: connection, msg: dns_msg, ans:  dns_answer, a: addr)
    {
      if (a in localnet) return;

      add dns_addr[a];
    }
# Bro raises this event for every SYN packet seen by its TCP analyzer.
event connection_SYN_packet (c: connection, pkt: SYN_packet) {
      if ([c$id$resp_h] !in dns_addr && c$id$resp_h !in localnet)
      {
        NOTICE([$note=DNS::No_Query_Before_Connection,
                $msg="Found IP connection with no preceding DNS request",
                $conn=c,
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $suppress_for=1day]);

      }
    }
