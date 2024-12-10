`syslog(transport(proxied-*))` and `network(transport(proxied-*))`: changed
where HAProxy transport saved the original source and destination addresses.
Instead of using dedicated `PROXIED_*` name-value pairs, use the usual
`$SOURCEIP`, `$DESTIP` and `$DESTPORT` macros, making haproxy based
connections just like native ones.
