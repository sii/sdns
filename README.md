# dns.routemeister.net dynamic dns server

sdns is the (simple) dynamic dns server used by the dynamic dns service
on http://dns.routemeister.net.

This project was used as a way to get more familiar with the Go programming
language.

The project should be runnable as is, but there are a few notable issues.
Primarily the NS/SOA records are hardcoded to the values used by
dns.routemeister.net and need to be updated directly in the source.

sdns also depends on sdnsweb as a web frontend.

See:
* https://github.com/sii/sdnsweb
* http://dns.routemeister.net
