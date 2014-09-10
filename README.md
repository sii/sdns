# dns.routemeister.net dynamic dns server

sdns is the (simple) dynamic dns server used by the dynamic dns service
on dns.routemeister.net.

This project was used as a way to get more familiar with the Go programming
language.

A few config items need to be broken into command line options (or a
config file). Most notable the NS/SOA records are hardcoded to the
values used by dns.routemeister.net.
