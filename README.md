# clapd
is a simple LDAP caching proxy written in Python

## it will
* proxy bind, unbind and search requests between an LDAP enabled application and your LDAP server
* cache these requests with the corresponding responses and reply from cache if possible
* reply to requests it has cached even if the LDAP server is not available

## it will not
* handle any other type of query (no LDAPmodify etc.)
* (in offline mode) answer queries it has not seen before

## Getting started:
1. Install redis and required python modules.
2. Edit configuration.yaml with your settings.
3. Run clap.py and point your LDAP enabled app at it.

## Use cases:
* You want to run an LDAP-enabled application against a remote LDAP server without setting up a whole local LDAP slave server.
* You want to run an application that supports only ldap but not ldaps against a TLS-only LDAP server. 
* You want to use LDAP authentication across a flaky connection. 

##ToDo
* PEP8ify the code
* Clarify some comments

## Beware:
Caching always introduces security risks because old credentials can be used to validate.

-----
clapd, especially the BER encoding stuff, is based in part on work of Giovanni Cannata and contributors at https://github.com/cannatag/ldap3
