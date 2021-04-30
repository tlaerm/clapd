# clap
## is a simple LDAP caching proxy

clap
* should be set up between an LDAP enabled application and your LDAP server
* will proxy and cache bind, unbind and search requests and the corresponding responses

clap
* will not handle any other type of query (no LDAPmodify etc.)
* in offline mode will only answer queries, that it has seen before

Beware:
Caching always introduces security risks because old credentials can be used to validate
