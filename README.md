# badflare
OSINT tool for discovering the real IP addresses of services which are behind Cloudflare but not properly configured

## Pardon?
Cloudflare provides protection to it's customers, however this is predicated on those customers locking their environment to only be accessible to Cloudflare.  Direct access to services circumvents this protection, and can de-anonymise the location of the service.

Many people opt to use simple obfuscation, specifically, no DNS pointing to the real host, rather than truely locking down their environment.  This leaves the host vulnerable to attack if it's true IP address can be discovered, thus bypassing Cloudflare protection.

## Hence badflare
Badflare attempts to discover poorly configured hosts.  Simply provide your shodan API key on the commandline or as the env var `SHODAN_API` and run the command in form:

`badflare -h host.this_is_my_victim.com`

## Building
This is a simple go tool so you can either clone this repo and build using:

`go build`
