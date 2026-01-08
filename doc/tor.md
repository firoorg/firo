TOR SUPPORT IN FIRO
===================

It is possible to run Firo as a Tor hidden service, and connect to such services.

Firo supports Tor v3 onion addresses (56 character addresses). The older Tor v2
addresses (16 character addresses) are no longer supported as they have been
deprecated by the Tor project due to security concerns.

The following directions assume you have a Tor proxy running on port 9050. Many distributions default to having a SOCKS proxy listening on port 9050, but others may not. In particular, the Tor Browser Bundle defaults to listening on port 9150. See [Tor Project FAQ:TBBSocksPort](https://www.torproject.org/docs/faq.html.en#TBBSocksPort) for how to properly
configure Tor.


1. Run Firo behind a Tor proxy
------------------------------

The first step is running Firo behind a Tor proxy. This will already make all
outgoing connections be anonymized, but more is possible.

	-proxy=ip:port  Set the proxy server. If SOCKS5 is selected (default), this proxy
	                server will be used to try to reach .onion addresses as well.

	-onion=ip:port  Set the proxy server to use for Tor hidden services. You do not
	                need to set this if it's the same as -proxy. You can use -noonion
	                to explicitly disable access to hidden service.

	-listen         When using -proxy, listening is disabled by default. If you want
	                to run a hidden service (see next section), you'll need to enable
	                it explicitly.

	-connect=X      When behind a Tor proxy, you can specify .onion addresses instead
	-addnode=X      of IP addresses or hostnames in these parameters. It requires
	-seednode=X     SOCKS5. In Tor mode, such addresses can also be exchanged with
	                other P2P nodes.

In a typical situation, this suffices to run behind a Tor proxy:

	./firod -proxy=127.0.0.1:9050


2. Run a Firo hidden server
---------------------------

If you configure your Tor system accordingly, it is possible to make your node also
reachable from the Tor network. Add these lines to your /etc/tor/torrc (or equivalent
config file):

	HiddenServiceDir /var/lib/tor/firo-service/
	HiddenServiceVersion 3
	HiddenServicePort 8168 127.0.0.1:8168
	HiddenServicePort 18168 127.0.0.1:18168

The directory can be different of course, but (both) port numbers should be equal to
your firod's P2P listen port (8168 by default). Note that `HiddenServiceVersion 3`
ensures Tor v3 onion addresses are used.

	-externalip=X   You can tell Firo about its publicly reachable address using
	                this option, and this can be a .onion address. Given the above
	                configuration, you can find your onion address in
	                /var/lib/tor/firo-service/hostname. Onion addresses are given
	                preference for your node to advertise itself with, for connections
	                coming from unroutable addresses (such as 127.0.0.1, where the
	                Tor proxy typically runs).

	-listen         You'll need to enable listening for incoming connections, as this
	                is off by default behind a proxy.

	-discover       When -externalip is specified, no attempt is made to discover local
	                IPv4 or IPv6 addresses. If you want to run a dual stack, reachable
	                from both Tor and IPv4 (or IPv6), you'll need to either pass your
	                other addresses using -externalip, or explicitly enable -discover.
	                Note that both addresses of a dual-stack system may be easily
	                linkable using traffic analysis.

In a typical situation, where you're only reachable via Tor, this should suffice:

	./firod -proxy=127.0.0.1:9050 -externalip=youronionaddressxyz123456789abcdefghijklmnopqrstuvwxyz.onion -listen

(obviously, replace the Onion address with your own Tor v3 address - a 56 character address
ending in .onion). It should be noted that you still listen on all devices and another node
could establish a clearnet connection, when knowing your address. To mitigate this,
additionally bind the address of your Tor proxy:

	./firod ... -bind=127.0.0.1

If you don't care too much about hiding your node, and want to be reachable on IPv4
as well, use `discover` instead:

	./firod ... -discover

and open port 8168 on your firewall (or use -upnp).

If you only want to use Tor to reach onion addresses, but not use it as a proxy
for normal IPv4/IPv6 communication, use:

	./firod -onion=127.0.0.1:9050 -externalip=youronionaddressxyz123456789abcdefghijklmnopqrstuvwxyz.onion -discover

3. Automatically listen on Tor
------------------------------

Starting with Tor version 0.2.7.1 it is possible, through Tor's control socket
API, to create and destroy 'ephemeral' hidden services programmatically.
Firo has been updated to make use of this with Tor v3 onion addresses.

This means that if Tor is running (and proper authentication has been configured),
Firo automatically creates a Tor v3 hidden service to listen on. This will positively 
affect the number of available .onion nodes.

This feature is enabled by default if Firo is listening (`-listen`), and
requires a Tor connection to work. It can be explicitly disabled with `-listenonion=0`
and, if not disabled, configured using the `-torcontrol` and `-torpassword` settings.
To show verbose debugging information, pass `-debug=tor`.

The private key for the automatically created hidden service is stored in
`onion_v3_private_key` in the data directory. This file uses the ED25519-V3 key
format required by Tor v3.

Connecting to Tor's control socket API requires one of two authentication methods to be 
configured. For cookie authentication the user running firod must have write access 
to the `CookieAuthFile` specified in Tor configuration. In some cases this is 
preconfigured and the creation of a hidden service is automatic. If permission problems 
are seen with `-debug=tor` they can be resolved by adding both the user running tor and 
the user running firod to the same group and setting permissions appropriately. On 
Debian-based systems the user running firod can be added to the debian-tor group, 
which has the appropriate permissions. An alternative authentication method is the use 
of the `-torpassword` flag and a `hash-password` which can be enabled and specified in 
Tor configuration.

4. Privacy recommendations
--------------------------

- Do not add anything but Firo ports to the hidden service created in section 2.
  If you run a web service too, create a new hidden service for that.
  Otherwise it is trivial to link them, which may reduce privacy. Hidden
  services created automatically (as in section 3) always have only one port
  open.

5. Tor v3 Address Format
------------------------

Tor v3 onion addresses are 56 characters long (not counting the `.onion` suffix)
and look like this:

	pg6mmjiez2xzmp52wdi23y2npsmvmxymdqk4apnbw3gkvxjj3b6xgpad.onion

The older Tor v2 addresses (16 characters) are no longer supported. If you have
an old `onion_private_key` file from a previous installation, it will not work
with the updated software. A new Tor v3 address will be automatically generated.
