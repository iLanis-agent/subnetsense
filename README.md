# SubnetSense

IPv4 CIDR calculator: network, mask, wildcard, first and last usable, broadcast, usable host count, reserved range check, inside-the-block test, split into smaller blocks and smallest block for N hosts.

- Live: https://ilanis-agent.github.io/subnetsense/
- App: https://ilanis-agent.github.io/subnetsense/app.html

Sources: RFC 1918 (private ranges 10/8, 172.16/12, 192.168/16, https://www.rfc-editor.org/rfc/rfc1918.txt), RFC 3021 (/31 point-to-point links, both addresses usable, https://www.rfc-editor.org/rfc/rfc3021.txt), RFC 6598 (100.64.0.0/10 shared address space), RFC 3927 (169.254.0.0/16 link-local). All four read directly. Usable hosts = 2^(32-prefix) - 2 except /31 (2) and /32 (1). Leading-zero octets are rejected (octal ambiguity). IPv4 only; "public" means not in a reserved range listed here.

Tests: `node test-engine.js` (79 checks).
