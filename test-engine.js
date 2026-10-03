var S = require('./engine.js'), fails = 0, n = 0;
function eq(a, b, m) { n++; if (JSON.stringify(a) !== JSON.stringify(b)) { fails++; console.log('FAIL', m, JSON.stringify(a), JSON.stringify(b)); } }
function I(s) { return S.info(S.parseCidr(s)); }
// RFC 1918 ranges
var r = I('10.0.0.0/8'); eq(r.network, '10.0.0.0', '10/8 net'); eq(r.last, '10.255.255.254', '10/8 last usable'); eq(r.broadcast, '10.255.255.255', '10/8 bcast'); eq(r.size, 16777216, '10/8 size'); eq(r.usable, 16777214, '10/8 usable'); eq(r.type, 'Private (RFC 1918)', '10/8 type');
r = I('172.16.0.0/12'); eq(r.broadcast, '172.31.255.255', '172.16/12 end'); eq(r.mask, '255.240.0.0', '/12 mask'); eq(r.type, 'Private (RFC 1918)', '172.16 type');
r = I('192.168.0.0/16'); eq(r.broadcast, '192.168.255.255', '192.168/16 end'); eq(r.type, 'Private (RFC 1918)', '192.168 type'); eq(r.mask, '255.255.0.0', '/16 mask');
eq(S.classify(S.parseIp('172.15.255.255')), 'Public (not in a reserved range listed here)', '172.15 public'); eq(S.classify(S.parseIp('172.32.0.0')), 'Public (not in a reserved range listed here)', '172.32 public'); eq(S.classify(S.parseIp('172.20.1.1')), 'Private (RFC 1918)', '172.20 private');
// RFC 6598, 3927
eq(S.classify(S.parseIp('100.64.0.1')), 'Shared address space for carrier-grade NAT (RFC 6598)', 'cgnat'); eq(S.classify(S.parseIp('100.127.255.255')), 'Shared address space for carrier-grade NAT (RFC 6598)', 'cgnat end'); eq(S.classify(S.parseIp('100.128.0.0')), 'Public (not in a reserved range listed here)', 'after cgnat');
eq(S.classify(S.parseIp('169.254.10.1')), 'Link-local (RFC 3927)', 'link-local'); eq(S.classify(S.parseIp('127.0.0.1')), 'Loopback', 'loopback'); eq(S.classify(S.parseIp('224.0.0.1')), 'Multicast', 'multicast'); eq(S.classify(S.parseIp('255.255.255.255')), 'Limited broadcast', 'bcast'); eq(S.classify(S.parseIp('8.8.8.8')), 'Public (not in a reserved range listed here)', 'public');
// /24 classic
r = I('192.168.1.0/24'); eq([r.mask, r.wildcard, r.first, r.last, r.broadcast, r.usable, r.size], ['255.255.255.0', '0.0.0.255', '192.168.1.1', '192.168.1.254', '192.168.1.255', 254, 256], '/24');
r = I('192.168.1.77/24'); eq(r.network, '192.168.1.0', 'host bits normalised'); eq(r.hostBits, true, 'host bits flag'); eq(I('192.168.1.0/24').hostBits, false, 'no host bits');
// RFC 3021 /31, /32, /30
r = I('10.0.0.0/31'); eq([r.usable, r.first, r.last, r.broadcast], [2, '10.0.0.0', '10.0.0.1', null], '/31'); eq(/RFC 3021/.test(r.note), true, '/31 note');
r = I('10.0.0.5/32'); eq([r.usable, r.first, r.last, r.size], [1, '10.0.0.5', '10.0.0.5', 1], '/32');
r = I('10.0.0.0/30'); eq([r.usable, r.first, r.last, r.broadcast], [2, '10.0.0.1', '10.0.0.2', '10.0.0.3'], '/30');
r = I('0.0.0.0/0'); eq([r.size, r.broadcast, r.mask], [4294967296, '255.255.255.255', '0.0.0.0'], '/0');
eq(I('10.1.2.3').prefix, 32, 'bare ip is /32');
// mask form
eq(S.parseCidr('192.168.1.0 255.255.255.0').prefix, 24, 'mask form'); eq(S.parseCidr('10.0.0.0 255.0.255.0').error !== undefined, true, 'non-contiguous mask'); eq(S.parseCidr('10.0.0.0 255.255.252.0').prefix, 22, 'mask /22'); eq(I('10.0.0.0/22').mask, '255.255.252.0', '/22 mask'); eq(I('10.0.0.0/22').wildcard, '0.0.3.255', '/22 wildcard');
// errors
['', 'abc', '256.1.1.1/24', '1.2.3/24', '1.2.3.4/33', '1.2.3.4/-1', '1.2.3.4//24', '01.2.3.4/24', '1.2.3.4/', '1.2.3.4/a', '1.2.3.4 1.2.3', '1.2.3.4.5'].forEach(function (e) { eq(S.parseCidr(e).error !== undefined, true, 'error: ' + e); });
// contains
var c = S.parseCidr('192.168.1.0/24');
eq(S.contains(c, S.parseIp('192.168.1.200')), true, 'in'); eq(S.contains(c, S.parseIp('192.168.2.1')), false, 'out'); eq(S.contains(c, S.parseIp('192.168.1.255')), true, 'broadcast is in range'); eq(S.contains(S.parseCidr('0.0.0.0/0'), S.parseIp('8.8.8.8')), true, 'default route');
eq(S.contains(S.parseCidr('10.0.0.8/29'), S.parseIp('10.0.0.15')), true, '/29 end'); eq(S.contains(S.parseCidr('10.0.0.8/29'), S.parseIp('10.0.0.16')), false, '/29 past');
// split
var sp = S.split(S.parseCidr('192.168.0.0/24'), 26); eq(sp.count, 4, 'split count'); eq(sp.shown, ['192.168.0.0/26', '192.168.0.64/26', '192.168.0.128/26', '192.168.0.192/26'], 'split list');
eq(S.split(S.parseCidr('10.0.0.0/8'), 16).count, 256, '/8 into /16'); eq(S.split(S.parseCidr('10.0.0.0/8'), 16).shown.length, 64, 'limit 64'); eq(S.split(S.parseCidr('10.0.0.0/24'), 23), null, 'cannot merge'); eq(S.split(S.parseCidr('10.0.0.0/24'), 24).count, 1, 'same prefix');
eq(S.split(S.parseCidr('10.0.0.0/24'), 33), null, 'bad new prefix'); eq(S.split(S.parseCidr('10.0.0.77/24'), 25).shown[0], '10.0.0.0/25', 'split normalises');
eq(S.split(S.parseCidr('10.0.0.0/30'), 32).shown, ['10.0.0.0/32', '10.0.0.1/32', '10.0.0.2/32', '10.0.0.3/32'], 'split to /32');
// hosts to prefix
eq(S.prefixForHosts(254), 24, '254 hosts'); eq(S.prefixForHosts(255), 23, '255 hosts'); eq(S.prefixForHosts(500), 23, '500 hosts'); eq(S.prefixForHosts(2), 31, '2 hosts'); eq(S.prefixForHosts(1), 32, '1 host'); eq(S.prefixForHosts(3), 29 + 0 === 29 ? 29 : 0, '3 hosts needs /29');
eq(S.prefixForHosts(6), 29, '6 hosts'); eq(S.prefixForHosts(7), 28, '7 hosts'); eq(S.prefixForHosts(0), null, '0 hosts'); eq(S.prefixForHosts(4294967294), 0, 'max hosts'); eq(S.prefixForHosts(4294967295), null, 'too many');
eq(S.ipStr(S.parseIp('1.2.3.4')), '1.2.3.4', 'roundtrip'); eq(S.parseIp('0.0.0.0'), 0, 'zero ip'); eq(S.parseIp('255.255.255.255'), 4294967295, 'max ip');
console.log(n - fails + '/' + n + ' pass'); process.exit(fails ? 1 : 0);
