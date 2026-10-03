(function (root) {
  function parseIp(s) {
    if (typeof s !== 'string') return null;
    var p = s.trim().split('.'); if (p.length !== 4) return null;
    var v = 0;
    for (var i = 0; i < 4; i++) {
      if (!/^(0|[1-9]\d{0,2})$/.test(p[i])) return null;
      var o = parseInt(p[i], 10); if (o > 255) return null;
      v = v * 256 + o;
    }
    return v;
  }
  function ipStr(v) { return [Math.floor(v / 16777216) % 256, Math.floor(v / 65536) % 256, Math.floor(v / 256) % 256, v % 256].join('.'); }
  function maskOf(n) { return n === 0 ? 0 : (0xFFFFFFFF << (32 - n)) >>> 0; }
  function prefixFromMask(v) {
    var n = 0, seen0 = false;
    for (var i = 31; i >= 0; i--) { var bit = (v >>> i) & 1; if (bit) { if (seen0) return null; n++; } else seen0 = true; }
    return n;
  }
  // "10.0.0.0/24", "10.0.0.5" (as /32) or "10.0.0.0 255.255.255.0"
  function parseCidr(s) {
    if (typeof s !== 'string' || s.trim() === '') return { error: 'Enter an address like 192.168.1.0/24.' };
    var t = s.trim(), ip, n;
    if (t.indexOf('/') >= 0) {
      var p = t.split('/'); if (p.length !== 2) return { error: 'Use one "/" followed by the prefix length.' };
      ip = parseIp(p[0]); if (ip === null) return { error: 'The address must be four numbers from 0 to 255 with no leading zeros.' };
      if (!/^\d{1,2}$/.test(p[1]) || parseInt(p[1], 10) > 32) return { error: 'The prefix length must be 0 to 32.' };
      n = parseInt(p[1], 10);
    } else if (/\s/.test(t)) {
      var q = t.split(/\s+/); if (q.length !== 2) return { error: 'Use address/prefix or address and mask.' };
      ip = parseIp(q[0]); var m = parseIp(q[1]);
      if (ip === null || m === null) return { error: 'The address and mask must be four numbers from 0 to 255 with no leading zeros.' };
      n = prefixFromMask(m); if (n === null) return { error: 'That is not a valid subnet mask (ones must come first).' };
    } else {
      ip = parseIp(t); if (ip === null) return { error: 'The address must be four numbers from 0 to 255 with no leading zeros.' };
      n = 32;
    }
    return { ip: ip, prefix: n };
  }
  var SPECIAL = [
    ['10.0.0.0', 8, 'Private (RFC 1918)'], ['172.16.0.0', 12, 'Private (RFC 1918)'], ['192.168.0.0', 16, 'Private (RFC 1918)'],
    ['100.64.0.0', 10, 'Shared address space for carrier-grade NAT (RFC 6598)'], ['127.0.0.0', 8, 'Loopback'],
    ['169.254.0.0', 16, 'Link-local (RFC 3927)'], ['224.0.0.0', 4, 'Multicast'], ['0.0.0.0', 8, '"This network"'], ['240.0.0.0', 4, 'Reserved']
  ];
  function classify(ip) {
    if (ip === 0xFFFFFFFF) return 'Limited broadcast';
    for (var i = 0; i < SPECIAL.length; i++) { var b = parseIp(SPECIAL[i][0]), m = maskOf(SPECIAL[i][1]); if (((ip & m) >>> 0) === b) return SPECIAL[i][2]; }
    return 'Public (not in a reserved range listed here)';
  }
  function info(c) {
    var n = c.prefix, m = maskOf(n), net = (c.ip & m) >>> 0, size = Math.pow(2, 32 - n), last = net + size - 1;
    var r = { prefix: n, mask: ipStr(m), wildcard: ipStr((~m) >>> 0), network: ipStr(net), last: ipStr(last), size: size, hostBits: (c.ip & ~m) >>> 0 !== 0, given: ipStr(c.ip) };
    if (n === 32) { r.first = r.network; r.broadcast = null; r.usable = 1; r.note = 'A single host (/32).'; r.last = r.network; }
    else if (n === 31) { r.first = r.network; r.broadcast = null; r.usable = 2; r.last = ipStr(last); r.note = 'Point-to-point link: both addresses are usable hosts (RFC 3021).'; }
    else { r.broadcast = ipStr(last); r.first = ipStr(net + 1); r.last = ipStr(last - 1); r.usable = size - 2; r.note = ''; }
    r.type = classify(net);
    return r;
  }
  function contains(c, ip) { var m = maskOf(c.prefix); return ((ip & m) >>> 0) === ((c.ip & m) >>> 0); }
  function split(c, newPrefix, limit) {
    if (!(newPrefix >= c.prefix && newPrefix <= 32) || newPrefix !== Math.floor(newPrefix)) return null;
    var m = maskOf(c.prefix), net = (c.ip & m) >>> 0, count = Math.pow(2, newPrefix - c.prefix), step = Math.pow(2, 32 - newPrefix), out = [];
    for (var i = 0; i < Math.min(count, limit || 64); i++) out.push(ipStr(net + i * step) + '/' + newPrefix);
    return { count: count, shown: out };
  }
  // smallest prefix that fits this many hosts (usable)
  function prefixForHosts(h) {
    if (!(h >= 1) || h !== Math.floor(h) || h > 4294967294) return null;
    if (h === 1) return 32; if (h === 2) return 31;
    for (var n = 30; n >= 0; n--) if (Math.pow(2, 32 - n) - 2 >= h) return n;
    return null;
  }
  var api = { parseIp: parseIp, ipStr: ipStr, parseCidr: parseCidr, info: info, contains: contains, split: split, classify: classify, prefixForHosts: prefixForHosts, maskOf: maskOf };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.SubnetSense = api;
})(typeof window !== 'undefined' ? window : this);
