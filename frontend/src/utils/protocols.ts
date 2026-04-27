/** IANA protocol number → well-known name mapping. */
const PROTOCOL_MAP: Record<number, string> = {
  1:   'ICMP',
  2:   'IGMP',
  6:   'TCP',
  17:  'UDP',
  41:  'IPv6',
  47:  'GRE',
  50:  'ESP',
  51:  'AH',
  58:  'ICMPv6',
  89:  'OSPF',
  103: 'PIM',
  112: 'VRRP',
  132: 'SCTP',
};

/**
 * Convert a raw protocol number to a human-readable name.
 * Falls back to the number as a string if unknown, '—' if null/undefined.
 */
export function protocolName(n: number | null | undefined): string {
  if (n == null) return '—';
  return PROTOCOL_MAP[n] ?? String(n);
}
