## Copyright (c) 2020 rockcavera
## https://github.com/rockcavera/nim-ndns/blob/main/LICENSE
##
## Minimal implementation to get System DNS Server (IPv4 and IPv6)
##
## This implementation uses the winapi function `GetAdaptersAddresses` and
## should work for Windows.
##
## References:
## - https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
## - https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh

const
  AF_UNSPEC = 0'u32
  AF_INET = 2'u32
  AF_INET6 = 23'u32

  GAA_FLAG_SKIP_UNICAST = 0x0001'u32
  GAA_FLAG_SKIP_ANYCAST = 0x0002'u32
  GAA_FLAG_SKIP_MULTICAST = 0x0004'u32

  ERROR_SUCCESS = 0'u32
  ERROR_BUFFER_OVERFLOW = 111'u32

type
  SockAddr {.importc: "struct sockaddr", header: "<winsock2.h>".} = object
    sa_family: uint16

  SockAddrIn {.importc: "struct sockaddr_in", header: "<ws2tcpip.h>".} = object
    sin_family: uint16
    sin_port: uint16
    sin_addr: array[4, uint8]

  SockAddrIn6 {.importc: "struct sockaddr_in6", header: "<ws2tcpip.h>".} = object
    sin6_family: uint16
    sin6_port: uint16
    sin6_flowinfo: uint32
    sin6_addr: array[16, uint8]
    sin6_scope_id: uint32

  SOCKET_ADDRESS {.importc: "SOCKET_ADDRESS", header: "<iptypes.h>".} = object
    lpSockaddr: ptr SockAddr
    iSockaddrLength: cint

  IP_ADAPTER_DNS_SERVER_ADDRESS {.
    importc: "IP_ADAPTER_DNS_SERVER_ADDRESS", header: "<iptypes.h>"
  .} = object
    next: ptr IP_ADAPTER_DNS_SERVER_ADDRESS
    address: SOCKET_ADDRESS

  IP_ADAPTER_ADDRESSES {.importc: "IP_ADAPTER_ADDRESSES", header: "<iptypes.h>".} = object
    next: ptr IP_ADAPTER_ADDRESSES
    firstDnsServerAddress: ptr IP_ADAPTER_DNS_SERVER_ADDRESS

proc getAdaptersAddresses(
  family: uint32,
  flags: uint32,
  reserved: pointer,
  adapterAddresses: pointer,
  sizePointer: ptr uint32,
): uint32 {.importc: "GetAdaptersAddresses", stdcall, dynlib: "Iphlpapi.dll".}

proc ipToString(sa: ptr SockAddr): string =
  ## Convert a sockaddr to an IP address string.
  if sa.sa_family == uint16(AF_INET):
    let addr4 = cast[ptr SockAddrIn](sa)
    result =
      $addr4.sin_addr[0] & "." & $addr4.sin_addr[1] & "." & $addr4.sin_addr[2] & "." &
      $addr4.sin_addr[3]
  elif sa.sa_family == uint16(AF_INET6):
    let addr6 = cast[ptr SockAddrIn6](sa)
    var parts: array[8, uint16]
    for i in 0 .. 7:
      parts[i] =
        (uint16(addr6.sin6_addr[i * 2]) shl 8) or uint16(addr6.sin6_addr[i * 2 + 1])

    # Find the longest run of consecutive zero groups for :: compression
    var bestStart = -1
    var bestLen = 0
    var curStart = -1
    var curLen = 0
    for i in 0 .. 7:
      if parts[i] == 0:
        if curStart == -1:
          curStart = i
          curLen = 1
        else:
          inc curLen
        if curLen > bestLen:
          bestStart = curStart
          bestLen = curLen
      else:
        curStart = -1
        curLen = 0

    const hexDigits = "0123456789abcdef"

    proc addHexGroup(s: var string, v: uint16) =
      if v == 0:
        s.add('0')
      else:
        var started = false
        for shift in countdown(12, 0, 4):
          let nibble = (v shr shift) and 0xF
          if nibble != 0 or started:
            s.add(hexDigits[nibble])
            started = true

    if bestLen >= 2:
      for i in 0 .. 7:
        if i == bestStart:
          result.add(if i == 0: "::" else: ":")
        elif i > bestStart and i < bestStart + bestLen:
          discard
        else:
          if i > 0 and i != bestStart + bestLen:
            result.add(':')
          result.addHexGroup(parts[i])
    else:
      for i in 0 .. 7:
        if i > 0:
          result.add(':')
        result.addHexGroup(parts[i])

proc getSystemDnsServer*(): string =
  ## Returns the first DNS server IP (IPv4 or IPv6) used by the system for DNS
  ## resolution. Otherwise it returns an empty string `""`.
  let flags = GAA_FLAG_SKIP_UNICAST or GAA_FLAG_SKIP_ANYCAST or GAA_FLAG_SKIP_MULTICAST

  var bufLen = 15000'u32
  var buf = cast[ptr IP_ADAPTER_ADDRESSES](alloc0(int(bufLen)))

  if isNil(buf):
    raise newException(
      OSError, "Error allocating memory needed to call GetAdaptersAddresses"
    )

  try:
    var rc = getAdaptersAddresses(AF_UNSPEC, flags, nil, buf, addr bufLen)

    if rc == ERROR_BUFFER_OVERFLOW:
      buf = cast[ptr IP_ADAPTER_ADDRESSES](realloc0(buf, 15000, int(bufLen)))

      if isNil(buf):
        raise newException(
          OSError, "Error allocating memory needed to call GetAdaptersAddresses"
        )

      rc = getAdaptersAddresses(AF_UNSPEC, flags, nil, buf, addr bufLen)

    if rc == ERROR_SUCCESS:
      var adapter = buf
      while not isNil(adapter):
        var dns = adapter.firstDnsServerAddress
        while not isNil(dns):
          let sa = dns.address.lpSockaddr
          if not isNil(sa) and
              (sa.sa_family == uint16(AF_INET) or sa.sa_family == uint16(AF_INET6)):
            return ipToString(sa)
          dns = dns.next
        adapter = adapter.next
  finally:
    if not isNil(buf):
      dealloc(buf)
