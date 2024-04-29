# (c) Copyright 2024 Shuhei Nogawa
# This software is released under the MIT License, see LICENSE.
#
# Copyright (c) 2020 rockcavera
# https://github.com/rockcavera/nim-ndns/blob/main/LICENSE

import std/[nativesockets, random]

import pkg/[chronos,
            chronos/transports/common,
            chronos/osdefs,
            chronos/apps/http/httpcommon,
            dnsprotocol,
            stew/endians2]

export chronos, dnsprotocol, Port

when defined(nimdoc):
  import ./dnsc/platforms/winapi
  import ./dnsc/platforms/resolv except getSystemDnsServer
else:
  when defined(linux) or defined(bsd) or defined(ndnsUseResolver):
    import ./dnsc/platforms/resolv
  elif defined(windows):
    import ./dnsc/platforms/winapi

type
  DnsClient* = object ## Contains information about the DNS server.
    ip: string ## Dns server IP.
    port: Port ## DNS server listening port.
    domain: Domain

  UnexpectedDisconnectionError* = object of CatchableError
    ## Raised if an unexpected disconnect occurs (only TCP).
  ResponseIpNotEqualError* = object of CatchableError
    ## Raised if the IP that sent the response is different from the IP that
    ## received the query (only UDP).
  ResponsePortNotEqualError* = object of CatchableError
    ## Raised if the Port that sent the response is different from the Port that
    ## received the query (only UDP).
  ResponseIdNotEqualError* = object of CatchableError
    ## Raised if the query ID does not match the response ID.
  IsNotAnResponseError* = object of CatchableError
    ## Raised if not a response (!= QR.Response).
  OpCodeNotEqualError* = object of CatchableError
    ## Raised if the OpCode is different between the query and the response.

const
  ipv4Arpa = "in-addr.arpa"
    ## Special domain reserved for reverse IP lookup for IPv4
  ipv6Arpa = "ip6.arpa"
    ## Special domain reserved for IP reverse query for IPv6
  ndnsDnsServerIp* {.strdefine.} = "8.8.8.8"
    ## Default dns server ip for queries. You can change by compiling with
    ## `-d:ndnsDnsServerIp=1.1.1.1`.
  defaultIpDns* {.deprecated: "Use `ndnsDnsServerIp`".} = ndnsDnsServerIp
    ## Kept only for compatibility reasons.
  ndnsDnsServerIpDomain = case parseIpAddress(ndnsDnsServerIp).family
                          of IpAddressFamily.IPv6: Domain.AF_INET6
                          of IpAddressFamily.IPv4: Domain.AF_INET
  ndnsClient = DnsClient(ip: ndnsDnsServerIp, port: Port(53), domain: ndnsDnsServerIpDomain)

randomize()

proc initDnsClient(strIp: string, port: Port, raiseExceptions: static[bool]): DnsClient =
  when raiseExceptions:
    let ip = parseIpAddress(strIp)

    result.ip = strIp
    result.port = port

    case ip.family
    of IpAddressFamily.IPv6:
      result.domain = AF_INET6
    of IpAddressFamily.IPv4:
      result.domain = AF_INET
  else:
    try:
      let ip = parseIpAddress(strIp)

      result.ip = strIp
      result.port = port

      case ip.family
      of IpAddressFamily.IPv6:
        result.domain = AF_INET6
      of IpAddressFamily.IPv4:
        result.domain = AF_INET
    except ValueError:
      result = ndnsClient

proc initDnsClient*(strIp: string = ndnsDnsServerIp, port: Port = Port(53)): DnsClient =
  ## Returns a created `DnsClient` object.
  ##
  ## **Parameters**
  ## - `ip` is a DNS server IP. It can be IPv4 or IPv6. It cannot be a domain
  ##   name.
  ## - `port` is a DNS server listening port.
  ##

  initDnsClient(strIp, port, true)

proc initSystemDnsClient*(): DnsClient =
  ## Returns a `DnsClient` object, in which the dns server IP is the first one
  ## used by the system. If it is not possible to determine a dns server IP by
  ## the system, it will be initialized with `ndnsDnsServerIp`.
  ##
  ## Currently implemented for:
  ## - `Windows<ndns/platforms/winapi.html>`_
  ## - `Linux<ndns/platforms/resolv.html>`_
  ## - `BSD<ndns/platforms/resolv.html>`_
  ##
  ## Notes:
  ## - If your platform is not listed above and uses a `resolver configuration
  ##   file<ndns/platforms/resolv.html>`_, compile with `-d:ndnsUseResolver`.
  ## - It just creates a `DnsClient` object with the IP used by the system. Does
  ##   not use the system's native DNS resolution implementation unless the
  ##   system provides a proxy.
  ## - The `ip` field in the `DnsClient` object does not change automatically if
  ##   the IP used by the system changes.

  when declared(getSystemDnsServer):
    let ipServDns = getSystemDnsServer()

    if ipServDns == "":
      result = ndnsClient
    else:
      result = initDnsClient(ipServDns, Port(53), false)
  else:
    result = ndnsClient

proc getIp*(client: DnsClient): string =
  ## Returns the IP defined in the `client`.
  client.ip

proc getPort*(client: DnsClient): Port =
  ## Returns the port defined in the `client`.
  client.port

proc parseBinMessage(msg: BinMsg): Message =
  try:
    {.cast(gcsafe).}:
      result = parseMessage(msg)
  except:
    result = Message()

template checkResponse() =
  result = parseBinMessage(rBinMsg)

  if result.header.id != msg.header.id:
    raise newException(ResponseIdNotEqualError,
                       "The query ID does not match the response ID")

  if result.header.flags.qr != QR.Response:
    raise newException(IsNotAnResponseError, "Not a response (!= QR.Response)")

  if result.header.flags.opcode != msg.header.flags.opcode:
    raise newException(OpCodeNotEqualError,
                       "The OpCode is different between the query and the response")

proc toBinTcpMsg(msg: Message): string =
  try:
    {.cast(gcsafe).}:
      result = toBinMsg(msg, true)
  except:
    result = ""

proc toBinMsg(msg: Message): string =
  try:
    {.cast(gcsafe).}:
      result = toBinMsg(msg, false)
  except:
    result = ""

proc dnsTcpQuery*(client: DnsClient,
                  msg: Message,
                  timeout: Duration = 5000.milliseconds): Future[Message] {.async.} =
  ## Returns a `Message` of the DNS query response performed using the TCP
  ## protocol
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `msg` is a `Message` object that contains the DNS query.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server. When it is negative (less than 0), it will try to connect for
  ##   an unlimited time.

  let qBinMsg = toBinTcpMsg(msg)
  if qBinMsg.len == 0:
    raise newException(ValueError, "toBinTcpMsg failed")

  let
    address = initTAddress(client.ip, client.port)
    transpFut = connect(address)
    transp =
      if await transpFut.withTimeout(timeout): transpFut.read
      else: raise newException(IOError, "timeout")

  try:
    if not await transp.write($qBinMsg).withTimeout(timeout):
      raise newException(IOError, "timeout")

    let
      lenRecvFut = transp.read(2)
      lenRecv =
        if await lenRecvFut.withTimeout(timeout): lenRecvFut.read
        else: raise newException(IOError, "timeout")

    var
      remaiderRecv = int(fromBytes(uint16,
                                   [uint8(ord(lenRecv[0])),
                                   uint8(ord(lenRecv[1]))],
                                   bigEndian))
      rBinMsg = newStringOfCap(remaiderRecv)

    let
      recvFut = transp.read
      recv =
        if await recvFut.withTimeout(timeout): recvFut.read
        else: raise newException(IOError, "timeout")
      recvMsg = bytesToString(recv)

    rBinMsg.add recvMsg

    remaiderRecv = remaiderRecv - recv.len

    checkResponse()
  finally:
    await transp.closeWait

proc dnsQuery*(client: DnsClient,
               msg: Message,
               timeout: Duration = 500.milliseconds,
               retransmit = false): Future[Message] {.async.} =
  ## Returns a `Message` of the DNS query response performed using the UDP
  ## protocol.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `msg` is a `Message` object that contains the DNS query.
  ## - `timeout` is the maximum waiting time, in milliseconds, to receive the
  ##   response from the DNS server. When it is negative (less than 0), it will
  ##   try to receive the response for an unlimited time.
  ## - `retransmit` when `true`, determine the retransmission of the query to
  ##   TCP protocol when the received response is truncated
  ##   (`header.flags.tc == true`).

  let qBinMsg = toBinMsg(msg)
  if qBinMsg.len == 0:
    raise newException(ValueError, "toBinMsg failed")

  let receivedDataFuture = newFuture[void]()

  proc datagramDataReceived(transp: DatagramTransport,
                            raddr: TransportAddress): Future[void] {.
                            async: (raises: []).} =
    receivedDataFuture.complete()

  let sock = newDatagramTransport(datagramDataReceived)

  let address = initTAddress(client.ip, client.port)

  try:
    if not await sock.sendTo(address, qBinMsg).withTimeout(timeout):
      raise newException(IOError, "timeout")

    if not (await receivedDataFuture.withTimeout(timeout)):
      raise newException(IOError, "timeout")

    let
      rawResponse = sock.getMessage
      rBinMsg = bytesToString(rawResponse)

    checkResponse()
  finally:
    await sock.closeWait

template domainNameRDns(strIp, domainV4, domainV6: string) =
  let ip = parseIpAddress(strIp)

  case ip.family
  of IpAddressFamily.IPv4:
    # 15 characters for IPv4 +
    # 1 character for the dot of connection between IPv4 and `domainV4` +
    # `len(domainV4)`
    result = newStringOfCap(16 + len(domainV4))

    for i in countdown(3, 0):
      result.add($ip.address_v4[i])
      result.add('.')

    result.add(domainV4)
  of IpAddressFamily.IPv6:
    const hexDigits = "0123456789ABCDEF"
    # 63 characters for IPv6 +
    # 1 character for the dot of connection between IPv6 and `domainV6` +
    # `len(domainV6)`

    result = newStringOfCap(64 + len(domainV6))

    for i in countdown(15, 0):
      let
        hi = (ip.address_v6[i] shr 4) and 0xF
        lo = ip.address_v6[i] and 0xF

      add(result, hexDigits[lo])
      add(result, '.')
      add(result, hexDigits[hi])
      add(result, '.')

    result.add(domainV6)

proc prepareRDns*(strIp: string): string =
  ## Returns a domain name for reverse DNS lookup.
  ##
  ## **Parameters**
  ## - `ip` is the IP address you want to query. It can be an IPv4 or IPv6. It
  ##   cannot be a domain name.

  domainNameRDns(strIp, ipv4Arpa, ipv6Arpa)

proc prepareDnsBL*(strIp, dnsbl: string): string =
  ## Returns a domain name for DnsBL query.
  ##
  ## **Parameters**
  ## - `ip` is the IP address you want to query. It can be an IPv4 or IPv6. It
  ##   cannot be a domain name.
  ## - `dnsbl` is the domain name that maintains the blacklist.

  domainNameRDns(strIp, dnsbl, dnsbl)

proc randId*(): uint16 {.inline.} =
  ## Returns a `uint16`, randomly generated, to be used as an id.

  rand(1 .. 65535).uint16

proc resolveIpv4*(client: DnsClient,
                  domain: string,
                  timeout: Duration = 500.milliseconds): Future[seq[string]] {.async.} =
  ## Returns all IPv4 addresses, in a `seq[string]`, that have been resolved
  ## from `domain`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `domain` is the domain name that you wish to obtain IPv4 addresses.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.

  let
    msg = initMessage(initHeader(id = randId(), rd = true),
                      @[initQuestion(domain, QType.A, QClass.IN)])
    rmsg = await dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode == RCode.NoError:
    for rr in rmsg.answers:
      if rr.name != msg.questions[0].qname or rr.`type` != Type.A or
        rr.class != Class.IN: continue

      let ip = IpAddress(family: IpAddressFamily.IPv4,
                         address_v4: RDataA(rr.rdata).address)

      add(result, $ip)

proc resolveIpv6*(client: DnsClient,
                  domain: string,
                  timeout: Duration = 500.milliseconds): Future[seq[string]] {.async.} =
  ## Returns all IPv6 addresses, in a `seq[string]`, that have been resolved
  ## from `domain`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `domain` is the domain name that you wish to obtain IPv6 addresses.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.

  let
    msg = initMessage(initHeader(id = randId(), rd = true),
                      @[initQuestion(domain, QType.AAAA, QClass.IN)])
    rmsg = await dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode == RCode.NoError:
    for rr in rmsg.answers:
      if rr.name != msg.questions[0].qname or rr.`type` != Type.AAAA or
        rr.class != Class.IN: continue

      let ip = IpAddress(family: IpAddressFamily.IPv6,
                         address_v6: RDataAAAA(rr.rdata).address)

      add(result, $ip)

proc resolveRDns*(client: DnsClient,
                  strIp: string,
                  timeout: Duration = 500.milliseconds): Future[seq[string]] {.async.} =
  ## Returns all domain names, in a `seq[string]`, which is obtained by the
  ## "reverse" query of `ip`. The `seq[string]` can be empty.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `ip` is the IPv4 or IPv6 address that is intended to obtain the domain
  ##   name, which represents the reverse address.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.

  let
    msg = initMessage(initHeader(id = randId(), rd = true),
                      @[initQuestion(prepareRDns(strIp), QType.PTR, QClass.IN)])
    rmsg = await dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode == RCode.NoError:
    for rr in rmsg.answers:
      if rr.name != msg.questions[0].qname or rr.`type` != Type.PTR or
        rr.class != Class.IN: continue

      add(result, RDataPTR(rr.rdata).ptrdname)

proc resolveDnsBL*(client: DnsClient,
                   strIp, dnsbl: string,
                   timeout: Duration = 500.milliseconds): Future[seq[string]] {.async.} =
  ## Returns IPv4 addresses. Usually the loopback address (127.0.0.0/24), in
  ## which the last octet of IPv4 represents something on the black list.
  ##
  ## **Parameters**
  ## - `client` is a `DnsClient` object that contains the IP and Port of the DNS
  ##   server.
  ## - `ip` is the IPv4 or IPv6 address that you want to know if it is
  ##   blacklisted.
  ## - `dnsbl` is the domain name for DnsBL queries.
  ## - `timeout` is the maximum waiting time, in milliseconds, to connect to the
  ##   DNS server or to receive the response from the DNS server. When it is
  ##   negative (less than 0), it will try to connect for an unlimited time or
  ##   to receive the response for an unlimited time.

  result = await resolveIpv4(client, prepareDnsBL(strIp, dnsbl))
