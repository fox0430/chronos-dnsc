# (c) Copyright 2024 Shuhei Nogawa
# This software is released under the MIT License, see LICENSE.
#
# Copyright (c) 2020 rockcavera
# https://github.com/rockcavera/nim-ndns/blob/main/LICENSE

import std/[nativesockets, sysrand]

import
  pkg/[
    chronos,
    chronos/transports/common,
    chronos/osdefs,
    chronos/apps/http/httpcommon,
    dnsprotocol,
    stew/endians2,
  ]

export chronos, dnsprotocol, Port

when defined(nimdoc):
  import ./dnsc/platforms/winapi
  import ./dnsc/platforms/resolv except getSystemDnsServer
else:
  when defined(linux) or defined(bsd) or defined(dnscUseResolver):
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

  DnsResponseError* = object of CatchableError
    ## Raised if the DNS response contains an error (rcode != NoError).
    rcode*: RCode

const
  ipv4Arpa = "in-addr.arpa" ## Special domain reserved for reverse IP lookup for IPv4
  ipv6Arpa = "ip6.arpa" ## Special domain reserved for IP reverse query for IPv6
  dnscDnsServerIp* {.strdefine.} = "8.8.8.8"
    ## Default dns server ip for queries. You can change by compiling with
    ## `-d:dnscDnsServerIp=1.1.1.1`.
  dnscDnsServerIpDomain =
    case parseIpAddress(dnscDnsServerIp).family
    of IpAddressFamily.IPv6: Domain.AF_INET6
    of IpAddressFamily.IPv4: Domain.AF_INET
  dnscClient =
    DnsClient(ip: dnscDnsServerIp, port: Port(53), domain: dnscDnsServerIpDomain)

proc initDnsClient*(strIp: string = dnscDnsServerIp, port: Port = Port(53)): DnsClient =
  ## Returns a created `DnsClient` object.
  ##
  ## **Parameters**
  ## - `ip` is a DNS server IP. It can be IPv4 or IPv6. It cannot be a domain
  ##   name.
  ## - `port` is a DNS server listening port.
  ##

  let ip = parseIpAddress(strIp)

  result.ip = strIp
  result.port = port

  case ip.family
  of IpAddressFamily.IPv6:
    result.domain = AF_INET6
  of IpAddressFamily.IPv4:
    result.domain = AF_INET

proc initSystemDnsClient*(): DnsClient =
  ## Returns a `DnsClient` object, in which the dns server IP is the first one
  ## used by the system. If it is not possible to determine a dns server IP by
  ## the system, it will be initialized with `dnscDnsServerIp`.
  ##
  ## Currently implemented for:
  ## - `Windows<ndns/platforms/winapi.html>`_
  ## - `Linux<ndns/platforms/resolv.html>`_
  ## - `BSD<ndns/platforms/resolv.html>`_
  ##
  ## Notes:
  ## - If your platform is not listed above and uses a `resolver configuration
  ##   file<ndns/platforms/resolv.html>`_, compile with `-d:dnscUseResolver`.
  ## - It just creates a `DnsClient` object with the IP used by the system. Does
  ##   not use the system's native DNS resolution implementation unless the
  ##   system provides a proxy.
  ## - The `ip` field in the `DnsClient` object does not change automatically if
  ##   the IP used by the system changes.

  when declared(getSystemDnsServer):
    let ipServDns = getSystemDnsServer()

    if ipServDns != "":
      try:
        return initDnsClient(ipServDns, Port(53))
      except ValueError:
        discard

  result = dnscClient

proc getIp*(client: DnsClient): string =
  ## Returns the IP defined in the `client`.
  client.ip

proc getPort*(client: DnsClient): Port =
  ## Returns the port defined in the `client`.
  client.port

proc parseBinMessage(msg: BinMsg): Message =
  {.cast(gcsafe).}:
    {.cast(raises: [CatchableError]).}:
      result = parseMessage(msg)

proc checkResponse(rBinMsg: string, msg: Message): Message =
  result = parseBinMessage(rBinMsg)

  if result.header.id != msg.header.id:
    raise newException(
      ResponseIdNotEqualError, "The query ID does not match the response ID"
    )

  if result.header.flags.qr != QR.Response:
    raise newException(IsNotAnResponseError, "Not a response (!= QR.Response)")

  if result.header.flags.opcode != msg.header.flags.opcode:
    raise newException(
      OpCodeNotEqualError, "The OpCode is different between the query and the response"
    )

proc toBinTcpMsg(msg: Message): string =
  {.cast(gcsafe).}:
    {.cast(raises: [CatchableError]).}:
      result = toBinMsg(msg, true)

proc toBinMsg(msg: Message): string =
  {.cast(gcsafe).}:
    {.cast(raises: [CatchableError]).}:
      result = toBinMsg(msg, false)

proc dnsTcpQuery*(
    client: DnsClient, msg: Message, timeout: Duration = 5000.milliseconds
): Future[Message] {.async.} =
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

  let
    qBinMsg = toBinTcpMsg(msg)
    address = initTAddress(client.ip, client.port)
    transpFut = connect(address)
    transp =
      if await transpFut.withTimeout(timeout):
        transpFut.read
      else:
        raise newException(IOError, "timeout")

  try:
    if not await transp.write(qBinMsg).withTimeout(timeout):
      raise newException(IOError, "timeout")

    let
      lenRecvFut = transp.read(2)
      lenRecv =
        if await lenRecvFut.withTimeout(timeout):
          lenRecvFut.read
        else:
          raise newException(IOError, "timeout")

    if lenRecv.len < 2:
      raise newException(
        UnexpectedDisconnectionError, "Connection closed while reading message length"
      )

    var
      remainderRecv = int(
        fromBytes(uint16, [uint8(ord(lenRecv[0])), uint8(ord(lenRecv[1]))], bigEndian)
      )
      rBinMsg = newStringOfCap(remainderRecv)

    while remainderRecv > 0:
      let
        recvFut = transp.read(remainderRecv)
        recv =
          if await recvFut.withTimeout(timeout):
            recvFut.read
          else:
            raise newException(IOError, "timeout")

      if recv.len == 0:
        raise newException(UnexpectedDisconnectionError, "Unexpected disconnection")

      rBinMsg.add bytesToString(recv)
      remainderRecv = remainderRecv - recv.len

    result = checkResponse(rBinMsg, msg)
  finally:
    await transp.closeWait

proc dnsQuery*(
    client: DnsClient,
    msg: Message,
    timeout: Duration = 500.milliseconds,
    retransmit = false,
    tcpTimeout: Duration = 5000.milliseconds,
): Future[Message] {.async.} =
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
  ## - `tcpTimeout` is the maximum waiting time for TCP fallback when
  ##   `retransmit` is `true`. Defaults to 5000ms since TCP connections
  ##   typically need more time than UDP.

  let qBinMsg = toBinMsg(msg)

  var receivedDataFuture = newFuture[void]("dnsQuery.receive")
  var remoteAddr: TransportAddress

  proc datagramDataReceived(
      transp: DatagramTransport, raddr: TransportAddress
  ): Future[void] {.async: (raises: []).} =
    remoteAddr = raddr
    if not receivedDataFuture.finished:
      receivedDataFuture.complete()

  let sock = newDatagramTransport(datagramDataReceived)

  let address = initTAddress(client.ip, client.port)

  try:
    if not await sock.sendTo(address, qBinMsg).withTimeout(timeout):
      raise newException(IOError, "timeout")

    let deadline = Moment.now() + timeout

    while true:
      let remaining = deadline - Moment.now()
      if remaining <= ZeroDuration:
        raise newException(IOError, "timeout")

      if not (await receivedDataFuture.withTimeout(remaining)):
        raise newException(IOError, "timeout")

      if remoteAddr.toIpAddress() == address.toIpAddress() and
          remoteAddr.port == address.port:
        let
          rawResponse = sock.getMessage()
          rBinMsg = bytesToString(rawResponse)

        try:
          result = checkResponse(rBinMsg, msg)
        except ResponseIdNotEqualError, IsNotAnResponseError, OpCodeNotEqualError:
          receivedDataFuture = newFuture[void]("dnsQuery.receive")
          continue

        if retransmit and result.header.flags.tc:
          result = await dnsTcpQuery(client, msg, tcpTimeout)
        return

      # Invalid source address, wait for the next packet
      receivedDataFuture = newFuture[void]("dnsQuery.receive")
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

proc randId*(): uint16 =
  ## Returns a `uint16`, randomly generated, to be used as an id.

  var buf: array[2, byte]
  doAssert urandom(buf)
  result = (uint16(buf[0]) shl 8) or uint16(buf[1])

proc resolveIpv4*(
    client: DnsClient, domain: string, timeout: Duration = 500.milliseconds
): Future[seq[string]] {.async.} =
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
    msg = initMessage(
      initHeader(id = randId(), rd = true), @[initQuestion(domain, QType.A, QClass.IN)]
    )
    rmsg = await dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode != RCode.NoError:
    let err = newException(
      DnsResponseError, "DNS query failed with rcode: " & $rmsg.header.flags.rcode
    )
    err.rcode = rmsg.header.flags.rcode
    raise err

  for rr in rmsg.answers:
    if rr.`type` != Type.A or rr.class != Class.IN:
      continue

    let ip =
      IpAddress(family: IpAddressFamily.IPv4, address_v4: RDataA(rr.rdata).address)

    add(result, $ip)

proc resolveIpv6*(
    client: DnsClient, domain: string, timeout: Duration = 500.milliseconds
): Future[seq[string]] {.async.} =
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
    msg = initMessage(
      initHeader(id = randId(), rd = true),
      @[initQuestion(domain, QType.AAAA, QClass.IN)],
    )
    rmsg = await dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode != RCode.NoError:
    let err = newException(
      DnsResponseError, "DNS query failed with rcode: " & $rmsg.header.flags.rcode
    )
    err.rcode = rmsg.header.flags.rcode
    raise err

  for rr in rmsg.answers:
    if rr.`type` != Type.AAAA or rr.class != Class.IN:
      continue

    let ip =
      IpAddress(family: IpAddressFamily.IPv6, address_v6: RDataAAAA(rr.rdata).address)

    add(result, $ip)

proc resolveRDns*(
    client: DnsClient, strIp: string, timeout: Duration = 500.milliseconds
): Future[seq[string]] {.async.} =
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
    msg = initMessage(
      initHeader(id = randId(), rd = true),
      @[initQuestion(prepareRDns(strIp), QType.PTR, QClass.IN)],
    )
    rmsg = await dnsQuery(client, msg, timeout, true)

  if rmsg.header.flags.rcode != RCode.NoError:
    let err = newException(
      DnsResponseError, "DNS query failed with rcode: " & $rmsg.header.flags.rcode
    )
    err.rcode = rmsg.header.flags.rcode
    raise err

  for rr in rmsg.answers:
    if rr.name != msg.questions[0].qname or rr.`type` != Type.PTR or rr.class != Class.IN:
      continue

    add(result, RDataPTR(rr.rdata).ptrdname)

proc resolveDnsBL*(
    client: DnsClient, strIp, dnsbl: string, timeout: Duration = 500.milliseconds
): Future[seq[string]] {.async.} =
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
