import std/[algorithm, osproc, sequtils, strutils]

import pkg/chronos/unittest2/asynctests

import dnsc {.all.}

suite "dnsQuery":
  asyncTest "nim-lang.org":
    let
      header = initHeader(randId(), rd = true)
      question = initQuestion("nim-lang.org", QType.A, QClass.IN)
      msg = initMessage(header, @[question])

    let client = initDnsClient()
    let r = await client.dnsQuery(msg)

    check r.header.flags ==
      Flags(
        qr: Response,
        opcode: Query,
        aa: false,
        tc: false,
        rd: true,
        ra: true,
        z: 0,
        rcode: NoError,
      )

    check r.header.qdcount == 1
    check r.header.ancount >= 1
    check r.header.nscount == 0
    check r.header.arcount == 0

    check r.questions == @[Question(qname: "nim-lang.org.", qtype: A, qclass: IN)]

    check r.answers[0].name == "nim-lang.org."
    check r.answers[0].`type` == Type.A
    check r.answers[0].class == Class.IN
    check r.answers[0].rdlength == 4

suite "dnsTcpQuery":
  asyncTest "nim-lang.org":
    let
      header = initHeader(randId(), rd = true)
      question = initQuestion("nim-lang.org", QType.A, QClass.IN)
      msg = initMessage(header, @[question])

    let client = initDnsClient()
    let r = await client.dnsTcpQuery(msg)

    check r.header.flags ==
      Flags(
        qr: Response,
        opcode: Query,
        aa: false,
        tc: false,
        rd: true,
        ra: true,
        z: 0,
        rcode: NoError,
      )

    check r.header.qdcount == 1
    check r.header.ancount >= 1
    check r.header.nscount == 0
    check r.header.arcount == 0

    check r.questions == @[Question(qname: "nim-lang.org.", qtype: A, qclass: IN)]

    check r.answers[0].name == "nim-lang.org."
    check r.answers[0].`type` == Type.A
    check r.answers[0].class == Class.IN
    check r.answers[0].rdlength == 4

suite "error cases":
  asyncTest "NXDOMAIN raises DnsResponseError":
    let client = initDnsClient()

    expect DnsResponseError:
      discard await client.resolveIpv4("nonexistent-domain-test-12345.invalid")

  asyncTest "UDP timeout":
    # Use TEST-NET address (192.0.2.1) which is non-routable and will timeout
    let
      client = initDnsClient("192.0.2.1", Port(53))
      header = initHeader(randId(), rd = true)
      question = initQuestion("example.com", QType.A, QClass.IN)
      msg = initMessage(header, @[question])

    expect IOError:
      discard await client.dnsQuery(msg, timeout = 50.milliseconds)

  asyncTest "TCP connection refused":
    let
      client = initDnsClient("127.0.0.1", Port(1))
      header = initHeader(randId(), rd = true)
      question = initQuestion("example.com", QType.A, QClass.IN)
      msg = initMessage(header, @[question])

    expect CatchableError:
      discard await client.dnsTcpQuery(msg, timeout = 50.milliseconds)

suite "prepareRDns":
  test "IPv4":
    check prepareRDns("192.168.1.1") == "1.1.168.192.in-addr.arpa"

  test "IPv4 with zeros":
    check prepareRDns("0.0.0.0") == "0.0.0.0.in-addr.arpa"

  test "IPv6 loopback":
    check prepareRDns("::1") ==
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"

  test "IPv6 full":
    check prepareRDns("2001:db8::1") ==
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"

suite "prepareDnsBL":
  test "IPv4":
    check prepareDnsBL("192.168.1.1", "zen.spamhaus.org") ==
      "1.1.168.192.zen.spamhaus.org"

suite "randId":
  test "returns different values":
    # Not guaranteed but extremely unlikely to get the same value twice
    var ids: seq[uint16]
    for _ in 0 ..< 10:
      ids.add(randId())
    check ids.len > 1
    # At least some should differ
    var allSame = true
    for i in 1 ..< ids.len:
      if ids[i] != ids[0]:
        allSame = false
        break
    check not allSame

suite "getUpdatedSystemDnsClient":
  test "returns a valid client":
    let client = getUpdatedSystemDnsClient()
    check client.getIp().len > 0
    check client.getPort() == Port(53)

  test "custom port":
    let client = getUpdatedSystemDnsClient(Port(5353))
    check client.getPort() == Port(5353)

  asyncTest "can resolve with returned client":
    let client = getUpdatedSystemDnsClient()
    let r = await client.resolveIpv4("nim-lang.org")
    check r.len >= 1

suite "resolveIpv4":
  proc execDig(domain: string): seq[string] {.raises: [].} =
    try:
      result =
        execCmdEx("dig +short " & domain).output.splitLines.filterIt(it.len > 0).sorted
    except:
      result = @[]

  asyncTest "nim-lang.org":
    let expected = execDig("nim-lang.org")
    if expected.len == 0:
      skip()
    else:
      let client = initDnsClient()
      let r = await client.resolveIpv4("nim-lang.org")

      check r.sorted == expected

suite "resolveIpv6":
  asyncTest "google.com":
    let client = initDnsClient()
    let r = await client.resolveIpv6("google.com")

    check r.len >= 1

  asyncTest "NXDOMAIN raises DnsResponseError":
    let client = initDnsClient()

    expect DnsResponseError:
      discard await client.resolveIpv6("nonexistent-domain-test-12345.invalid")

suite "resolveRDns":
  asyncTest "Google public DNS":
    let client = initDnsClient()
    let r = await client.resolveRDns("8.8.8.8")

    check r.len >= 1
    check "dns.google." in r
