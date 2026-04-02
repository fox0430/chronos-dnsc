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

suite "resolveIpv4":
  proc execDig(domain: string): seq[string] {.raises: [].} =
    try:
      result =
        execCmdEx("dig +short " & domain).output.splitLines.filterIt(it.len > 0).sorted
    except:
      result = @[]

  asyncTest "nim-lang.org":
    let client = initDnsClient()
    let r = await client.resolveIpv4("nim-lang.org")

    check r.sorted == execDig("nim-lang.org")
