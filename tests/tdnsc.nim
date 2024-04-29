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

    check r.header.flags == Flags(
      qr: Response,
      opcode: Query,
      aa: false,
      tc: false,
      rd: true,
      ra: true,
      z: 0,
      rcode: NoError)

    check r.header.qdcount == 1
    check r.header.ancount == 2
    check r.header.nscount == 0
    check r.header.arcount == 0

    check r.questions == @[
      Question(qname: "nim-lang.org.", qtype: A, qclass: IN)
    ]

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

    check r.header.flags == Flags(
      qr: Response,
      opcode: Query,
      aa: false,
      tc: false,
      rd: true,
      ra: true,
      z: 0,
      rcode: NoError)

    check r.header.qdcount == 1
    check r.header.ancount == 2
    check r.header.nscount == 0
    check r.header.arcount == 0

    check r.questions == @[
      Question(qname: "nim-lang.org.", qtype: A, qclass: IN)
    ]

    check r.answers[0].name == "nim-lang.org."
    check r.answers[0].`type` == Type.A
    check r.answers[0].class == Class.IN
    check r.answers[0].rdlength == 4

suite "resolveIpv4":
  asyncTest "nim-lang.org":
    let client = initDnsClient()
    let r = await client.resolveIpv4("nim-lang.org")

    check r.sorted == execCmdEx("dig +short nim-lang.org")
      .output
      .splitLines
      .filterIt(it.len > 0)
      .sorted
