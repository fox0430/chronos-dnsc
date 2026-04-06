## Copyright (c) 2020 rockcavera
## https://github.com/rockcavera/nim-ndns/blob/main/LICENSE
##
## Minimal implementation to get System DNS Server (IPv4 and IPv6). This implementation is heavily
## influenced by glibc.
##
## Implements a parser for the resolver configuration file, which is, by default, /etc/resolv.conf.
## You can change this file by passing to compile `-d:dnscPathResConf=/etc/myresolv.conf`.
##
## Checking for changes in the `dnscPathResConf` file performed at each new call makes the code 2x
## faster, if there is no change.
##
## This implementation should work for systems that adopt resolver. Currently this implementation is
## imported into Linux and BSD. If your platform uses a resolver configuration file, compile with
## `-d:dnscUseResolver`.
##
## References:
## - https://man7.org/linux/man-pages/man5/resolv.conf.5.html
import std/[net, os, parseutils, strutils, times]

const
  dnscPathResConf* {.strdefine.} = "/etc/resolv.conf"
    ## Resolver configuration file. You can change by compiling with
    ## `-d:dnscPathResConf=/etc/myresolv.conf`.

  MAXNS = 3 ## Maximum number of nameservers
  MAXDNSRCH = 6 ## Maximum number of search domains

type
  FileChangeDetection = object ## Object for `dnscPathResConf` file information.
    fileId: FileId ## Serial ID
    size: BiggestInt ## Size
    lastWriteTime: Time ## Last write time
    creationTime: Time ## Creation time

  ResolvConf* = object ## Parsed resolver configuration.
    nameservers*: seq[string] ## DNS server IPs (up to MAXNS).
    domain*: string ## Local domain name.
    search*: seq[string] ## Search list for hostname lookup (up to MAXDNSRCH).
    ndots*: int
      ## Threshold for number of dots before initial absolute query (default: 1).
    timeout*: int ## Timeout in seconds for queries (default: 5).
    attempts*: int ## Number of query attempts (default: 2).
    rotate*: bool ## Round-robin selection of nameservers.

  ResolvConfGlobal = object ## Object for global resolver information.
    resolvConf: ResolvConf ## Parsed configuration from last parse.
    fileResolvConf: FileChangeDetection
      ## `dnscPathResConf` file information during last parse.
    initialized: bool
      ## Determines whether the `dnscPathResConf` file has already been parsed.

var resolvGlobal {.threadvar.}: ResolvConfGlobal
  ## Keeps information from the `dnscPathResConf` file and if it has already been parsed.

proc isUnchanged(fileInfo: FileInfo): bool =
  ## Returns `true` if the `dnscPathResConf` file has not changed since the last parse.
  result =
    (fileInfo.id.file == resolvGlobal.fileResolvConf.fileId) and
    (fileInfo.size == resolvGlobal.fileResolvConf.size) and
    (fileInfo.creationTime == resolvGlobal.fileResolvConf.creationTime) and
    (fileInfo.lastWriteTime == resolvGlobal.fileResolvConf.lastWriteTime)

proc initResolvConf*(): ResolvConf =
  ## Returns a ResolvConf with default values.
  result.ndots = 1
  result.timeout = 5
  result.attempts = 2

proc parseIntOption(value: string, minVal: int): int =
  ## Parses an integer option value. Returns the parsed value if valid and >= minVal,
  ## otherwise returns -1.
  try:
    let v = parseInt(value)
    if v >= minVal: v else: -1
  except ValueError:
    -1

proc parseOptions(result: var ResolvConf, line: string, start: int) =
  ## Parses the options directive. Options are space-separated and can be
  ## `key:value` or just `key`.
  var pos = start

  while pos < line.len:
    pos += skipWhitespace(line, pos)
    if pos >= line.len:
      break

    var opt: string
    let count =
      parseUntil(line, opt, {' ', '\t', '\v', '\r', '\n', '\f', ';', '#'}, pos)
    if count == 0:
      break
    pos += count

    let colonIdx = opt.find(':')
    if colonIdx >= 0:
      let
        key = opt[0 ..< colonIdx]
        value = opt[colonIdx + 1 .. ^1]
      case key
      of "ndots":
        let v = parseIntOption(value, 0)
        if v >= 0:
          result.ndots = v
      of "timeout":
        let v = parseIntOption(value, 1)
        if v >= 0:
          result.timeout = v
      of "attempts":
        let v = parseIntOption(value, 1)
        if v >= 0:
          result.attempts = v
      else:
        discard
    else:
      case opt
      of "rotate":
        result.rotate = true
      else:
        discard

proc parseResolvConf*(content: string): ResolvConf =
  ## Parses resolv.conf content and returns a ResolvConf.
  ##
  ## Parses the following directives:
  ## - `nameserver` (up to 3)
  ## - `domain`
  ## - `search` (up to 6 domains)
  ## - `options` (ndots, timeout, attempts, rotate)
  ##
  ## `domain` and `search` are mutually exclusive; the last one in the file takes effect.
  const
    comments = {';', '#'}
    whiteSpaces = {' ', '\t', '\v', '\r', '\n', '\f'}
    commentsAndWhiteSpaces = comments + whiteSpaces

  result = initResolvConf()

  for line in content.splitLines():
    if line == "":
      continue
    if line[0] in comments:
      continue

    var strConf: string
    let count = parseUntil(line, strConf, whiteSpaces)

    if count > 0:
      let valueStart = count + skipWhitespace(line, count)
      case strConf
      of "nameserver":
        if result.nameservers.len < MAXNS:
          var ns: string
          if parseUntil(line, ns, commentsAndWhiteSpaces, valueStart) > 0:
            try:
              discard parseIpAddress(ns)
              result.nameservers.add(ns)
            except ValueError:
              discard
      of "domain":
        var dom: string
        if parseUntil(line, dom, commentsAndWhiteSpaces, valueStart) > 0:
          result.domain = dom
          result.search = @[]
      of "search":
        result.search = @[]
        result.domain = ""
        var pos = valueStart
        while pos < line.len and result.search.len < MAXDNSRCH:
          pos += skipWhitespace(line, pos)
          if pos >= line.len or line[pos] in comments:
            break
          var dom: string
          let c = parseUntil(line, dom, commentsAndWhiteSpaces, pos)
          if c > 0:
            result.search.add(dom)
            pos += c
          else:
            break
      of "options":
        result.parseOptions(line, valueStart)
      else:
        discard

proc getResolvConf*(): ResolvConf =
  ## Returns the parsed resolver configuration from the `dnscPathResConf` file.
  ##
  ## The result is cached based on file metadata (ID, size, timestamps). If the file has not
  ## changed since the last call, the cached result is returned immediately.
  var fileInfo: FileInfo
  try:
    fileInfo = getFileInfo(dnscPathResConf)
  except OSError:
    return initResolvConf()

  if resolvGlobal.initialized and fileInfo.isUnchanged():
    return resolvGlobal.resolvConf

  try:
    result = parseResolvConf(readFile(dnscPathResConf))
  except IOError:
    result = initResolvConf()

  resolvGlobal.resolvConf = result
  resolvGlobal.fileResolvConf.fileId = fileInfo.id.file
  resolvGlobal.fileResolvConf.size = fileInfo.size
  resolvGlobal.fileResolvConf.creationTime = fileInfo.creationTime
  resolvGlobal.fileResolvConf.lastWriteTime = fileInfo.lastWriteTime
  resolvGlobal.initialized = true

proc getSystemDnsServer*(): string =
  ## Returns the first nameserver found in the `dnscPathResConf` file. Will return `""` if not
  ## found.
  ##
  ## The result is cached based on file metadata (ID, size, timestamps). If the file has not
  ## changed since the last call, the cached result is returned immediately. Note that an empty
  ## string result is also cached — if no nameserver is found, subsequent calls will return `""`
  ## until the file changes.
  let conf = getResolvConf()
  if conf.nameservers.len > 0:
    result = conf.nameservers[0]
