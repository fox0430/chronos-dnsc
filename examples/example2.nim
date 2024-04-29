# Copyright (c) 2020 rockcavera
# https://github.com/rockcavera/nim-ndns/blob/main/LICENSE

import dnsc

let client = initDnsClient()

echo waitFor resolveIpv4(client, "nim-lang.org")
