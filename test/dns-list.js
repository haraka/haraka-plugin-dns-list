// node.js built-in modules
const assert = require('node:assert')
const { before, describe, it, beforeEach } = require('node:test')

// npm modules
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

let plugin
let connection

// Spamhaus blocks queries from public/cloud DNS resolvers and returns a
// rate-limit code (127.255.255.252/254/255) instead of real data. GitHub-hosted
// macOS runners (Azure infrastructure) are in that bucket and will see the
// block deterministically. Probe once and skip the Spamhaus-dependent tests
// when the network can't reach a real answer.
// https://www.spamhaus.org/news/article/807/using-our-public-mirrors-check-your-return-codes-now
let spamhausReachable = true

before(async () => {
  const probe = makePlugin('index', { register: false })
  probe.load_config()
  await probe.lookup('127.0.0.2', 'xbl.spamhaus.org')
  spamhausReachable = !probe.rate_limited.has('xbl.spamhaus.org')
})

beforeEach(() => {
  plugin = makePlugin('index', { register: false })
  plugin.load_config()
  // plugin.register()
})

// node:test's t.skip() marks the test as skipped but doesn't halt execution,
// so each caller must `if (skipUnlessSpamhaus(t)) return`.
const skipUnlessSpamhaus = (t) => {
  if (spamhausReachable) return false
  t.skip('Spamhaus rate-limits this network')
  return true
}

describe('dns-list', () => {
  it('plugin loads', () => {
    assert.ok(plugin)
  })

  it('loads config/dns-list.ini', () => {
    plugin.load_config()
    assert.ok(plugin.cfg)
  })

  it('config initializes a boolean', () => {
    assert.equal(plugin.cfg.stats.enable, false, plugin.cfg)
    assert.equal(plugin.cfg['ips.backscatterer.org'].enable, false)
  })

  it('sets up a connection', () => {
    connection = makeConnection({})
    assert.ok(connection.server)
  })

  it('sets up a transaction', () => {
    connection = makeConnection({ withTxn: true })
    assert.ok(connection.transaction.header)
  })
})

describe('lookup', () => {
  it('Spamcop, test IPv4', async () => {
    const a = await plugin.lookup('127.0.0.2', 'bl.spamcop.net')
    assert.deepStrictEqual(['127.0.0.2'], a)
  })

  it('Spamcop, unlisted IPv6', async () => {
    const r = await plugin.lookup('::1', 'bl.spamcop.net')
    assert.deepStrictEqual(undefined, r)
  })

  it('b.barracudacentral.org, unlisted IPv6', async () => {
    const r = await plugin.lookup('::1', 'b.barracudacentral.org')
    assert.deepStrictEqual(undefined, r)
  })

  it('Spamcop, unlisted IPv4', async () => {
    const a = await plugin.lookup('127.0.0.1', 'bl.spamcop.net')
    assert.deepStrictEqual(undefined, a)
  })

  it('CBL', { timeout: 3000 }, async (t) => {
    if (skipUnlessSpamhaus(t)) return
    const a = await plugin.lookup('127.0.0.2', 'xbl.spamhaus.org')
    assert.deepStrictEqual(a, ['127.0.0.4'])
  })
})

describe('check_zone', () => {
  it('tests DNS list bl.spamcop.net', async () => {
    const r = await plugin.check_zone('bl.spamcop.net')
    assert.deepStrictEqual(r, true)
  })

  it('tests DNS list zen.spamhaus.org', { timeout: 3000 }, async (t) => {
    if (skipUnlessSpamhaus(t)) return
    const r = await plugin.check_zone('zen.spamhaus.org')
    assert.deepStrictEqual(r, true)
  })

  it(
    'tests DNS list hostkarma.junkemailfilter.com',
    { timeout: 3000 },
    async () => {
      const r = await plugin.check_zone('hostkarma.junkemailfilter.com')
      assert.deepStrictEqual(r, true)
    },
  )
})

describe('check_zones', { timeout: 29000 }, () => {
  it('tests each block list', async () => {
    await plugin.check_zones(8000)
  })
})

describe('onConnect', () => {
  beforeEach(() => {
    connection = makeConnection()
  })

  it('onConnect 127.0.0.1', async () => {
    connection.set('remote.ip', '127.0.0.1')
    plugin.zones = new Set(['bl.spamcop.net', 'list.dnswl.org'])
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, undefined)
    assert.strictEqual(msg, undefined)
  })

  it('onConnect 127.0.0.2', async () => {
    connection.set('remote.ip', '127.0.0.2')
    plugin.zones = new Set(['bl.spamcop.net', 'list.dnswl.org'])
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    if (code === OK) {
      assert.strictEqual(code, OK)
      assert.strictEqual(msg, 'host [127.0.0.2] is listed on list.dnswl.org')
    } else {
      assert.strictEqual(code, DENY)
      assert.strictEqual(msg, 'host [127.0.0.2] is listed on bl.spamcop.net')
    }
  })

  it('Spamcop + CBL', async (t) => {
    if (skipUnlessSpamhaus(t)) return
    connection.set('remote.ip', '127.0.0.2')
    plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, DENY)
    assert.ok(/is listed on/.test(msg))
  })

  it('Spamcop + CBL + negative result', async () => {
    connection.set('remote.ip', '127.0.0.1')
    plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, undefined)
    assert.strictEqual(msg, undefined)
  })

  it('IPv6 addresses supported', async () => {
    connection.set('remote.ip', '::1')
    plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('rate-limited Spamhaus zone records skip:rate_limited', async (t) => {
    if (spamhausReachable) {
      t.skip('only runs when Spamhaus rate-limits us')
      return
    }
    connection.set('remote.ip', '127.0.0.2')
    plugin.zones = new Set(['xbl.spamhaus.org'])
    const { rc: code } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, undefined)
    assert.ok(
      connection.results.get(plugin).skip.some((s) => /^rate_limited:/.test(s)),
      'expected skip:rate_limited: result',
    )
  })
})

describe('first', () => {
  beforeEach(() => {
    plugin.cfg.main.search = 'first'
    plugin.zones = new Set(['xbl.spamhaus.org', 'bl.spamcop.net'])
    connection = makeConnection()
  })

  it('positive result', async (t) => {
    if (skipUnlessSpamhaus(t)) return
    connection.set('remote.ip', '127.0.0.2')
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, DENY)
    assert.ok(/is listed on/.test(msg))
  })

  it('negative result', async () => {
    connection.set('remote.ip', '127.0.0.1')
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, undefined)
    assert.strictEqual(msg, undefined)
  })
})

describe('disable_zone', () => {
  it('empty request', () => {
    assert.strictEqual(plugin.disable_zone(), false)
  })

  it('testbl1, no zones', () => {
    plugin.zones = new Set()
    assert.strictEqual(plugin.disable_zone('testbl1', 'test result'), false)
  })

  it('testbl1, zones miss', () => {
    plugin.zones = new Set(['testbl2'])
    assert.strictEqual(plugin.disable_zone('testbl1', 'test result'), false)
    assert.strictEqual(plugin.zones.size, 1)
  })

  it('testbl1, zones hit', () => {
    plugin.zones = new Set(['testbl1'])
    assert.strictEqual(plugin.disable_zone('testbl1', 'test result'), true)
    assert.strictEqual(plugin.zones.size, 0)
  })
})

describe('ipQuery', () => {
  it('reverses IPv4 octets', () => {
    assert.strictEqual(
      plugin.ipQuery('1.2.3.4', 'zen.spamhaus.org'),
      '4.3.2.1.zen.spamhaus.org.',
    )
  })

  it('normalizes IPv4-mapped IPv6 before reversing', () => {
    assert.strictEqual(
      plugin.ipQuery('::ffff:1.2.3.4', 'zen.spamhaus.org'),
      '4.3.2.1.zen.spamhaus.org.',
    )
  })

  it('throws on invalid IP, message includes the IP', () => {
    assert.throws(
      () => plugin.ipQuery('not-an-ip', 'z'),
      /invalid IP: not-an-ip/,
    )
  })
})

describe('should_skip', () => {
  it('records err when zones set is empty', () => {
    connection = makeConnection()
    plugin.zones = new Set()
    assert.strictEqual(plugin.should_skip(connection), true)
    assert.ok(
      connection.results.get(plugin).err.some((e) => /no zones/.test(e)),
    )
  })
})

describe('eachActiveDnsList ipv6 policy', () => {
  it('skips IPv6 client on a zone with ipv6=false', async () => {
    connection = makeConnection()
    connection.set('remote.ip', '2001:db8::1')
    plugin.cfg['fake.zone'] = { ipv6: false }
    let dnsCalled = false
    plugin.lookup = async () => {
      dnsCalled = true
    }
    await plugin.eachActiveDnsList(connection, 'fake.zone', () => {})
    assert.strictEqual(dnsCalled, false)
    assert.ok(
      connection.results.get(plugin).skip.some((s) => /ipv6 disabled/.test(s)),
    )
  })
})

describe('reject=false', () => {
  it('records fail but does not DENY in search=all', async () => {
    connection = makeConnection()
    connection.set('remote.ip', '127.0.0.2')
    plugin.cfg.main.search = 'all'
    plugin.cfg['informational.zone'] = { type: 'block', reject: false }
    plugin.zones = new Set(['informational.zone'])
    plugin.lookup = async () => ['127.0.0.2']
    const { rc: code, msg } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, undefined)
    assert.strictEqual(msg, undefined)
    assert.ok(
      connection.results.get(plugin).fail.includes('informational.zone'),
    )
  })

  it('does not DENY in search=first either', async () => {
    connection = makeConnection()
    connection.set('remote.ip', '127.0.0.2')
    plugin.cfg.main.search = 'first'
    plugin.cfg['informational.zone'] = { type: 'block', reject: false }
    plugin.zones = new Set(['informational.zone'])
    plugin.lookup = async () => ['127.0.0.2']
    const { rc: code } = await callHook(plugin, 'onConnect', connection)
    assert.strictEqual(code, undefined)
  })
})
