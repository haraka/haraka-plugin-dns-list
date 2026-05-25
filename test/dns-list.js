// node.js built-in modules
const assert = require('node:assert')
const { describe, it, beforeEach } = require('node:test')

// npm modules
const fixtures = require('haraka-test-fixtures')

let plugin
let connection

beforeEach(() => {
  plugin = new fixtures.plugin('index')
  plugin.load_config()
  // plugin.register()
})

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
    connection = fixtures.connection.createConnection({})
    assert.ok(connection.server)
  })

  it('sets up a transaction', () => {
    connection = fixtures.connection.createConnection({})
    connection.init_transaction()
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

  it('CBL', async () => {
    const a = await plugin.lookup('127.0.0.2', 'xbl.spamhaus.org')
    assert.deepStrictEqual(a, ['127.0.0.4'])
  })
})

describe('check_zone', () => {
  it('tests DNS list bl.spamcop.net', async () => {
    const r = await plugin.check_zone('bl.spamcop.net')
    assert.deepStrictEqual(r, true)
  })

  it('tests DNS list zen.spamhaus.org', async () => {
    const r = await plugin.check_zone('zen.spamhaus.org')
    assert.deepStrictEqual(r, true)
  })

  it('tests DNS list hostkarma.junkemailfilter.com', async () => {
    const r = await plugin.check_zone('hostkarma.junkemailfilter.com')
    assert.deepStrictEqual(r, true)
  })
})

describe('check_zones', { timeout: 29000 }, () => {
  it('tests each block list', async () => {
    await plugin.check_zones(8000)
  })
})

describe('onConnect', () => {
  beforeEach(() => {
    connection = fixtures.connection.createConnection()
  })

  it('onConnect 127.0.0.1', async () => {
    connection.set('remote.ip', '127.0.0.1')
    plugin.zones = new Set(['bl.spamcop.net', 'list.dnswl.org'])
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('onConnect 127.0.0.2', async () => {
    connection.set('remote.ip', '127.0.0.2')
    plugin.zones = new Set(['bl.spamcop.net', 'list.dnswl.org'])
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        // console.log(`code: ${code}, ${msg}`)
        if (code === OK) {
          assert.strictEqual(code, OK)
          assert.strictEqual(msg, 'host [127.0.0.2] is listed on list.dnswl.org')
        } else {
          assert.strictEqual(code, DENY)
          assert.strictEqual(msg, 'host [127.0.0.2] is listed on bl.spamcop.net')
        }
        resolve()
      }, connection)
    })
  })

  it('Spamcop + CBL', async () => {
    connection.set('remote.ip', '127.0.0.2')
    plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        // console.log(`code: ${code}, ${msg}`)
        assert.strictEqual(code, DENY)
        assert.ok(/is listed on/.test(msg))
        resolve()
      }, connection)
    })
  })

  it('Spamcop + CBL + negative result', async () => {
    connection.set('remote.ip', '127.0.0.1')
    plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        // console.log(`test return ${code} ${msg}`)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, connection)
    })
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
})

describe('first', () => {
  beforeEach(() => {
    plugin.cfg.main.search = 'first'
    plugin.zones = new Set(['xbl.spamhaus.org', 'bl.spamcop.net'])
    connection = fixtures.connection.createConnection()
  })

  it('positive result', async () => {
    connection.set('remote.ip', '127.0.0.2')
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        // console.log(`onConnect return ${code} ${msg}`)
        assert.strictEqual(code, DENY)
        assert.ok(/is listed on/.test(msg))
        resolve()
      }, connection)
    })
  })

  it('negative result', async () => {
    connection.set('remote.ip', '127.0.0.1')
    await new Promise((resolve) => {
      plugin.onConnect((code, msg) => {
        // console.log(`test return ${code} ${msg}`)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, connection)
    })
  })
})

describe('disable_zone', () => {
  it('empty request', () => {
    assert.strictEqual(plugin.disable_zone(), false)
  })

  it('testbl1, no zones', () => {
    plugin.zones = new Set()
    assert.strictEqual(
      plugin.disable_zone('testbl1', 'test result'),
      false,
    )
  })

  it('testbl1, zones miss', () => {
    plugin.zones = new Set(['testbl2'])
    assert.strictEqual(
      plugin.disable_zone('testbl1', 'test result'),
      false,
    )
    assert.strictEqual(plugin.zones.size, 1)
  })

  it('testbl1, zones hit', () => {
    plugin.zones = new Set(['testbl1'])
    assert.strictEqual(plugin.disable_zone('testbl1', 'test result'), true)
    assert.strictEqual(plugin.zones.size, 0)
  })
})
