// node.js built-in modules
const assert = require('assert')

// npm modules
const fixtures = require('haraka-test-fixtures')

beforeEach(function () {
  this.plugin = new fixtures.plugin('index')
  this.plugin.load_config()
  // this.plugin.register()
})

describe('dns-list', function () {
  it('plugin loads', function () {
    assert.ok(this.plugin)
  })

  it('loads config/dns-list.ini', function () {
    this.plugin.load_config()
    assert.ok(this.plugin.cfg)
  })

  it('config initializes a boolean', function () {
    assert.equal(this.plugin.cfg.stats.enable, false, this.plugin.cfg)
    assert.equal(this.plugin.cfg['ips.backscatterer.org'].enable, false)
  })

  it('sets up a connection', function () {
    this.connection = fixtures.connection.createConnection({})
    assert.ok(this.connection.server)
  })

  it('sets up a transaction', function () {
    this.connection = fixtures.connection.createConnection({})
    this.connection.transaction = fixtures.transaction.createTransaction({})
    // console.log(this.connection.transaction)
    assert.ok(this.connection.transaction.header)
  })
})

describe('lookup', function () {
  it('Spamcop, test IPv4', async function () {
    const a = await this.plugin.lookup('127.0.0.2', 'bl.spamcop.net')
    assert.deepStrictEqual(['127.0.0.2'], a)
  })

  it('Spamcop, unlisted IPv6', async function () {
    const r = await this.plugin.lookup('::1', 'bl.spamcop.net')
    assert.deepStrictEqual(undefined, r)
  })

  it('b.barracudacentral.org, unlisted IPv6', async function () {
    const r = await this.plugin.lookup('::1', 'b.barracudacentral.org')
    assert.deepStrictEqual(undefined, r)
  })

  it('Spamcop, unlisted IPv4', async function () {
    const a = await this.plugin.lookup('127.0.0.1', 'bl.spamcop.net')
    assert.deepStrictEqual(undefined, a)
  })

  it('CBL', async function () {
    const a = await this.plugin.lookup('127.0.0.2', 'xbl.spamhaus.org')
    assert.deepStrictEqual(a, ['127.0.0.4'])
  })
})

describe('check_zone', function () {
  it('tests DNS list bl.spamcop.net', async function () {
    const r = await this.plugin.check_zone('bl.spamcop.net')
    assert.deepStrictEqual(r, true)
  })

  it('tests DNS list zen.spamhaus.org', async function () {
    const r = await this.plugin.check_zone('zen.spamhaus.org')
    assert.deepStrictEqual(r, true)
  })

  it('tests DNS list hostkarma.junkemailfilter.com', async function () {
    const r = await this.plugin.check_zone('hostkarma.junkemailfilter.com')
    assert.deepStrictEqual(r, true)
  })
})

describe('check_zones', function () {
  this.timeout(22000)

  it('tests each block list', async function () {
    await this.plugin.check_zones(6000)
  })
})

describe('onConnect', function () {
  beforeEach(function () {
    this.connection = fixtures.connection.createConnection()
  })

  it('onConnect 127.0.0.1', function (done) {
    this.connection.set('remote.ip', '127.0.0.1')
    this.plugin.zones = new Set(['bl.spamcop.net', 'list.dnswl.org'])
    this.plugin.onConnect((code, msg) => {
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
      done()
    }, this.connection)
  })

  it('onConnect 127.0.0.2', function (done) {
    this.connection.set('remote.ip', '127.0.0.2')
    this.plugin.zones = new Set(['bl.spamcop.net', 'list.dnswl.org'])
    this.plugin.onConnect((code, msg) => {
      // console.log(`code: ${code}, ${msg}`)
      if (code === OK) {
        assert.strictEqual(code, OK)
        assert.strictEqual(msg, 'host [127.0.0.2] is listed on list.dnswl.org')
      } else {
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'host [127.0.0.2] is listed on bl.spamcop.net')
      }
      done()
    }, this.connection)
  })

  it('Spamcop + CBL', function (done) {
    this.connection.set('remote.ip', '127.0.0.2')
    this.plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    this.plugin.onConnect((code, msg) => {
      // console.log(`code: ${code}, ${msg}`)
      assert.strictEqual(code, DENY)
      assert.ok(/is listed on/.test(msg))
      done()
    }, this.connection)
  })

  it('Spamcop + CBL + negative result', function (done) {
    this.connection.set('remote.ip', '127.0.0.1')
    this.plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    this.plugin.onConnect((code, msg) => {
      // console.log(`test return ${code} ${msg}`)
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
      done()
    }, this.connection)
  })

  it('IPv6 addresses supported', function (done) {
    this.connection.set('remote.ip', '::1')
    this.plugin.zones = new Set(['bl.spamcop.net', 'xbl.spamhaus.org'])
    this.plugin.onConnect((code, msg) => {
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('first', function () {
  beforeEach(function () {
    this.plugin.cfg.main.search = 'first'
    this.plugin.zones = new Set(['xbl.spamhaus.org', 'bl.spamcop.net'])
    this.connection = fixtures.connection.createConnection()
  })

  it('positive result', function (done) {
    this.connection.set('remote.ip', '127.0.0.2')
    this.plugin.onConnect((code, msg) => {
      // console.log(`onConnect return ${code} ${msg}`)
      assert.strictEqual(code, DENY)
      assert.ok(/is listed on/.test(msg))
      done()
    }, this.connection)
  })

  it('negative result', function (done) {
    this.connection.set('remote.ip', '127.0.0.1')
    this.plugin.onConnect((code, msg) => {
      // console.log(`test return ${code} ${msg}`)
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('disable_zone', function () {
  it('empty request', function () {
    assert.strictEqual(this.plugin.disable_zone(), false)
  })

  it('testbl1, no zones', function () {
    this.plugin.zones = new Set()
    assert.strictEqual(
      this.plugin.disable_zone('testbl1', 'test result'),
      false,
    )
  })

  it('testbl1, zones miss', function () {
    this.plugin.zones = new Set(['testbl2'])
    assert.strictEqual(
      this.plugin.disable_zone('testbl1', 'test result'),
      false,
    )
    assert.strictEqual(this.plugin.zones.size, 1)
  })

  it('testbl1, zones hit', function () {
    this.plugin.zones = new Set(['testbl1'])
    assert.strictEqual(this.plugin.disable_zone('testbl1', 'test result'), true)
    assert.strictEqual(this.plugin.zones.size, 0)
  })
})
