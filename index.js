// dns-lists plugin

const dnsPromises = require('node:dns').promises
const dns = new dnsPromises.Resolver({ timeout: 25000, tries: 1 })
const net = require('node:net')
const net_utils = require('haraka-net-utils')

// ::ffff:1.2.3.4 -> 1.2.3.4 ; pass-through otherwise. Node reports such
// addresses as IPv6, which makes DNSBL queries reverse-nibble them.
function normalizeIP(ip) {
  if (!net.isIPv6(ip)) return ip
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip)
  return m && net.isIPv4(m[1]) ? m[1] : ip
}

let redis_client

exports.register = function () {
  this.load_config()

  if (this.cfg.main.periodic_checks) {
    this.check_zones(this.cfg.main.periodic_checks)
  }

  this.register_hook('connect', 'onConnect')

  if (this.cfg['ips.backscatterer.org'].enable) {
    this.register_hook('mail', 'check_backscatterer')
  }

  // IMPORTANT: don't run this on hook_rcpt else we're an open relay...
  if (this.cfg['list.dnswl.org'].ok_helo) {
    this.register_hook('helo', 'check_dnswl')
    this.register_hook('ehlo', 'check_dnswl')
  }
  if (this.cfg['list.dnswl.org'].ok_mail) {
    this.register_hook('mail', 'check_dnswl')
  }
}

exports.load_config = function () {
  this.cfg = this.config.get(
    'dns-list.ini',
    {
      booleans: [
        '-stats.enable',
        '*.reject',
        '*.ipv6',
        '*.loopback_is_rejected',
        '-ips.backscatterer.org.enable',
        '-list.dnswl.org.ok_helo',
        '-list.dnswl.org.ok_mail',
      ],
    },
    () => {
      this.load_config()
    },
  )

  if (Array.isArray(this.cfg.main.zones)) {
    this.cfg.main.zones = new Set(this.cfg.main.zones)
  } else {
    this.cfg.main.zones = new Set(this.cfg.main.zones.split(/[\s,;]+/))
  }

  // Compatibility with old-plugin
  for (const z in this.config.get('dnsbl.zones', 'list')) {
    this.cfg.main.zones.add(z)
  }
  for (const z in this.config.get('dnswl.zones', 'list')) {
    this.cfg.main.zones.add(z)
    if (this.cfg[z] === undefined) this.cfg[z] = {}
    this.cfg[z].type = 'allow'
  }

  // active zones
  if (this.cfg.main.periodic_checks < 5) {
    // all configured are enabled
    this.zones = this.cfg.main.zones
  } else {
    this.zones = new Set() // populated by check_zones()
  }

  // zones that responded with a rate-limit code (e.g. Spamhaus 127.255.255.x
  // when queried from a public/cloud resolver). Surfaced separately from
  // disabled zones so tests + callers can distinguish "blocked from this
  // network" from "list is broken" or "not listed".
  this.rate_limited = new Set()
}

exports.should_skip = function (connection) {
  if (!connection) return true

  if (connection.remote.is_private) {
    connection.results.add(this, {
      skip: `private: ${connection.remote.ip}`,
      emit: true,
    })
    return true
  }

  if (this.zones.size === 0) {
    connection.results.add(this, { err: `no zones` })
    return true
  }

  return false
}

exports.eachActiveDnsList = async function (connection, zone, nextOnce) {
  const type = this.getListType(zone)
  const ip = normalizeIP(connection.remote.ip)

  if (net.isIPv6(ip) && this.cfg[zone]?.ipv6 === false) {
    connection.results.add(this, { skip: `${zone}: ipv6 disabled` })
    return
  }

  const ips = await this.lookup(ip, zone)

  if (!ips) {
    if (this.rate_limited.has(zone)) {
      connection.results.add(this, { skip: `rate_limited:${zone}` })
    } else if (type === 'block') {
      connection.results.add(this, { pass: zone })
    }
    return
  }

  for (const i of ips) {
    if (this.cfg[zone] && this.cfg[zone][i]) {
      connection.results.add(this, { msg: this.cfg[zone][i] })
    }
  }

  if (type === 'allow') {
    connection.notes.dnswl = true
    connection.results.add(this, { pass: zone })
    return nextOnce(OK, [zone])
  }

  if (type === 'karma') {
    if (ips.includes('127.0.0.1')) {
      connection.results.add(this, { pass: zone })
    } else if (ips.includes('127.0.0.2')) {
      connection.results.add(this, { fail: zone })
      if (this.getListReject(zone) && this.cfg.main.search === 'first') {
        nextOnce(DENY, [zone])
      }
    } else {
      connection.results.add(this, { msg: zone })
    }
    return
  }

  // type=block
  connection.results.add(this, { fail: zone })
  if (this.getListReject(zone) && this.cfg.main.search === 'first') {
    nextOnce(DENY, [zone])
  }
}

exports.onConnect = function (next, connection) {
  const plugin = this
  if (this.should_skip(connection)) return next()

  let calledNext = false
  function nextOnce(code, zones) {
    // console.log(`nextOnce: ${code} : ${zones}`)
    if (calledNext) return
    calledNext = true
    connection.results.add(plugin, { emit: true })
    if (code === undefined || zones === undefined) return next()
    next(
      code,
      `host [${connection.remote.ip}] is listed on ${zones.join(', ')}`,
    )
  }

  const promises = []
  for (const zone of this.zones) {
    promises.push(this.eachActiveDnsList(connection, zone, nextOnce))
  }

  Promise.all(promises).then(() => {
    const failed = connection.results.get(this)?.fail || []
    const rejectable = failed.filter((z) => this.getListReject(z))
    if (rejectable.length) {
      nextOnce(DENY, rejectable)
      return
    }
    nextOnce()
  })
}

exports.check_dnswl = (next, connection) =>
  connection.notes.dnswl ? next(OK) : next()

exports.check_backscatterer = async function (next, connection, params) {
  if (!this.cfg['ips.backscatterer.org'].enable) return next()

  const user = params[0]?.user ? params[0].user.toLowerCase() : null
  if (!(!user || user === 'postmaster')) return next()

  const ip = normalizeIP(connection.remote.ip)
  if (net.isIPv6(ip) && this.cfg['ips.backscatterer.org'].ipv6 === false) {
    return next()
  }

  try {
    const a = await this.lookup(ip, 'ips.backscatterer.org')
    if (a)
      return next(
        DENY,
        `Host ${connection.remote.host} [${connection.remote.ip}] is listed by ips.backscatterer.org`,
      )
  } catch (err) {
    connection.logerror(this, err)
  }
  next()
}

exports.ipQuery = function (ip, zone) {
  ip = normalizeIP(ip)

  // ::FFFF:7F00:2 -> 2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.$zone.
  if (net.isIPv6(ip)) return [net_utils.ipv6_reverse(ip), zone, ''].join('.')

  // 1.2.3.4 -> 4.3.2.1.$zone.
  if (net.isIPv4(ip))
    return [ip.split('.').reverse().join('.'), zone, ''].join('.')

  throw new Error(`invalid IP: ${ip}`)
}

exports.lookup = async function (ip, zone) {
  if (!ip || !zone) throw new Error(`lookup: invalid request`)

  let start
  if (this.cfg.stats.enable) {
    this.init_redis()
    start = new Date().getTime()
  }

  try {
    const query = this.ipQuery(ip, zone)
    const a = await dns.resolve4(query, 'A')

    this.stats_incr_zone(null, zone, start)

    if (this.hasSpecialResults(zone, a)) return

    return a
  } catch (err) {
    this.stats_incr_zone(err, zone, start)

    if (err.code === dnsPromises.NOTFOUND) return // unlisted, not an error

    if (err.code === dnsPromises.TIMEOUT) {
      this.disable_zone(zone, err.code)
      return
    }

    this.logerror(`${zone} lookup error: ${err}`)
  }
}

exports.hasSpecialResults = function (zone, a) {
  // Check for a result outside 127/8
  // This should *never* happen on a proper DNS list
  if (
    a &&
    a.find((rec) => {
      return rec.split('.')[0] !== '127'
    })
  ) {
    this.disable_zone(zone, a)
    return true
  }

  if (/spamhaus/.test(zone)) {
    // https://www.spamhaus.org/news/article/807/using-our-public-mirrors-check-your-return-codes-now
    if (
      a?.includes('127.255.255.252') ||
      a?.includes('127.255.255.254') ||
      a?.includes('127.255.255.255')
    ) {
      this.rate_limited?.add(zone)
      this.disable_zone(zone, a)
      return true
    }
  }

  // https://www.dnswl.org/?page_id=15
  if ('list.dnswl.org' === zone && a?.includes('127.0.0.255')) {
    this.disable_zone(zone, a)
    return true
  }

  return false
}

exports.stats_incr_zone = function (err, zone, start) {
  if (!this.cfg.stats.enable) return

  const rkey = `dns-list-stat:${zone}`
  const elapsed = new Date().getTime() - start
  redis_client.hIncrBy(rkey, 'TOTAL', 1)
  const foo = err ? err.code : 'LISTED'
  redis_client.hIncrBy(rkey, foo, 1)
  redis_client.hGet(rkey, 'AVG_RT').then((rt) => {
    const avg = parseInt(rt)
      ? (parseInt(elapsed) + parseInt(rt)) / 2
      : parseInt(elapsed)
    redis_client.hSet(rkey, 'AVG_RT', avg)
  })
}

exports.init_redis = function () {
  if (redis_client) return

  const redis = require('redis')
  const host_port = this.cfg.stats.redis_host.split(':')
  const host = host_port[0] || '127.0.0.1'
  const port = parseInt(host_port[1], 10) || 6379

  redis_client = redis.createClient(port, host)
  redis_client.connect().then(() => {
    redis_client.on('error', (err) => {
      this.logerror(`Redis error: ${err}`)
      redis_client.quit()
      redis_client = null // should force a reconnect
      // not sure if that's the right thing but better than nothing...
    })
  })
}

exports.getListType = function (zone) {
  if (this.cfg[zone] === undefined) return 'block'
  return this.cfg[zone]?.type || 'block'
}

exports.getListReject = function (zone) {
  if (this.cfg[zone]?.reject === undefined) return true // default: true
  return this.cfg[zone].reject
}

exports.checkZonePositive = async function (zone, ip) {
  // RFC 5782 § 5
  // IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes.

  const query = this.ipQuery(ip, zone)
  try {
    const a = await dns.resolve4(query, 'A')
    if (a) return true
    this.logwarn(`${query}\tno response`)
    this.disable_zone(zone, a)
  } catch (err) {
    this.logerror(`${query} -> ${err}`)
  }
  return false
}

exports.checkZoneNegative = async function (zone, ip) {
  // RFC 5782 § 5
  // IPv4-based DNSxLs MUST NOT contain an entry for 127.0.0.1.

  // skip this test for DNS lists that don't follow the RFC
  if (this.cfg[zone]?.loopback_is_rejected) return true

  const query = this.ipQuery(ip, zone)
  try {
    const a = await dns.resolve4(query, 'A')
    if (a) this.disable_zone(zone, a) // listing 127.0.0.1 is invalid per RFC
  } catch (err) {
    switch (err.code) {
      case dnsPromises.NOTFOUND: // IP not listed
        return true
      case dnsPromises.TIMEOUT: // list timed out
        this.disable_zone(zone, err.code)
        return false
    }
    this.logerror(`${query} -> got err ${err}`)
  }
  return false
}

exports.check_zone = async function (zone) {
  if (!(await this.checkZonePositive(zone, '127.0.0.2'))) return false
  if (!(await this.checkZoneNegative(zone, '127.0.0.1'))) return false

  this.enable_zone(zone) // both tests passed

  if (this.cfg[zone]?.ipv6 === true) {
    await this.checkZonePositive(zone, '::FFFF:7F00:2')
    await this.checkZoneNegative(zone, '::FFFF:7F00:1')
  }

  return true
}

exports.check_zones = async function (interval) {
  if (interval) interval = parseInt(interval)

  const promises = []
  for (const zone of this.cfg.main.zones) {
    promises.push(this.check_zone(zone))
  }

  try {
    await Promise.all(promises)
  } catch (err) {
    console.error(err)
  }

  // Set a timer to re-test
  if (interval && interval >= 5 && !this._interval) {
    this.loginfo(`will re-test list zones every ${interval} minutes`)
    this._interval = setInterval(
      () => {
        this.check_zones()
      },
      interval * 60 * 1000,
    )

    this._interval.unref() // don't block node process from exiting
  }
}

exports.shutdown = function () {
  clearInterval(this._interval)
  if (redis_client) redis_client.quit()
}

exports.enable_zone = function (zone) {
  if (!zone) return false
  const type = this.getListType(zone)

  if (!this.zones.has(zone)) {
    this.loginfo(`enabling ${type} zone ${zone}`)
    this.zones.add(zone)
  }
}

exports.disable_zone = function (zone, result) {
  if (!zone) return false
  const type = this.getListType(zone)

  if (!this.zones.has(zone)) return false

  this.logwarn(`disabling ${type} zone '${zone}' ${result ? result : ''}`)
  this.zones.delete(zone)
  return true
}
