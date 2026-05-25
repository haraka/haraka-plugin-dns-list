# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.3.0] - 2026-05-24

- fix: honor per-zone `reject=false` so block lists can be informational
- fix: normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) before DNSBL lookup
- fix: enforce per-zone `ipv6=false` on live lookups, not just self-tests
- fix: empty-zones check now uses `Set.size` (was always-false `.length`)
- fix: `invalid IP` error message now interpolates the IP
- fix: route lookup errors through `logerror` instead of `console.error`
- doc(README): correct config filename to `dns-list.ini`
- dep(eslint): upgrade to v10
- change: test runner is now node:test
- remove done callbacks in async tests #16

### [1.2.4] - 2025-03-28

- remove SORBS.net (#14)

### [1.2.3] - 2025-01-26

- doc(README): use URL refs
- style(prettier): move config into package.json
- dep(all): bump versions to latest
- dep(eslint): upgrade to v9

### [1.2.2] - 2025-01-02

- fix: zone specific settings are optional, so check if it exists before accessing properties inside it, #11

### [1.2.1] - 2024-08-22

- fix: don't make a set from a set (happened when periodic_checks < 5), #9
- chore: bump dep versions

### [1.2.0] - 2024-04-13

- dnswl: sending OK on helo & mail hooks disabled by default
- check_zones: check all zones concurrently (test speedup)

### [1.1.0] - 2024-04-10

- feat: imported backscatterer from haraka/Haraka

### [1.0.3] - 2024-04-10

- emit a log entry when all DNS lists pass (to show its working)

### [1.0.2] - 2024-04-09

- dep: eslint-plugin-haraka -> @haraka/eslint-config
- populate [files] in package.json. Delete .npmignore.
- doc(CHANGE): renamed Changes.md -> CHANGELOG.md
- doc(CONTRIBUTORS): added
- prettier
- feat: add timeout to DNS Resolver #2

## 1.0.0 - 2023-12-15

- Initial release

[1.0.1]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/1.0.1
[1.0.2]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.0.2
[1.0.3]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.0.3
[1.1.0]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.1.0
[1.2.0]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.2.0
[1.2.1]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.2.1
[1.2.2]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.2.2
[1.2.3]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.2.3
[1.2.4]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.2.4
[1.3.0]: https://github.com/haraka/haraka-plugin-dns-list/releases/tag/v1.3.0
