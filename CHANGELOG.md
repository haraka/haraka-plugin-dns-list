# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

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
