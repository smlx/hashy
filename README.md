# hashy

[![Release](https://github.com/smlx/hashy/actions/workflows/release.yaml/badge.svg)](https://github.com/smlx/hashy/actions/workflows/release.yaml)
[![Coverage](https://coveralls.io/repos/github/smlx/hashy/badge.svg?branch=main)](https://coveralls.io/github/smlx/hashy?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/smlx/hashy)](https://goreportcard.com/report/github.com/smlx/hashy)

## About

`hashy` is a CLI tool and Go library for inspection and manipulation of password hashes, such as you may find in `/etc/shadow` on Unix systems.
It may be useful to sysadmins or security researchers.

---
**WARNING**

Both the CLI and library interfaces are currently unstable may change at any time.

---
---
**IMPORTANT NOTE**

Many of the password hash functions implemented in this module are known to be insecure.
Implementation should not be considered endorsement.

---

### Features

* Generate a password hash (similar to `mkpasswd`([code](https://github.com/rfc1036/whois), [manpage](https://manpages.debian.org/testing/whois/mkpasswd.1.en.html)))
* Identify the format of a password hash (similar to [`hash-identifier`](https://github.com/blackploit/hash-identifier))
* Check if a password matches a password hash
* Support a wide range of password hash functions (still a WIP, see the table below)
* Written in pure Go (no cgo)

### Design philosophy

`hashy` aims for simplicity and good documentation.
It does not aim for speed or to be useful for cracking password hashes; use [hashcat](https://github.com/hashcat/hashcat) for that.

### Supported password hash functions

Development work is currently targeting common Linux password hash functions.
If you are interested in a function not listed below please open an issue with documentation / implementation links.

| Supported | WIP |
| ---       | --- |
| ✅        | ⏳  |

#### Unix crypt() functions

|             | Supported | Best practice?                                                                                                                                           |
| ---         | ---       | ---                                                                                                                                                      |
| bcrypt      | ⏳        | -                                                                                                                                                        |
| md5crypt    | ✅        | [No](https://web.archive.org/web/20190324130136/http://phk.freebsd.dk:80/sagas/md5crypt_eol.html), [CVE](https://nvd.nist.gov/vuln/detail/CVE-2012-3287) |
| scrypt      | ⏳        | -                                                                                                                                                        |
| sha1crypt   | ✅        | [No](https://manpages.debian.org/testing/libcrypt-dev/crypt.5.en.html#sha1crypt)                                                                         |
| sha256crypt | ⏳        | -                                                                                                                                                        |
| sha512crypt | ⏳        | -                                                                                                                                                        |
| yescrypt    | ⏳        | -                                                                                                                                                        |

#### Other software

|                                | Supported | Best practice?                                                                                                                                         |
| ---                            | ---       | ---                                                                                                                                             |
| MariaDB/MySQL `OLD_PASSWORD()` | ✅        | [No](https://security.stackexchange.com/questions/3133/mysql-old-password-cryptanalysis), [CVE](https://nvd.nist.gov/vuln/detail/CVE-2003-1480) |

## Install and Use

Download the latest release binary for your platform, drop it into your `$PATH`, and run:

```
hashy --help
```

## Develop and Build

Clone the git repository locally and run:

```
make
```

## References / Prior art

These projects were referenced to understand the password hash functions implemented by `hashy`:

* [libxcrypt](https://github.com/besser82/libxcrypt)
* [musl crypt()](https://git.musl-libc.org/cgit/musl/tree/src/crypt)
* [unix-crypt](https://github.com/mogest/unix-crypt)
* [go-htpasswd](https://github.com/tg123/go-htpasswd)

In addition, [`hash-identifier`](https://github.com/blackploit/hash-identifier) inspired the `id` functionality.
