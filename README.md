<div align="center">

# MaskProxy

**Proxy checker · harvester · analyzer - SOCKS4 / SOCKS5 / HTTP**

One file. Zero dependencies. Windows, Linux, macOS and Android (Termux).

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-2BFF88?style=for-the-badge)
![Platforms](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos%20%7C%20termux-8A8FA3?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-FF3DCB?style=for-the-badge)
![Made by](https://img.shields.io/badge/made%20by-msk3du0t-00E5FF?style=for-the-badge)

</div>

---

## Why MaskProxy

- **Truly live.** A real request goes *through* each proxy and must return a valid IP. A handshake alone never counts.
- **Auto-detects the type.** Feed it a mixed list; it finds SOCKS5, SOCKS4 or HTTP for each proxy. Or force a type.
- **Harvests for you.** Pulls fresh free lists from ten sources, mixes them fairly, checks them, keeps the live ones.
- **Safety scan.** Flags proxies that inject scripts into pages or intercept HTTPS (TLS) as `suspicious`.
- **Smart output.** Every run gets its own timestamped folder: `live.txt`, per-type files, CSV and JSON reports. Nothing is overwritten.
- **Looks good everywhere.** Animated live dashboard that adapts to phone screens, with an ASCII fallback.
- **Two ways to use it.** Interactive menu, or command-line flags for scripts.

## Quick start

```bash
git clone https://github.com/msk3du0t/maskproxy.git
cd maskproxy
python maskproxy.py          # interactive menu
```

Needs only **Python 3.9+**. Check your install without internet: `python maskproxy.py --selftest`

## Usage

```bash
python maskproxy.py -f proxies.txt                 # quick check: live only
python maskproxy.py -f proxies.txt -m smart        # speed, country, HTTPS, safety scan
python maskproxy.py -f proxies.txt -t socks5       # force a type
python maskproxy.py --harvest --target 100         # scrape free lists, stop at 100 live
python maskproxy.py -p user:pass@1.2.3.4:1080      # inspect one proxy
```

| Flag | Meaning |
|---|---|
| `-f` `-u` `-p` | file / URL / single proxy (`-f -` reads stdin) |
| `--harvest` | download free proxy lists, then check them |
| `-m quick\|smart` | live only, or full analysis |
| `-t auto\|socks\|socks4\|socks5\|http` | proxy type |
| `-c` `--timeout` `--retries` | concurrency, seconds per proxy, retries |
| `-l` `--target` | harvest limit, stop after N live |
| `--country US,DE` | keep only these exit countries (smart) |
| `-o` | output folder |
| `--ascii` `--no-color` `--no-banner` | display options |

Formats understood: `ip:port` · `user:pass@ip:port` · `ip:port:user:pass` · `socks5://ip:port` — and lists copied from web pages or JSON.

## Output

```
maskproxy_results/2026-10-29_14-32-05/
├── live.txt              fastest first
├── socks5.txt  socks4.txt  http.txt
├── suspicious.txt  dead.txt
└── report.csv  report.json
```

## Sources

TheSpeedX · monosans · gfpcom · VPSLab · jetkai · Proxifly · ProxyScrape · GeoNode · free-proxy-list.net · a health-checked list.
Add your own, including ones that need an **API key**, from the *Sources & Keys* menu.

## Notes

Free public proxies are operated by unknown third parties. Treat them as untrusted, never send passwords or private data through them, and use this tool lawfully and in line with the terms of the services you connect to. Typically only a small share of any free list is alive at a given moment.

---

<div align="center">

**MaskProxy** · made by **msk3du0t** · MIT License

</div>
