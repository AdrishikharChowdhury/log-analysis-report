# CONTEXT.md — Forensic Narrative & Factual Ledger (Organisation X)

_Last updated: 2026-10-03 — Phases 1–3 complete (web C2 confirmed for 7 clusters). All timestamps local UTC+05:30 unless noted._

## 1. Environment
- ~250 Linux desktops, 19 units (alpha, bravo, charlie, delta, echo, foxtrot, golf, hotel, india, juliett, kilo, lima, mike, november, oscar, papa, quebec, romeo, sierra). Logs 01–26 Sep 2026 (endpoint_security) + 10–21 Sep 2026 web_activity (248 endpoints).
- Layout: endpoint_id / endpoint_name / mac / unit / log_type (web, web_block, av_scan, quarantine, usb) / event_time (endpoint clock) / received_time (server) / message. Endpoints upload late (days); clocks may be wrong — must use delay analysis.

## 2. Verified compromised endpoints (ledger)
### 2a. FileType==Malicious quarantine hits — 33 endpoints, 134 rows (ONE file re-listed many times; dedup by endpoint+SHA below). Treat as COMPROMISED pending web-confirm.

| endpoint_id | endpoint_name | mac | unit | malicious file(s) | SHA-256 | Quarantined At (first seen) |
|---|---|---|---|---|---|---|
| EPZRAPEL | host-d14b | 8A:58:3E:18:FD:1B | unit-foxtrot | 53EDA42869D426262B752F088EA605187284ACE8 | 2e4dff1672bbabba74a0a99d54e38e56e036ce8471989583039b3c3e7edac0b7 | 2026-08-31 13:21 |
| EPOC6Y4R | host-e783 | A2:DC:C5:9F:EC:E9 | unit-charlie | recently-used.xbel | 5e10b3490160cca0fc872f2b026d4b40bafc236852f83d30c9031899e50adc9c | Sep (9 re-lists 01–24 Sep) |
| EPJYEC7F | host-38aa | 5E:1C:0A:57:9A:B0 | unit-romeo | recently-used.xbel | 5e10b349... | Sep (10 re-lists) |
| EPMQTKSL | host-942d | 06:30:01:86:E8:62 | unit-charlie | recently-used.xbel | 5e10b349... | 02-09 |
| EPC2L3UH | host-b4da | 8A:CB:D0:3B:7E:64 | unit-india | recently-used.xbel | 5e10b349... | 02-09 (18 re-lists, heaviest) |
| EPAGTKNF | host-227c | B2:F1:48:20:04:E9 | unit-quebec | Buy CP PLUS Dashboard Camera...PPP.pdf | 18866b6f7308f73bc1b63193e50629bfd4fff701d6b9d3d2d6331b90e9162208 | 03-09 19:03 / 04-09 18:10 |
| EPJ42VCZ | host-56a6 | FE:1B:B6:08:36:73 | unit-india | RAGHAV STNC STNA.pdf / RAGHAV STNA STNB.pdf | a2beca1870ae689f4b046a20c3d8e2e48557d782dea53489b21a8b0adcef38be / 854b8f7716627df333e8ecfeae5887c02b3195658f7394573fe21b67e93e11be | 07-09-2026 08:43:44 |
| EPPGWIOF | host-a656 | 9E:61:10:7F:7C:01 | unit-india | brprintconflsr3 / rawtobr3 | 6594cac08d03782ad43d6b293faff904f20032c8eb37a1b27b6caf57b1aeae5e / 64efda7704564dd50c7514e74ef3c5252bc68af8f3b0d92358b64771980665af | 07-09 (5x each) |
| EPQKOBYG | host-d29a | BE:0F:9D:46:86:9F | unit-romeo | win-lbp623-621-fw-v1301(1).exe | f475a7462dd85932ad7f99354751663d1543adb5e37c7c51ece78e10b6c37189 | 08-09 |
| EPMDU6L5 | host-b05e | 32:B6:D9:DA:8B:BD | unit-oscar | recently-used.xbel | 5dd59e8309b4be90aad58871d82a5b3fb6dcd7ff19a7fb34587732512b28739d | 08-09 11:58 |
| EPFQSCDV | host-2fe4 | 4E:3D:CE:06:BF:3C | unit-juliett | recently-used.xbel | 5e10b349... | 09-09 / 10-09 |
| EPEEHWSG | host-4724 | 2A:53:8A:6D:50:9C | unit-kilo | Library Books.xlsx | 98d119993c27068f00bdf18a17d6613ae6ce6046b6b6620979282c2662c4efbd | 10-09 09:15 |
| EPGSQVEB | host-9a4f | 2A:98:89:E3:BB:4A | unit-bravo | Final_Documents.zip (x2 paths) | 404ee57531c33156d62154f49e3700c8c1f09cd0c75692f795748d59b9145088 | 11-09 10:11 |
| EP4YIFHV | host-a616 | 42:07:D0:E7:8E:56 | unit-lima | 20x JS bundles (bnpl.bundle.js, edge_driver.js, crypto.bundle.js, etc. + file named c3f9c4a4...) — full hash list in analysis dump | 20 distinct SHAs (e.g. 620389d2..., 6c21396c..., 100d970f..., 876ede3d..., 036965c2..., 528c866f..., 985d0862..., c3f9c4a4..., e3d95016..., 4aab5c4a..., b5aa710d..., 444d4db05..., 8e661de9..., 569e425e..., 39f5d83d..., bee346d1..., f2bf148b..., 56bada505..., d604ac76..., 6f47d71e...) | 11-09 09:23 + 09:35 |
| EPT3KTUL | host-ad7a | 3A:55:96:42:A1:8C | unit-quebec | Dash Camera-49600.00.pdf | 7505de4759aadebf5e21b2cc0f7f13fccdbec968e3b82be70791197fac3d21bc | 11-09 12:06 |
| EPDRB236 | host-b3df | 2A:DE:08:5F:46:0E | unit-hotel | recently-used.xbel | 5e10b349... | 13-09 |
| EPRD7FJT | host-916a | 3E:C4:03:FE:FC:5C | unit-romeo | 12th Plan Works Dashboard.pdf | 5c7fc859c5a8f2bba02446c30020bb2b478686d66b566818c7382c840d95720f | 12-09 08:25 |
| EPMVZYZO | host-ba01 | 9E:13:02:61:15:F6 | unit-quebec | mydoc.pdf / mydoc-9.pdf / mydoc-10.pdf / mydoc-75.pdf | d474833503a6404b8106d981c9f0769e4bd97033f45cf424e360b61f659c8cb1 / 7c10f54076fba8141f8ef95a701d0a4bdadfc63a5b98bec16b6b68439ebc3dc7 / 5b7914202b30fc7e28ddcd2f82502aa8531035b812ee2194d978b7e920f43066 / 92e24303edb5f2b6f1bc6c0c375655717eb2227c1622c4a723791aafce33965d | 13-09 17:27 |
| EPJ76RZV | host-aedd | 9E:85:42:C3:B1:56 | unit-alpha | COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx (4x re-lists) | d4a23078663777e758c04d2670b0d6aac8aa7ba5f91f811c5d94fa6ce8b7ef56 | 14-09 13:30 onward |
| EPVC2P55 | host-aca0 | C2:46:AE:94:76:F6 | unit-alpha | Data1.cab | 925b63ce20d94bc4a0d98d02d153161dbba9ac61c39ec323ac8a73b2acbde42e | 15-09 11:28 |
| EPAJI3E5 | host-f6a4 | F2:07:5D:2A:72:97 | unit-oscar | Lakeside traders.docx / Lakeside traders.pdf | c11e86d9e30b5fad8daf1c15c4dbbfd8d31b581a5d930b9c66d996d3bda11a2f / da22b024b1ba07c367e812e3c2f889f60cd3eb9758be906f6d5c231b8b71937b | 17-09 16:43 + 18-09 08:28 |
| EPNPX6VY | host-6ef6 | 82:FB:DF:E6:F2:88 | unit-juliett | Microsoft.Practices.EnterpriseLibrary.Common.dll | bde5bba12f076659ab19d3df625dedc7211180038c821b77b431b62647ef231f | 21-09 10:27 |
| EPSES7ZK | host-4c8d | 5A:26:AC:95:F8:C6 | unit-papa | hp_LJ1020_Full_Solution-v2012_918_1_57980.exe + (1)/(2)/(3)/(4).exe (5 files, same SHA) | f0c485571570100898f2d15531fbe4531ba303a252cd40a79b64c1976a5a9890 | 22-09 08:01 |
| EPF4AJCM | host-e53b | 9A:2A:28:6B:36:12 | unit-golf | libreoffice-calc.desktop | 93ffd792f92437a850e4939c84442391a624e20446cea276fffcfa2a4c664548 | 23-09 20:17 |
| EP2SJ6NE | host-a976 | BE:4C:5C:70:25:8F | unit-bravo | libreoffice-calc.desktop (SAME SHA as above) | 93ffd792... | 26-09 11:06 |
| EPR4BEDS | host-fe94 | 12:37:FF:AA:B0:B9 | unit-romeo | recently-used.xbel | 5e10b349... | 10-09 09:01 |
| EPLDM6PE | host-2d83 | 26:F7:A0:14:54:99 | unit-foxtrot | recently-used.xbel | 5e10b349... | 17-09 06:45 |
| EP3GALVS | host-58bb | 0A:53:EF:A1:B7:E2 | unit-golf | recently-used.xbel | 5e10b349... | 19-09 / 21-09 |
| EPQBJBDX | host-19e6 | 1A:B6:F6:34:07:EC | unit-golf | dash cam.pdf | 30c78bc9ec28a6e4d47708c309f8c88599c71a0fb379a3b4d75847d0f66ef0ca | 24-09 08:48 |
| EPVSWBNA | host-e103 | 0E:D2:71:95:A6:B5 | unit-delta | Strings.dll / launcher.exe / zshp1020s.dll (printer bundle) | ae107170c153cb3eb34c049482722d3937f2c03a6c23cadb9bbdb9034e28b9c0 / 61a67e53c6c0c80a4e95af35a2997ad2ce59720020fc7438991eda3541df73b6 / c6525c5230387653e16f21f408eab8202157b0eddeb180bd91a13e860fbee4f4 | 24-09 12:10 |
| EPWZ7L6L | host-a61e | F2:26:18:8E:08:35 | unit-sierra | ops-electron-app.desktop | dd294df9886197bd68807cee3bf62d10859b4860bd95421dda6bb67db9648dd1 | 25-09 08:08 |
| EPSJWX5J | host-0982 | E6:C0:52:B3:39:08 | unit-golf | Staff_Library_Payment_Final.docx | d831cf990c1445b507ef9fea05a6e483983aa4737fa56fcf650a96af1cee0cd5 | 26-09 08:33 |
| EP7UYCXM | host-2c1e | 8E:FF:DA:6B:FD:44 | unit-alpha | libeToken.so.10.7.77 | 574564cd6ed90f7938ab4967d5802f28cddc38ed1148e42838083ea6553c3be5 | 26-09 15:25 |

### 2b. AV-triggered but NOT quarantined (still-active suspects)
- EPAX5P5D host-0b21 (92:4B:4A:D6:5B:E5) unit-bravo — AV quarantined recently-used.xbel 22/23-09 but NO quarantine-service Malicious row → possible gap / delayed upload.
- EPLFOXSS host-423b (CA:AE:6F:7A:A0:DE) unit-romeo — AV `Attempting to handle: .../evolution/mail/.../1773731387.41169_0.EPLFOXSS` + `File not found or no permissions` continuously 01–19 Sep, quarantine service only `No Malicious files found.` → FAILED remediation, likely active phishing payload.

### 2c. USB events
- EPD24DBC host-7394 (6E:DE:00:D5:9F:8A) unit-foxtrot — `General -UDisk, Mass Storage abcd:1234` 22-09-2026 18:23:12/41 (4 rows = 2 event_times x 2 received_times). No AV/quarantine hit. USB-drop suspect until web pivot clears it.
- EP7FZ2XY host-9764 (F6:6F:85:06:00:26) unit-quebec — Logitech mouse 046d:c077 07-09 — BENIGN.

### 2d. AV / web-filter notes
- av_scan: 0 `FOUND` signature strings (lower-level detection text not logged as FOUND); all `Knownviruses` summaries `Infectedfiles:0` (22 summaries). AV actions inferred only from `Beginning quarantine / Processing / Attempting / Quarantined and deleted / File not found` lines (13 endpoints, 179 rows).
- web_block (914 rows, 74 endpoints): facebook/googleapis/ipify/linkedin/instagram dominated — corporate policy noise, NOT IOCs. Overlap with mal set = 14 endpoints.

## 3. IOC ledger (preliminary, needs web C2)
- File hashes: see table (48 distinct Malicious SHAs; most-reused = 5e10b3490160cca0fc872f2b026d4b40bafc236852f83d30c9031899e50adc9c on 9 endpoints; f0c4855715... on 5 HP installer copies; 93ffd792... shared by EPF4AJCM+EP2SJ6NE libreoffice-calc.desktop).
- Paths: `~/.local/share/recently-used.xbel`, `~/Desktop/DOWNLOAD FOLDER/.../Final_Documents.zip`, `~/Downloads/*.exe`, `~/Desktop/printer/*`, evolution mail cur file, `*.pdf/*.docx/*.xlsx/*.dll/*.cab/*.desktop/*.bundle.js`.
- C2 IPs/domains: TBD from web_activity Phase 2.
- USB: abcd:1234 (General UDisk) on EPD24DBC.

## 3b. Web C2 ledger — CONFIRMED (Phase 2, chunked pandas, 2,812,118 rows / 248 endpoints / 19,027 uniq messages)
Method: global message→endpoint cardinality; `rare = eps<=3`; per-suspect rare≥3 hits; paired same-second domain+IP = DNS→IP of one C2 session. Stripped `.hgu_lan/.bbrouter/.dlink/.local`. `198.18.0.0/15` = anonymized C2 IPs; `svc-<hex>.gov.example` / `n*.svc-*.example` = anonymized C2 domains (per-victim subdomains); widespread `svc-*.gov.example` (eps≥10) = benign Indian-gov portals, ignored.

| endpoint | quarantine file | web C2 (unique, eps=1 unless noted) | beacon pattern (event_time, same-second pairs) | verdict |
|---|---|---|---|---|
| EPZRAPEL host-d14b foxtrot | 53EDA428... (31-08) | `svc-d44578.gov.example` (50, eps1) + `198.18.165.210` (43, eps1) | paired every session 11→19 Sep (e.g. 11-09 19:27:36 x2, 12-09 08:59, 13-09 09:44/09:51/10:57/11:00/11:48, 16-09, 17-09, 18-09, 19-09) | STILL COMPROMISED (persistent 3 weeks post-quarantine) |
| EPVC2P55 host-aca0 alpha | Data1.cab (15-09 11:28) | `svc-148367.gov.example` (152, eps1) + `198.18.227.50` (143 on this host +1 on EPL4KXNW) + `198.41.0.4` (86, eps1) + `40.81.94.65` (75, eps1) | C2 starts 11-09 15:58:42 (AFTER 11:28 quarantine) then 14/17/18 Sep bursts (8–14 sessions/day, ≤1 min apart) | STILL COMPROMISED |
| EPT3KTUL host-ad7a quebec | Dash Camera pdf (11-09 12:06) | `svc-89bec8.gov.example` (35, eps1) + `198.18.251.94` (17) + sub `n7473.svc-89bec8.gov.example` (3) | pairs 10-09 13:46, 11-09 12:07, 12-09 10:27/11:00/14:37/17:39, 19-09 10:11/12:56, 20-09 10:52–11:38 burst | STILL COMPROMISED |
| EPLFOXSS host-423b romeo | NONE (AV mail fail) | `svc-89a41f.gov.example` (20, eps1) + `198.18.40.61` (18, eps1) | pairs 12-09 08:51–08:52, 14-09 09:01–09:20, 16-09 09:13–09:17, 17-09 08:39–08:43; AV `File not found` 01–19 Sep overlapped | ACTIVE PHISHING COMPROMISE (never quarantined) |
| EPWZ7L6L host-a61e sierra | ops-electron-app.desktop (25-09, AFTER web window) | `svc-b76574.gov.example` (13, eps1) + `svc-171e30.gov.example` (10, eps1) + `n2b40.svc-e557f1.gov.example` (6, eps1) | pre-quarantine staging 12-09 08:26/11:35–11:57, 15-09 13:08, 18-09 09:27–10:24, 19-09 12:25/17:47 | COMPROMISED (C2 before file hit = download → persist) |
| EPSES7ZK host-4c8d papa | hp_LJ1020 x5 (22-09) | `freshysearch.com` (61, eps1) + `search.freshy.com` (58) + `i.wallpapers.searchtabnew.com` (45) + `dz2gehduwv9t4.cloudfront.net` (44) — 4-way same-second redirect chain | bursts 10-09 11:22–18:53, 12-09 12:12–13:48, 13-09, 14-09, 16-09, 18-09, 19-09, 20-09 — BEFORE 21-09 AV detection | BROWSER-HIJACKER + trojanized installer (PUA/C2) |
| EPGSQVEB host-9a4f bravo | Final_Documents.zip (11-09 10:11) | `relay-7ef33ce3.net.anydesk.com` + `148.113.17.93` (4 each, eps1) + `relay-59e6d48d.net.anydesk.com` + `148.113.8.189` | Anydesk sessions 15-09 11:07/13:06/15:44, 16-09 14:21, 19-09 12:17/15:22 — ALL AFTER quarantine | REMOTE-ACCESS persist (attacker Anydesk post-payload) |
| EPFQSCDV host-2fe4 juliett | xbel (09/10-09) | `n7093.svc-1943de.gov.example` (188, eps3 with EPCRFN4D/EPV7MB2K) + `n3618.svc-4f2a32.gov.example` (184, eps2) + `34.93.158.11` (131, eps2) + bbrouter twins | shared C2 cluster — EPCRFN4D/EPV7MB2K have NO quarantine (possible undetected co-victims, flag for EDR) | COMPROMISED + 2 co-suspects to triage |
| EPVSWBNA host-e103 delta | printer DLLs (24-09) | NO unique C2 in window; only SBI banking (`yonobusiness/corp.sbi.bank.in` + `103.209.97.10/103.68.221.192`, eps2 with EPR3CJU6) on 10/11/15 Sep BEFORE 23-09 AV hit | banking = user-normal, not C2; C2 outside window or via LAN/printer share | COMPROMISED (file evidence), C2 unknown |
| EPMQTKSL host-942d charlie | xbel (02-09) | NO unique C2; heavy Yahoo (`106.10.218.155` 726 + `c2shb-oao.ssp.yahoo.com` etc, eps2 with EPHXH7MS-clean) = benign Yahoo mail infra, NOT C2 (`c2` in Yahoo hostname is content-server, not CnC) | Yahoo bursts 10→20 Sep daily 08:30–19:20 | COMPROMISED (file), no web C2 in window (likely cleaned 02-09) |
| EP4YIFHV host-a616 lima | 20x bundle.js (11-09) | NO unique C2 (71 uniq all benign Mozilla/DNS; 1034 rows 15→20 Sep sampled) | no beacon post-11-09 → cleaned browser cache | COMPROMISED then CLEANED (no persistence) |
| EPD24DBC host-7394 foxtrot | NONE | NO suspicious (7951 rows: news/youtube/mozilla only; USB 22-09 AFTER web window 10–21 Sep, no overlap) | benign browsing; no AV/quarantine | USB NOT CORROBORATED — low risk, monitor |
| All other 24 mal endpoints (EPOC6Y4R/EPJYEC7F/EPC2L3UH/EPAGTKNF/EPJ42VCZ/EPPGWIOF/EPQKOBYG/EPMDU6L5/EPEEHWSG/EPT3KTUL etc.) | file hits | no eps1 high-count beacon in 10–21 Sep window (only shared benign infra) | consistent with quarantine-before-window + no persistence (or C2 outside window) | COMPROMISED per file evidence; web-persistence NEGATIVE in window |

- Ruled OUT as C2 (high-count but benign): `question` (4012/89eps), `opt` (1533/150eps) = captive/DHCP probes; `epdajrps.local` (1322/8eps, 7/8 romeo) = romeo LAN box; `106.10.218.155`/Yahoo cluster = Yahoo mail CDN; `svc-1ca9c2/n22ce/...` (25k–66k, eps capped 10+) = benign gov/Mozilla infra; `eptmfzsx` (385/eps1) = self-hostname of EPTMFZSX.
- Delay analysis (Phase 3 requirement): quarantine median ~0h (real-time, max 203h, min −0.75h clock-ahead); av_scan median 34h (nightly + 1–3d upload lag, max 562h); web_block median 21h. Per-host: EPC2L3UH 18.4h / EPLFOXSS 31.8h / EPGSQVEB 32.9h medians = offline hosts; negatives = endpoint clock ahead of server — timeline uses event_time with received_time sanity check.

## 4. Hypotheses under test
- Campaign-wide reuse of `recently-used.xbel` hash + `Final_Documents.zip` + trojanized printer drivers + lure docs (dash cam, RAGHAV, Lakeside, Staff_Library, RETIREES WELFARE) suggests multi-vector phishing/drive-by, NOT single USB worm. USB currently looks like dead end but must verify via web logs.
