# CVE Research Repository

个人 CVE 研究仓库，记录发现并验证的漏洞。

## 漏洞列表

| 漏洞 | 项目 | CWE | 状态 |
|---|---|---|---|
| [Mini-Inventory-and-Sales SQL Injection](./Mini-Inventory-SQLi/) | Mini-Inventory-and-Sales-Management-System | CWE-89 | 已提交 VulDB（审核中） |
| [youtube-downloader SSRF](./youtube-downloader-SSRF/) | athlon1600/youtube-downloader | CWE-918 | 已提交 VulDB（审核中） |
| [ossn-code-injection-rce](./ossn-code-injection-rce/) | 见目录 README | CWE-94 | gist 已发布·VulDB 待提交 |
| [vesta-path-traversal](./vesta-path-traversal/) | 见目录 README | CWE-22 | gist 已发布·VulDB 待提交 |
| [opencats-account-takeover](./opencats-account-takeover/) | 见目录 README | CWE-284 | gist 已发布·VulDB 待提交 |
| [fluxcp-ipn-spoof](./fluxcp-ipn-spoof/) | 见目录 README | CWE-346 | gist 已发布·VulDB 待提交 |
| [laravel-easy-pos-install-takeover](./laravel-easy-pos-install-takeover/) | 见目录 README | CWE-798 | gist 已发布·VulDB 待提交 |
| [billabear-install-takeover](./billabear-install-takeover/) | 见目录 README | CWE-862 | gist 已发布·VulDB 待提交 |
| [marketplacekit-sqli](./marketplacekit-sqli/) | 见目录 README | CWE-89 | gist 已发布·VulDB 待提交 |
| [marketplacekit-delete-idor](./marketplacekit-delete-idor/) | 见目录 README | CWE-639 | ❌ COVERED(GitHub issue #164/#162)勿提交 |
| [rhaphp-ssrf](./rhaphp-ssrf/) | 见目录 README | CWE-918 | gist 已发布·VulDB 待提交 |
| [fuelcms-eval-rce](./fuelcms-eval-rce/) | 见目录 README | CWE-94 | ❌ COVERED(CVE-2018-16763)勿提交 |
| [manong-sql-injection](./manong-sql-injection/) | 见目录 README | CWE-89 | gist 已发布·VulDB 待提交 |
| [manong-stored-xss](./manong-stored-xss/) | 见目录 README | CWE-79 | gist 已发布·VulDB 待提交 |
| [lms-message-idor](./lms-message-idor/) | 见目录 README | CWE-862 | ❌ COVERED(GitHub issue #92)勿提交 |
| [benotes-ssrf](./benotes-ssrf/) | 见目录 README | CWE-918 | gist 已发布·VulDB 待提交 |
| [easyimages-arbitrary-file-read](./easyimages-arbitrary-file-read/) | 见目录 README | CWE-22 | ❌ COVERED(CVE-2023-7098)勿提交 |
| [easyimages-arbitrary-delete](./easyimages-arbitrary-delete/) | 见目录 README | CWE-22 | gist 已发布·VulDB 待提交 |
| [openvk-config-read](./openvk-config-read/) | 见目录 README | CWE-22 | gist 已发布·VulDB 待提交 |
| [openvk-poll-enumeration](./openvk-poll-enumeration/) | 见目录 README | CWE-862 | gist 已发布·VulDB 待提交 |
| [gitscrum-unauth-upload-rce](./gitscrum-unauth-upload-rce/) | 见目录 README | CWE-434 | ❌ COVERED(issue #369 在先披露+厂商拒修)勿提交 |
| [laravel-filemanager-rename-rce](./laravel-filemanager-rename-rce/) | 见目录 README | CWE-22 | ❌ COVERED(CVE-2022-40734)勿提交 |
| [hms-auth-bypass](./hms-auth-bypass/) | 见目录 README | CWE-89 | ❌ COVERED(GitHub issue #71)勿提交 |
| [hms-panel-update-sqli](./hms-panel-update-sqli/) | 见目录 README | CWE-89 | ❌ COVERED(GitHub issue #64/#53)勿提交 |
| [hms-union-exfiltration](./hms-union-exfiltration/) | 见目录 README | CWE-89 | ❌ COVERED(GitHub issue #64)勿提交 |
| [hms-contact-insert-sqli](./hms-contact-insert-sqli/) | 见目录 README | CWE-89 | ❌ COVERED(GitHub issue #49/#6)勿提交 |
| [hms-appointment-sqli](./hms-appointment-sqli/) | 见目录 README | CWE-89 | gist 已发布·VulDB 待提交 |
| [edoc-registration-sqli](./edoc-registration-sqli/) | 见目录 README | CWE-89 | ❌ COVERED(CVE-2023-1058)勿提交 |
| [edoc-admin-insert-sqli](./edoc-admin-insert-sqli/) | 见目录 README | CWE-89 | ✅ CVE-2026-60137(已分配) |

## 说明

- 每个漏洞一个目录，包含：漏洞详情、PoC、提取证据
- 所有验证均在本地隔离环境完成
