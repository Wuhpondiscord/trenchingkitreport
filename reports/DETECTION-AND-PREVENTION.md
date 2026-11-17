# Detection, Prevention and Malware-Analysis Guide

*Practical lessons from the Trenchingkit Axiom-targeted bookmarklet case. Audience: everyday crypto users, security enthusiasts, SOC analysts, incident responders, and sandbox researchers.*

> **Bottom line:** **A clean antivirus result, a 0/XX VirusTotal score, or a low-severity sandbox verdict does not guarantee safety.** In this case, the decisive signs were discovered by inspecting **network logs, DevTools errors, the JavaScript source, and a controlled synthetic run**, not by relying solely on an automated classification.

## 1. The attack pattern to recognize

This campaign illustrates a common malicious workflow:

1. A third-party site offers a shortcut, trading helper, bookmarklet or other “enhancement.”
2. It asks you to save a link starting with `javascript:` and run it on a trusted site.
3. The code runs in the **current webpage's context** and may interact with that application's session, APIs and local browser storage.
4. It may display a realistic, professional-looking UI to seem legitimate.
5. In the background, it tries to collect sensitive wallet material, package it and send it to an external destination.

This is **not** a necessary feature of all bookmarklets. Many are benign. The warning sign is the untrusted origin, unclear behavior, sensitive access and requests to execute code inside a financial account.

### Specific warning signs from Trenchingkit

- An obfuscated `javascript:` bookmarklet copied from an unrelated domain.
- A call to the wallet-related Axiom API `/bundle-key-and-wallets-v2`.
- Reads of `sBundles`, `bBundles` and related localStorage keys.
- Web Crypto AES-GCM decryption in code presented as a social/trading overlay.
- Objects with fields `private`, `public` and `chain`.
- A dynamic CSS `@font-face` rule aimed at a `trycloudflare.com` host with a long `nocache` query value.
- A busy social feed and dozens of avatar-image requests distracting from the above.

**Caution:** not every occurrence of an API call, Web Crypto, cloud tunnel or font request is malicious. The *combined behavior and intent* matter.

## 2. How to avoid this as a normal user

- **Don't activate unknown bookmarklets on pages where you're logged in.** Especially avoid third-party “alpha,” trading, analytics, wallet unlock or verification scripts.
- **Treat instructions to paste code in DevTools as high risk.** Developers' consoles execute arbitrary page-context JavaScript. Warning banners are there for a reason.
- **Use only official wallet and trading integrations.** Verify the domain independently; don't trust branding, social-media posts or lookalike UI.
- **Keep crypto wallets separated.** Use distinct accounts/browser profiles for experimentation versus assets; don't import a valuable seed phrase into a test environment.
- **Use hardware-wallet signing and review transactions where available.** This may reduce exposure for supported workflows, but it will not guarantee protection against every wallet or approval attack.
- **Consider a dedicated browser profile for financial activity.** Keep experimental extensions, scripts and bookmarklets out of it.
- **Check any instructions requiring you to “run a tool on Axiom” or another wallet site.** Ask what code is executing and why a service needs that access.
- **Stay updated.** Browser and OS updates help against technical vulnerabilities, though user-initiated scripts can still be dangerous on fully patched systems.

If a page tells you to open the console and enter `allow pasting` to enable running a script, that is a **strong reason to stop and independently review what is being pasted**.

## 3. What to do if you already ran an unknown bookmarklet

If a wallet may have been exposed:

1. **Stop using the affected browser session for sensitive transactions.** Don't run the bookmarklet again.
2. **Preserve evidence first if safe to do so:** URL, timestamp, bookmarklet source, site screenshot, browser history, relevant network records and any wallet transaction hashes.
3. **Use a different trusted device/browser to secure accounts.** Sign out sessions, change site passwords and enable MFA as appropriate. These protect the account login, but **cannot revoke a leaked blockchain private key**.
4. **Treat potentially exposed wallet private keys as compromised.** For wallets with real assets, follow provider guidance to move remaining funds to new independently generated wallet(s) in a trusted environment. Do not reuse the old seed/private key.
5. **Review approvals, connected apps and outgoing transactions**, depending on chain and wallet type. Do not sign unknown “revoke” or “recovery” transactions delivered through DMs.
6. **Report the incident** to the wallet/trading provider, appropriate browser/vendor abuse channels and relevant authorities as appropriate.
7. **Avoid “recovery agents” who contact you privately** promising to recover crypto for an advance payment or asking for your seed phrase.

No analyst, provider, or support agent needs your seed phrase or private key to investigate public transactions.

## 4. What VirusTotal is useful for — and why it may miss this

**Tool:** [VirusTotal](https://www.virustotal.com/)  
**Documentation:** [How it works](https://docs.virustotal.com/docs/how-it-works), [Reports](https://docs.virustotal.com/docs/results-reports)

VirusTotal aggregates many antivirus engines and URL/domain reputation systems. It is excellent for **hash reputation, known malicious infrastructure, community context, prevalence, vendor labels, and quick correlation**.

But **do not treat a 0-detection result as proof a bookmarklet is safe**:

- This sample was primarily **obfuscated JavaScript executed by a user inside a browser page**, not a conventional executable attachment.
- Its most consequential behavior depended on **application context, session, localStorage, and dynamic Web Crypto**, which a static URL/file scan may not reproduce.
- Strings can be concealed in decoder tables and aliases, rather than appearing directly in the source.
- The suspected data transmission uses **CSS browser-resource loading** and a query parameter, not necessarily a recognizable malware binary or obvious `fetch` call.
- Brand-new sites or short-lived tunnel URLs may have little reputation history.
- A submitted **landing-page URL** is not the same artifact as the full obfuscated bookmarklet or the network behavior after activation.
- A provider's detection set changes over time; an old “clean” scan is only a historical data point.

**Important nuance:** We did **not** record a verified VirusTotal verdict for this exact bookmarklet in the evidence reviewed. Saying “VirusTotal missed it” as a factual test result would be unsupported. The supported claim is that **VirusTotal alone would not reliably establish safety for this class of context-dependent, obfuscated bookmarklet**. Even if an engine detects it, behavioral review is still valuable.

**Privacy warning:** VirusTotal submissions may be shared with security partners or customers. Never upload authentic recovery phrases, unredacted browser HARs, private keys, session cookies, or a URL containing a live private-key-bearing `nocache` parameter.

## 5. Hatching Triage — why logs matter more than a single score

**Tool:** [Hatching Triage](https://tria.ge/)  
**Documentation:** [Behavioral report structure](https://us-sandbox.recordedfuture.com/docs/cloud-api/dynamic-report/)

Triage can collect useful behavioral, process, DNS and HTTP observations, and may provide signatures and an overall verdict. Its report structure explicitly distinguishes **signatures** from **network** and other report sections.

**What happened in our case:**

- The automated assessment did **not surface the credential-theft sequence as an obvious malicious finding** in the user's run.
- But its underlying logs showed a `POST` to `api9.axiom.trade/bundle-key-and-wallets-v2`, alongside the website's script fetch and many avatar requests.
- DevTools showed the Axiom API attempt was **401 Unauthorized and CORS-blocked** when executed from `trenchingkit.com`. That explained why the original run did not proceed to a successful wallet-read path.
- A **separate synthetic test** using invalid fabricated key material mocked the wallet API response and localStorage. It reached construction of a Cloudflare-Tunnel CSS URL and logged `BLOCKED_CSS_RESOURCE` with two key-record objects.
- The harness **intercepted the malicious stylesheet before insertion**: this did not establish that an external server received keys.

The key lesson: **the automated Triage verdict missed the significance of what the investigator could establish by inspecting the logs and source**. This is a **case-specific observation**, not a claim that Triage is generally unable to detect bookmarklet theft or a measured false-negative rate.

### How to review a Triage report

1. **Start with the timeline**, not just a risk score. Identify what browser, scripts, endpoints and user actions were involved.
2. **Check all DNS and HTTP records**, including requests that returned 401/403/404 or were blocked. Failed requests are frequently highly informative.
3. **Separate benign-looking support traffic from sensitive API calls.** Here, dozens of `unavatar.io` image fetches were UI decoration; a single Axiom wallet-data POST was more consequential.
4. **Read raw request metadata:** method, hostname, path, initiating process, response status and timing. Avoid posting authentication headers or raw key-bearing URLs.
5. **Search for secondary channels:** font URLs, stylesheets, images, redirects, WebSockets, beacons, and navigations; not only `fetch` or `POST`.
6. **Correlate browser console errors with network traces.** In this case, CORS and 401 explained a missing later-stage request.
7. **Inspect the downloaded script statically.** An HTTP log alone won't explain encryption or serialization.
8. **Use a controlled synthetic fixture when necessary**, with independent network isolation and no real wallet, to understand reachable branches. Preserve the limits of this evidence.
9. **Document both positive and negative findings.** An absent exfil request in a failed run doesn't negate static evidence of exfil code; a constructed URL doesn't prove a server received anything.

**Never use a live personal wallet or valuable account just to make malware “finish.”**

## 6. ANY.RUN — interactive behavioral follow-up

**Tool:** [ANY.RUN](https://any.run/)  
**Documentation:** [Interactive sandbox features](https://any.run/features/)

ANY.RUN emphasizes an interactive environment where an analyst can inspect HTTP requests, DNS, process behavior and browser activity. This is useful for **interactive, user-triggered or multi-stage browser threats** that aren't fully understood from static files.

Suggested defensive workflow:

- Submit only samples and URLs you're authorized to analyze.
- Use a disposable environment and avoid any real account login or wallet material.
- Watch the browser interactions, network events and triggered detection rules separately.
- Look for dynamic DOM injection, unexpected requests to financial APIs, sensitive storage access and unusual CSS or font resource URLs.
- Correlate the original obfuscated code with actual behavior; don't rely only on screenshots of the decoy UI.
- Export or save **sanitized** IOC/event observations and screenshots, not real secrets.

**This report does not contain a completed ANY.RUN run of Trenchingkit.** ANY.RUN is presented as a useful independent analysis option, not as a tool whose verdict has been tested or proven on this sample.

## 7. Comparison: use complementary tools, not a “winner”

| Investigation question | VirusTotal | Triage | ANY.RUN |
| --- | --- | --- | --- |
| Is a hash or domain already known? | **Strong fit** | Can add sandbox context | Can add sandbox/threat context |
| Which HTTP/DNS requests occurred during execution? | Limited compared with a live browser sandbox | **Strong fit** | **Strong fit** |
| Did the browser encounter CORS/401 errors? | Usually not a substitute for a live DevTools session | Inspect browser/network evidence where captured | Inspect browser/network evidence where captured |
| Was an obfuscated string decoded to an endpoint? | Sometimes via vendor/static artifacts | Supplement with static source analysis | Supplement with static source analysis |
| Did the JavaScript use localStorage and Web Crypto? | Not consistently demonstrated by scan verdicts | May need source/manual instrumentation | May need source/manual instrumentation |
| Is a 0/clean verdict proof of safety? | **No** | **No** | **No** |
| Can it safely use a victim's wallet? | **Do not submit secrets** | **Do not use real credentials** | **Do not use real credentials** |

Use [Chrome DevTools](https://developer.chrome.com/docs/devtools/network/) as a fourth, often indispensable component: Preserve log, Network methods/status/initiators, Console errors, and Sources are often more specific than top-level scanner alerts.

## 8. A safe step-by-step research workflow

### Phase A — Collect without executing

- Preserve URLs, screenshots, suspicious instructions and the saved `javascript:` bookmarklet text.
- Hash each file and record *exactly what was hashed* (raw bytes vs percent-decoded JS body).
- Read source as **text**, not by pasting it into an authenticated browser.
- Identify APIs, storage keys, crypto methods, URL construction, dynamic DOM insertion and known IOCs.
- Be alert for intentional obfuscation and fake UI content.

### Phase B — Inspect in a sandbox

- Start a disposable VM/browser with no sensitive accounts or wallet extensions.
- Capture process, network, DNS and browser console data.
- Observe the ordinary failure path first; errors reveal prerequisites.
- Don't weaken CORS or disable browser security as a shortcut.
- Do not permit outgoing credential-bearing requests just to “prove” exfiltration.

### Phase C — Validate claims with controlled fixtures

- If the behavior depends on a wallet or login, simulate the relevant data **only in an isolated environment** using deliberately invalid material.
- Block outbound network connectivity below the JavaScript layer; hooks alone are not sufficient containment.
- Log destination, method, schema, timing and payload length **without logging secret values**.
- Distinguish “the code *constructed* an exfil request” from “a server *received* it.”
- Check whether the data passed validation and was genuinely decrypted; a string property called `private` is insufficient proof.

### Phase D — Turn observations into actionable detection

- Publish a timeline, sample hash/normalization rule, URLs and endpoint paths.
- Group indicators by role: delivery, legitimate target API, suspected collection endpoint, decoy/UI services.
- Submit sanitized findings to browser-blocklist projects, security platforms and relevant providers.
- Distinguish confirmed facts from hypotheses, and update the report as new evidence appears.

## 9. Concrete log-reading checklist

When a suspicious link/script comes back “clean,” ask:

- What exact code did the site load? Does it attach a `javascript:` link?
- Did it request unusual data from a legitimate platform's authenticated endpoints?
- Which browser storage keys, cookies or extension APIs did it access?
- Is Web Crypto or another decoder handling material that doesn't fit the advertised UI?
- What external hostnames appear in *CSS*, image, font, WebSocket and beacon resources?
- Are long Base64/URL-encoded strings being placed into query parameters?
- Did CORS, authorization, CSP or network failures interrupt the sequence?
- Is the sandbox missing a user click, a session or a prerequisite to reveal later behavior?
- What can be reproduced with **synthetic invalid data** safely?
- Is the conclusion tied to actual observed events, or just to an automated malware label?

## 10. Reporting this case responsibly

Suggested artifacts for a provider/vendor report:

~~~text
Delivery website: trenchingkit.com
Delivery script: /script.js
Target API: https://api9.axiom.trade/bundle-key-and-wallets-v2
Suspected off-site host: curve-aware-epic-visitors.trycloudflare.com
Resource path: /api/logo.png
Query keys: uid, nocache
Storage keys: sBundles, bBundles, eBundles, bscBundles,
              evmBundles, ethBundles, ethereumBundles, binanceBundles
Evidence: 401/CORS failure in original run; synthetic run recorded
          MOCK_AXIOM_POST, MOCK_STORAGE and BLOCKED_CSS_RESOURCE
~~~

**Do not publish or upload full credential-bearing query strings**, cookies, seed phrases or wallet private keys. An external exfil hostname is not the same thing as an on-chain receiving address.

## 11. Further reading and official product docs

- [VirusTotal: How it works](https://docs.virustotal.com/docs/how-it-works)
- [VirusTotal: Understanding reports](https://docs.virustotal.com/docs/results-reports)
- [Triage behavioral report structure](https://us-sandbox.recordedfuture.com/docs/cloud-api/dynamic-report/)
- [Hatching Triage](https://tria.ge/)
- [ANY.RUN sandbox features](https://any.run/features/)
- [Chrome DevTools Network panel](https://developer.chrome.com/docs/devtools/network/)

---

**Final takeaway:** Automated scanning is a useful filter, not a forensic conclusion. In this incident, the **network logs and manual analysis exposed suspicious wallet-access behavior that the automated assessment did not make apparent**. The most effective defense combines safer user practices, controlled sandboxing, source inspection and careful interpretation of raw evidence.

See [Payload Anatomy](PAYLOAD-ANATOMY.md) and [Main Investigation](../README.md).
