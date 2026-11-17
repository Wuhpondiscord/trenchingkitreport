# Trenchingkit: Analysis of an Axiom-Targeted Wallet-Stealing Bookmarklet

**Research writeup | November 16–17, 2026 (timestamps in UTC unless stated otherwise)**

> **Status:** Static analysis plus controlled dynamic validation using *synthetic, deliberately unusable* wallet material. This report documents an attempted credential-theft workflow. It does **not** establish an actual victim loss, successful exfiltration of a real wallet, or an on-chain destination address.
>
> **Safety:** Treat any original bookmarklet, website JavaScript, and decrypted data as untrusted. Don't execute the payload in an authenticated wallet session. This repository intentionally publishes **sanitized excerpts**, not ready-to-run malicious source or private keys.

## Companion reports

- **[Bookmarklet Payload Anatomy — full reverse-engineering breakdown](reports/PAYLOAD-ANATOMY.md)** — delivery, obfuscation, decoy UI, storage, AES-GCM, CSS exfiltration and the synthetic-wallet findings.
- **[Detection, Prevention and Analysis Guide](reports/DETECTION-AND-PREVENTION.md)** — warning signs, protective steps, Triage/ANY.RUN/VirusTotal comparison and a log-first analysis workflow.

## Summary

We investigated a website advertising a crypto-trading-themed “Trenchingkit” experience, with a JavaScript bookmarklet distributed through its external `script.js` file. The bookmarklet creates a convincing social/trading-style overlay, but its more consequential behavior is a wallet-data collection routine aimed at an Axiom Trade browser session.

The recovered logic:

1. Makes a credentialed `POST` to Axiom's `/bundle-key-and-wallets-v2` endpoint.
2. Reads local wallet bundle records from several `localStorage` keys.
3. Imports a returned `bundleKey` for **AES-GCM** operations and attempts to decrypt locally stored bundles.
4. Formats candidate wallet key records with `private`, `public`, and `chain` fields.
5. Encodes the records as JSON/Base64 and places the value in the `nocache` query parameter of a CSS `@font-face` resource pointing to a Cloudflare Tunnel hostname.
6. Appends the stylesheet and a hidden element intended to make the browser request the font resource.

In the *original Triage network observation*, the Axiom request failed (HTTP 401/CORS from the attacker-site origin). We **did not** observe a request to the suspected exfiltration host in that run.

We then used an isolated, synthetic test harness to intercept the Axiom API call, provide artificial AES-GCM-encrypted bundle data, and block the suspicious stylesheet insertion. The bookmarklet reached the stylesheet-construction point and attempted to embed **two synthetic key records**, one labeled `Solana` and one `BNB/BSC`, in the outbound URL. **No real wallet was provided. No exfiltration request was allowed by the interception.**

The data flow is consistent with **private-key theft**, not direct manipulation of Axiom to broadcast a forged transfer. We have not found a hardcoded cryptocurrency receiving address or an explicit transaction-broadcast routine in the inspected sample.

## At-a-glance findings

| Finding | Assessment | Evidence |
| --- | --- | --- |
| Website serves an obfuscated bookmarklet | Confirmed | Recovered `script.js` defines `BOOKMARKLET_CODE` and sets the `bmark` link's `href` |
| Calls Axiom wallet endpoint | Confirmed | Static source and Triage HTTP `POST` |
| Successful cross-origin reading from `trenchingkit.com` | **Not demonstrated** | CORS mismatch and `401 Unauthorized` in the original run |
| Reads wallet-related browser storage | Confirmed | Static source; synthetic test `MOCK_STORAGE`/`EMPTY_STORAGE` |
| Attempts AES-GCM key import/decryption | Confirmed in static code | `crypto.subtle.importKey` / `crypto.subtle.decrypt` |
| Constructs encoded JSON with private-key fields | Confirmed | Static source and intercepted synthetic CSS payload summary |
| Actual request reached attacker-controlled endpoint | **Not confirmed** | Interception prevented stylesheet insertion; earlier network capture did not show the host |
| Forged cryptocurrency transfers | **Not observed** | No identified signing/broadcast transaction path |
| Attacker's on-chain receiving wallet | **Unknown** | No identified fixed destination wallet in recovered sample |
| Same bookmarklet in website script and original sample | Confirmed **after percent-decoding** | SHA-256 of normalized source matches |

## 1. Scope and evidence

The investigation combined the following artifacts:

- **Original bookmarklet capture:** obfuscated JavaScript, with portions percent-encoded in the saved source.
- **Recovered `trenchingkit.com/script.js`:** website-side JavaScript assigning the bookmarklet URL to a page element.
- **Static reconstruction:** Python-based string-table/lookup decoding, wrapper simplification, formatting, and manual inspection. Some obfuscation and dead branches remain.
- **Triage network trace:** browser DNS, website loads, numerous avatar-image requests, and a failed Axiom API request.
- **Browser DevTools output:** CORS and authorization errors from the initial run.
- **Controlled synthetic-wallet test:** a console-injected instrumentation harness, in a sandbox, that mocked one Axiom response, mocked bundle storage reads, and intercepted the malicious CSS insertion.
- **Harness report:** timestamps, intercepted endpoint, storage keys, CSS URL metadata, key-record count and chain labels.

We did not obtain a real victim's private keys, a genuine Axiom endpoint response body, a verified successful transfer of stolen credentials to the remote host, or the victim's blockchain transaction history.

### Evidence-confidence conventions

- **Observed:** directly present in an uploaded artifact or a logged event.
- **Inferred:** reasonable explanation of observed behavior, but not independently validated.
- **Unverified:** would require additional traffic, authenticated-session testing, victim evidence, or blockchain evidence.

## 2. Infrastructure and indicators

The indicators below are for detection, correlation, and reporting. The presence of a domain in an incident does not imply that every service operator mentioned participated maliciously.

| Indicator | Type | Role | Evidence |
| --- | --- | --- | --- |
| `trenchingkit.com` | Domain | Bookmarklet delivery site | Website/DNS/HTTP logs |
| `https://trenchingkit.com/script.js?v=1792710692061` | URL | Website script distributing bookmarklet | Browser HTTP GET |
| `/script.js` | Path | Script defines `BOOKMARKLET_CODE` | Recovered source |
| `api9.axiom.trade` | Domain | Legitimate Axiom API host targeted by code | Static source/HTTP POST |
| `/bundle-key-and-wallets-v2` | Path | Wallet-related API route | Static source/HTTP POST |
| `curve-aware-epic-visitors.trycloudflare.com` | Hostname | **Suspected credential-collection endpoint** encoded in CSS | Static source/intercepted synthetic CSS |
| `/api/logo.png` | Path | Resource-shaped path used in CSS URL | Static source/intercepted synthetic CSS |
| `uid=8826609600` | Query field | Constant identifier in exfiltration URL | Static source/intercepted synthetic CSS |
| `nocache` | Query field | Carrier for encoded JSON payload | Static source/intercepted synthetic CSS |
| `unavatar.io/x/<handle>` | URL pattern | Profile pictures in decoy social feed | Triage HTTP GET; UI source |
| `fonts.googleapis.com` / `fonts.gstatic.com` | Domains | Browser font traffic | Triage DNS; no malicious role established |

**Important:** A `trycloudflare.com` subdomain is a tunnel endpoint, not a cryptocurrency wallet address. The specific hostname may be ephemeral.

### Hashes and reproducibility

Hashes are calculated over **specific representations** of the source. They must not be mixed up with the hash of a network response, executable, or the entire website script.

| Artifact / normalization | Size | SHA-256 |
| --- | ---: | --- |
| Original saved obfuscated `payload.txt` (including percent escapes) | 149,927 UTF-8 bytes | `6e1a002511131b43ed78becb013640c5bfa271c419725b541274bbf2067bf5aa` |
| Bookmarklet JavaScript body **after percent-decoding**, without leading `javascript:` | 139,406 UTF-8 bytes | `0c1ce82442ca1be2880320ccf1cc15b6a5b0ef05172e1b249a48d2633345cc6d` |

The JavaScript body extracted from the recovered website `BOOKMARKLET_CODE` string is **139,406 characters** and matches the **percent-decoded original bookmarklet body**. This is a normalized match, **not a byte-for-byte match between the original saved 149,927-byte text and the website's entire `script.js` HTTP response**.

The provided pasted website-script transcript includes a label line above the source. Accordingly, **its file hash is not presented as the authentic HTTP response hash**. For exact `script.js` IOC hashing, preserve and hash the raw response bytes from Triage/DevTools.

## 3. Delivery mechanism: the bookmarklet

The website script contains an obfuscated JavaScript string beginning with a `javascript:` URL and assigns it to the bookmark link:

~~~javascript
// Abbreviated, non-executable excerpt of the website's delivery logic.
const BOOKMARKLET_CODE = "javascript:function _0x347a(...) /* obfuscated body */";
document.getElementById("bmark").href = BOOKMARKLET_CODE;
~~~

This is significant because a bookmarklet executes in the context of the **page on which the user activates it**, not necessarily the page where they obtained or dragged the bookmark link.

That origin distinction matters for the Axiom request: executing a script from `trenchingkit.com` is not equivalent to running a bookmarklet while the browser is displaying `axiom.trade`.

The page's use of “Trenchingkit” branding, finance-themed controls, and a social feed appears intended to make the script seem like a trading utility. That motivation is inferred; the interface construction is visible in the source.

## 4. Obfuscation and static reconstruction

The original source is heavily obfuscated:

- Hexadecimal-style identifiers such as `_0x347a` and `_0x388529`.
- A large string table decoded via a Base64-like stage and an RC4-like transform.
- Runtime lookup helpers and aliases.
- Helper-object functions such as indirect calls and arithmetic wrappers.
- Computed properties, concatenated literals, hex arithmetic, and deliberately redundant conditional branches.
- Long, plausible-looking social-feed data mixed with attack logic.

Representative lookup-table patterns, simplified from the recovered source:

~~~javascript
const lookup = {
  UMbPi: "BNB/BSC",
  dfDQE: "tracker",
  alqKw: function (fn, value) { return fn(value); },
  yAlzv: function (a, b) { return a + b; }
};
~~~

The deobfuscation work used *static* decoding and rewriting; it did not intentionally execute the recovered bookmarklet. In one iteration, unsafe text-based arithmetic/string rewrites produced malformed JavaScript, and the tool was subsequently tightened with syntax checks. Therefore, screenshots or excerpts of an intermediate “deobfuscated” output should not be treated as a perfect semantic reconstruction.

A later local decoding pass resolved **2,373 lookup calls across 36 aliases** in this sample. One lookup containing non-printable decoded characters was intentionally left unresolved. These counts describe the analyst's decoding tooling, **not characteristics of the malicious program**.

## 5. Decoy interface

The code constructs a centered dark overlay and an X/Twitter-style financial feed. The interface references public figures and crypto-related accounts, including profile image requests to `unavatar.io`, for example:

~~~text
GET https://unavatar.io/x/elonmusk
GET https://unavatar.io/x/cz_binance
GET https://unavatar.io/x/solana
GET https://unavatar.io/x/coinbase
~~~

A timer adds fresh-looking items to the displayed feed. This activity explains much of the otherwise noisy browser network trace.

These avatar endpoints are **presentation resources** in the observed code. They are not evidence that the impersonated accounts or the avatar provider are responsible for the attack.

## 6. Wallet-related API request

The meaningful wallet-collection stage begins after the overlay setup. The recovered source shows:

~~~javascript
// Excerpt simplified from static reconstruction.
const walletApiResponse = await fetch(
  "https://api9.axiom.trade/bundle-key-and-wallets-v2",
  { method: "POST", credentials: "include" }
);
if (!walletApiResponse.ok) {
  /* display connection failure and return */
}
const walletApiData = await walletApiResponse.json();
const encryptedWalletBundleKey = walletApiData.bundleKey;
const serverWalletRecords = walletApiData.wallets || [];
~~~

`credentials: "include"` asks the browser to attach eligible credentials such as cookies. **It does not override same-origin policy or CORS.** Cookies can also be excluded by browser cookie policies.

The code expects at least a `bundleKey` property and a `wallets` array; we **have not independently confirmed** this exact schema against a successful authentic Axiom response. In the synthetic run, we intentionally supplied those fields.

### What the initial Triage run showed

The browser reached:

~~~http
POST https://api9.axiom.trade/bundle-key-and-wallets-v2
~~~

But DevTools reported a cross-origin block:

~~~text
Request origin: https://trenchingkit.com
Access-Control-Allow-Origin: https://axiom.trade
net::ERR_FAILED
401 Unauthorized
TypeError: Failed to fetch
~~~

This establishes an **attempted request**, not successful access to wallet information. CORS prevented the response from being exposed to JavaScript running at the attack-site origin. The unauthorized response also means no successful authenticated API read was demonstrated in this trace.

A bookmarklet executed on an actual `axiom.trade` page would have a different origin context. Whether the current attack succeeds there would require separate, appropriately authorized evidence; it is **not proven by this run**.

## 7. Browser storage discovery

The script reads an initial `sBundles` array and checks several other wallet-related keys. The actual storage identifiers observed are:

~~~text
sBundles
bBundles
eBundles
bscBundles
evmBundles
ethBundles
ethereumBundles
binanceBundles
~~~

The recovered logic parses each stored JSON array and combines nonempty additional arrays.

~~~javascript
// Simplified depiction of inspected read behavior.
const solanaBundles = JSON.parse(localStorage.getItem("sBundles") || "[]");
const additionalKeys = [
  "bBundles", "eBundles", "bscBundles", "evmBundles",
  "ethBundles", "ethereumBundles", "binanceBundles"
];
~~~

**Storage keys alone do not tell us which wallet products or networks actually exist in the victim's browser.** The script labels `sBundles` output as Solana and all additional-bundle output as `BNB/BSC`, which is the author's classification, not independent blockchain verification.

## 8. AES-GCM processing and key collection

The code imports the API-derived bundle key for decryption, then splits individual stored records on `:`, decoding the IV and ciphertext:

~~~javascript
// Sanitized excerpt of recovered logic; key material omitted.
const importedKey = await crypto.subtle.importKey(
  "raw",
  decodeBase64Url(encryptedWalletBundleKey),
  { name: "AES-GCM" },
  false,
  ["decrypt"]
);

async function decryptBundle(encryptedRecord) {
  const [encodedIv, encodedCiphertext] = encryptedRecord.split(":");
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64Url(encodedIv) },
    importedKey,
    decodeBase64Url(encodedCiphertext)
  );
  return new Uint8Array(decrypted);
}
~~~

For successfully processed records, the script constructs objects of the form:

~~~javascript
{
  private: "<derived key representation — REDACTED>",
  public: "<walletAddress from server record or empty string>",
  chain: "Solana" // or "BNB/BSC"
}
~~~

The Solana branch includes Base58-style encoding; the additional-bundle branch represents bytes as hex with a `0x` prefix. On decryption errors, the recovered code may still emit a record whose `private` string is `"ERROR"`. Thus, merely finding a `private` property in the serialized object is **not by itself proof of valid, usable private-key recovery**.

This behavior fits a **credential-harvesting** design more directly than a forged trading transaction. We did not identify a direct `signTransaction`, `sendTransaction`, or broadcast path in the inspected decoded flow; that absence is bounded by the source and reconstruction quality.

## 9. Exfiltration: data placed into a CSS resource URL

After collecting records, the script serializes them into the structure below:

~~~javascript
// Structural excerpt; no real or synthetic secrets included.
const serialized = JSON.stringify({
  keys: collectedKeyRecords,
  timestamp: Date.now(),
  source: "tracker",
  totalKeys: collectedKeyRecords.length
});
const encoded = btoa(serialized);
~~~

It then attempts to form a CSS font rule with a resource URL shaped like:

~~~text
https://curve-aware-epic-visitors.trycloudflare.com/api/logo.png
  ?uid=8826609600
  &nocache=<URL-ENCODED-BASE64-JSON-REDACTED>
~~~

The original program writes the URL into an `@font-face` `src: url(...)` rule, appends a `style` element to `document.head`, and creates a nearly invisible element using that font family.

This is a suspected **CSS-resource exfiltration** mechanism: browsers can load external URLs as stylesheet-referenced resources, and a URL's query string can carry data. The `/api/logo.png` path is camouflage in this context; the source uses it as a font-resource URL, not as proof that a real image is fetched.

We **do not claim** that a real external font request occurred. Whether it would execute depends on browser/CSP/network/font behavior and the actual page environment.

## 10. Controlled synthetic-wallet experiment

### Goal

Test the bookmarklet's behavior *after a successful-looking wallet API response* without creating a real Axiom wallet or providing usable keys to an external service.

### Design

The research harness ran in an isolated browser/test environment and installed JavaScript instrumentation **before** activating the bookmarklet:

- Intercepted `window.fetch` specifically for `https://api9.axiom.trade/bundle-key-and-wallets-v2`.
- Returned an artificial HTTP `200` JSON object containing `bundleKey` and two synthetic `wallets` records.
- Generated a random AES-256 key locally with Web Crypto.
- Created AES-GCM encrypted *invalid, labeled test material*, encoded as `base64url(iv):base64url(ciphertext)`.
- Supplied one synthetic record under `sBundles` and one under `bBundles`.
- Returned empty arrays for other `*Bundles` storage reads.
- Intercepted insertion of a suspicious `style` element containing the Cloudflare Tunnel/CSS URL **before adding it to the DOM**.
- Logged **only metadata** (host, path, key count, chain labels, parameter length) rather than dumping private fields or the full `nocache` value.

The experiment did not authenticate to Axiom and did not test real wallet decryption.

#### Representative sanitized fixture

~~~json
{
  "bundleKey": "[BASE64URL SYNTHETIC AES KEY — REDACTED]",
  "wallets": [
    { "walletAddress": "LAB_ONLY_SOLANA_NOT_AN_ADDRESS" },
    { "walletAddress": "LAB_ONLY_BSC_NOT_AN_ADDRESS" }
  ]
}
~~~

These “addresses” are obvious placeholders, not valid recipient accounts. The underlying synthetic plaintexts were labeled `INVALID_TEST_MATERIAL:SOLANA` and `INVALID_TEST_MATERIAL:BSC`.

**Containment limitation:** Overriding `fetch` or DOM insertion is not a complete network sandbox. Other browser resource loaders could bypass the hooks; independent outbound-network isolation was part of the recommended test procedure. The event log verifies **suppression of the particular stylesheet insertion observed**, not that every conceivable network side effect was blocked.

### Results

The DevTools console reported the following timeline (UTC, November 17, 2026):

| Time | Event | Meaning |
| --- | --- | --- |
| `02:06:05.716` | `READY` | Instrumentation installed; two synthetic wallet records prepared |
| `02:06:10.479` | `MOCK_AXIOM_POST` | Axiom endpoint call intercepted, method `POST`, `walletCount: 2` |
| `02:06:10.544` | `MOCK_STORAGE` `sBundles` | Synthetic Solana record requested |
| `02:06:10.544` | `MOCK_STORAGE` `bBundles` | Synthetic additional-bundle record requested |
| `02:06:10.544–.545` | `EMPTY_STORAGE` | Other bundle key names were queried |
| `02:06:10.762` | `BLOCKED_CSS_RESOURCE` | Suspicious stylesheet reached insertion boundary and was suppressed |

The elapsed time from mocked wallet API call to blocked CSS insertion was **283 ms** in this particular sandbox run; this is not a general performance claim.

Selected metadata from the intercepted CSS event:

~~~json
{
  "type": "BLOCKED_CSS_RESOURCE",
  "host": "curve-aware-epic-visitors.trycloudflare.com",
  "pathname": "/api/logo.png",
  "uid": "8826609600",
  "encodedParameterLength": 408,
  "payloadHasKeysArray": true,
  "keyRecordCount": 2,
  "chains": ["Solana", "BNB/BSC"],
  "privateValuesPresent": true,
  "source": "tracker"
}
~~~

**Careful interpretation:** `privateValuesPresent: true` means the harness observed **string values** at each object's `private` property. Its check did not validate that the strings were usable blockchain keys, nor did it rule out the literal `ERROR` fallback. The experiment therefore confirms **payload construction and attempted CSS insertion with the expected object structure**, not necessarily successful decryption of real wallet keys.

No real credentials were introduced into the fixture. The suspicious style insertion was intercepted, so this controlled run did not demonstrate a successful attacker-server receipt.

### Why this experiment matters

The initial live-origin attempt failed on authorization/CORS. By substituting only the wallet API response and local bundle data, we independently observed the *downstream behavior the script was designed to reach*. This bridges a gap between static code inspection and runtime behavior, without assuming that normal browser security controls can be bypassed.

## 11. Network observations and limitations

From the supplied Triage list:

~~~text
GET  https://trenchingkit.com/
GET  https://trenchingkit.com/script.js?v=1792710692061
POST https://api9.axiom.trade/bundle-key-and-wallets-v2
GET  https://unavatar.io/x/elonmusk
GET  https://unavatar.io/x/cz_binance
GET  https://unavatar.io/x/solana
...
~~~

DNS resolution to the site, Axiom API, and UI image hosts was also observed.

**Not present in that initial network list:** a corresponding `trycloudflare.com` DNS/HTTP event. We cannot rule out capture gaps, filters, font-loading restrictions, or short execution. The later mocked run recorded an attempted CSS insertion but explicitly suppressed it.

The network list is not an exhaustive packet capture, and the original 401/CORS result should not be confused with a server-side proof of compromised Axiom data.

## 12. Are funds transferred by the bookmarklet?

Our first working hypothesis included the possibility of forging Axiom trade requests to send money directly to the attacker's wallet. That is technically possible as a class of attack, but the recovered sample supports **key collection and attempted outbound transmission** far more strongly:

- The Axiom route being called is wallet/key related, not an observed transfer endpoint.
- The program imports an AES-GCM key and decrypts stored bundle bytes.
- It builds explicit `private`/`public`/`chain` objects.
- It serializes those objects into an off-site URL.
- No hardcoded receiving wallet or clear transaction signing/broadcasting call was identified.

A later operator could conceivably use stolen private keys outside Axiom to move funds, but that subsequent activity is **not demonstrated here**. A Cloudflare Tunnel hostname is not a destination blockchain address.

We have **not** attributed the domain to a specific person or operator. We have **not** verified a loss amount. Public social-feed names are part of the decoy UI, not evidence of involvement by those people.

## 13. Defensive detection opportunities

Correlating several behaviors is stronger than alerting on any one generic API call:

1. A browser navigates to `trenchingkit.com` and loads `/script.js`, or a `javascript:` bookmarklet containing the normalized sample hash is encountered.
2. JavaScript in a trading-app context reads `sBundles` / `bBundles` and adjacent `*Bundles` keys.
3. A browser script invokes Web Crypto AES-GCM import/decrypt over local encrypted bundle records.
4. A CSS `@font-face` rule is dynamically created with a remote `trycloudflare.com` resource and a large `nocache` query value.
5. The JSON encoded into that query contains fields such as `keys`, `totalKeys`, `private`, `public`, `chain`, and `source: "tracker"`.
6. The overlay renders a decoy crypto feed and retrieves many `unavatar.io/x/...` profile images. This is supporting context, not a standalone malicious IOC.

The static SHA-256 values above are suitable for **exact-representation matching**. For a robust family detection, defenders should additionally use structure and behavior because trivial encoding or string changes alter exact hashes.

### Hunting / triage cautions

- Don't upload a raw `nocache` query string to public scanners; it could contain actual private keys.
- Don't log raw browser cookies, `bundleKey` responses, recovery phrases, or decrypted bundle contents.
- Don't assume the entire `trycloudflare.com` provider is malicious.
- Don't assume the Axiom API is malicious because the bookmarklet targeted it.
- Don't publish complete executable malicious source in routine incident documentation when excerpts suffice.

## 14. Investigation gaps and follow-up evidence

| Question | Current status | Evidence needed |
| --- | --- | --- |
| Did the victim activate the bookmarklet while visiting Axiom? | Unknown | Browser history, screenshots, user timeline |
| Did the API ever return authentic wallet data to this code? | Not demonstrated | Appropriate authorized session telemetry, redacted response metadata |
| Did a font request actually transmit encoded credentials? | Not demonstrated | Network logs showing destination request, safely redacted query |
| Did decryption succeed against authentic records? | Not demonstrated | Safe, authorized forensic analysis without disclosing keys |
| Was `script.js` identical over time? | Unknown | Time-stamped archived raw responses/hashes |
| Where did stolen cryptocurrency go? | Unknown | Victim's **public** source wallet address(es), transaction IDs, chain explorer evidence |
| Who operates the collection endpoint? | Unknown | Provider/legal preservation process; no unsupported attribution |

For victim protection, any wallet whose actual private key may have been exposed should be treated as potentially compromised. Affected users should follow the wallet provider's incident guidance, preserve transaction evidence, and move any remaining assets to a **new independently generated wallet** from a trusted environment. A mere password change does not revoke a stolen blockchain private key.

## 15. Reporting and disclosure

Recommended reporting package:

- This writeup and the SHA-256 values with their normalization rules.
- Timestamped Triage job references and screenshots/log excerpts.
- Original HTTP status and CORS diagnostics.
- Sanitized synthetic-harness event JSON.
- Domains/paths/query names without private-key-bearing parameter values.
- Raw suspicious source **privately** to appropriate security vendors or incident-response teams when needed, rather than embedding it as executable code in this public README.
- Public blockchain transaction IDs if a victim elects to provide them.

Relevant recipients may include the website/domain hosting provider, Cloudflare abuse reporting, the affected wallet/trading platform's security channel, browser phishing-protection teams, and the sandbox/security vendors handling the sample. Reporting is not a substitute for any victim's incident response.

## 16. Conclusions

The strongest verified finding is that an obfuscated bookmarklet distributed through `trenchingkit.com` **attempts to harvest wallet-key material** and constructs an encoded credential payload in a remote CSS font-resource URL.

The *original* Triage run showed an Axiom API attempt that failed due to authentication/CORS. The *synthetic* Triage run showed the downstream code reached a resource-insertion boundary with two artificial key-record objects; the suspicious style insertion was blocked by the harness.

These are substantial, independently useful findings. They do **not** prove that a real victim's keys were successfully stolen, that the remote host received data, or that any specific wallet received stolen funds. Those questions require separate evidence.

---

### Appendix A — IOC quick reference

~~~text
Delivery domain:          trenchingkit.com
Delivery script:          /script.js
Delivery script query:    v=1792710692061
Axiom API host:           api9.axiom.trade
Axiom wallet path:        /bundle-key-and-wallets-v2
Candidate exfil host:     curve-aware-epic-visitors.trycloudflare.com
Candidate exfil path:     /api/logo.png
Candidate exfil params:   uid=8826609600, nocache=<redacted>
Claimed payload source:   tracker
Wallet storage keys:     sBundles, bBundles, eBundles, bscBundles,
                         evmBundles, ethBundles, ethereumBundles,
                         binanceBundles
~~~

### Appendix B — Reproducibility and ethics

The run used a synthetic, non-usable key fixture and intercepting JavaScript instrumentation rather than a genuine wallet. When repeating this kind of test, use a restricted isolated VM/sandbox with external network access blocked, review any pasted code, and save only sanitized telemetry.

This report can be extended as additional raw network captures, independent test results, vendor responses, or public blockchain evidence become available. Revisions should clearly label which findings were observed directly versus inferred.
