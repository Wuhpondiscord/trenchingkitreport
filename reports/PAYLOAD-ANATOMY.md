# Payload Anatomy: Full Technical Breakdown of the Trenchingkit Bookmarklet

*Companion report to [the main investigation](../README.md). Findings based on the recovered `BOOKMARKLET_CODE` in `trenchingkit.com/script.js`, the original obfuscated capture, decoded source, Triage network/console logs, and the synthetic-wallet run. November 2026.*

> **Purpose and limits:** Defensive reverse engineering and incident reporting. The excerpts are intentionally shortened or redacted. We have **not** established that real wallet keys were stolen or that a real on-chain transfer occurred. Some intermediate deobfuscator versions produced malformed JavaScript; conclusions below prioritize repeated observations, intact source patterns, and controlled runtime evidence.

## 1. The two things this bookmarklet does

At a high level it has **two parallel jobs**:

1. **Look like a legitimate crypto trading enhancement.** It builds a polished black overlay, faux X/Twitter-style feed, fake engagement information and profile icons, draggable panel, buttons and status notifications.
2. **Collect wallet secret material.** It requests wallet-related information from Axiom, queries multiple local browser storage keys, attempts AES-GCM decryption, creates objects containing `private` fields, and constructs an off-site CSS resource URL with the serialized records.

The distracting feed and the credential-handling code reside in the *same* bookmarklet. This is not a documented browser extension or audited Axiom integration.

## 2. Delivery: website → bookmarklet → current-page privileges

The website's external script defines a JavaScript URL and assigns it to its page link:

~~~javascript
// Schematic — not the full active bookmarklet.
const BOOKMARKLET_CODE = "javascript:function _0x347a(...)";
document.getElementById("bmark").href = BOOKMARKLET_CODE;
~~~

A bookmarklet is a bookmarked `javascript:` URL. When activated, its code executes in the context of the **currently displayed page**, which is central to this case. On the attacker's domain, CORS prevented reading Axiom's response. On an appropriately authenticated Axiom page, the browser origin and available storage would differ. That theoretical difference is not evidence that this particular incident succeeded.

Why it is attractive to attackers: convincing the user to drag/save a bookmarklet makes the *user* activate code in a page they trust, rather than the attacker having to exploit Chrome itself.

**Red flag:** a website asks you to drag a “trading tool,” “tracker,” or “dashboard” onto the bookmarks bar and run it inside another site.

## 3. String concealment: encrypted/encoded lookup table

The most visible technique is a large string table exposed through short hexadecimal-style resolver names (`_0x347a`, `_0xba16` and aliases). The resolver subtracts an offset from numeric lookup indexes, obtains an encoded string, and performs a Base64-like/RC4-like decode with a key argument.

Practical consequences:

- Endpoint strings, UI text and property names can appear as opaque lookups rather than searchable plain text.
- A simple `grep` for `api9.axiom.trade` or `crypto.subtle` may miss strings before decoding.
- Resolver aliases (`var x = _0x347a`) make a single function appear under many names.
- Initializers and transformed numeric arithmetic obscure the indexing process.
- A sizeable table and rotating/initialization logic inflate complexity without adding useful behavior.

Illustrative pattern:

~~~javascript
// Syntax resembles the original; the index/key below are illustrative.
const name = _0x347a(0x4cb, "W5]n");
~~~

The original contains thousands of lookup uses. Our decoder ultimately resolved **2,373 calls across 36 aliases**; a remaining call with non-printable output was preserved rather than guessed. These are tool results for **this sample**, not a promise of perfect deobfuscation.

## 4. Helper-object indirection and lookup tables

Another layer obscures ordinary operators, calls and strings behind short property names:

~~~javascript
const helpers = {
  UMbPi: "BNB/BSC",
  dfDQE: "tracker",
  alqKw: function(fn, value) { return fn(value); },
  yAlzv: function(a, b) { return a + b; }
};
~~~

As a result, innocent-looking code may do:

~~~javascript
const chain = helpers.UMbPi;      // "BNB/BSC"
const label = helpers.dfDQE;      // "tracker"
const joined = helpers.yAlzv(a,b); // a + b
~~~

Actual properties and calls also use computed brackets and *secondary* wrappers, such as one helper calling another helper. Some intermediate deobfuscator passes failed to resolve these or changed token boundaries. **Never assume prettified code is semantically correct without checking it against the original.**

## 5. Dead code, constant branches and nonsense arithmetic

The sample includes conditional branches where both sides are string literals or constant expressions:

~~~javascript
if ("qIAIA" !== "qIAIA") {
  // unreachable distraction
} else {
  // UI-building logic
}
~~~

It also deliberately writes simple constants as complex hexadecimal arithmetic, boolean values as `!(0)`/`!(1)`, and uses confusing comma-separated expressions. These techniques:

- Waste analysts' time by forcing them to inspect unreachable branches.
- Defeat shallow static string matching.
- Make the source look more complex than the runtime behavior.
- Can break naive regex-based rewriting.

For example, some early transformed outputs had impossible-looking `padStart(-0x11 * - -2990, ...)` expressions or malformed `for` headers. Those were **deobfuscator artifacts**, not reliable evidence of how the original payload executes.

## 6. The camouflage UI

Decoded source reconstructs a black modal/overlay: backdrop (`lt-backdrop`), root (`lt-root`), feed (`lt-feed`), button icons, subtle shadows, status notifications and pointer interactions.

The feed is populated with hardcoded objects resembling social posts:

~~~javascript
// Representative shortened record — content is decorative.
{ name: "Solana", handle: "@solana", fol: "3.1M",
  text: "Solana just processed its 500 billionth transaction." }
~~~

The script loads profile images such as:

~~~text
https://unavatar.io/x/elonmusk
https://unavatar.io/x/cz_binance
https://unavatar.io/x/solana
https://unavatar.io/x/coinbase
~~~

In the original Triage trace, dozens of avatar requests appeared. The volume of benign-looking visual traffic can drown out the single meaningful wallet API call when an analyst only skims the network panel.

The handles and names are *decoy content*, **not suspect identities**. No implication is made that the people, organizations, or avatar service are collaborators.

## 7. Targeted Axiom wallet API request

After or alongside UI rendering, the source attempts a credentialed wallet-related request:

~~~javascript
// Reconstructed essential operation.
const response = await fetch(
  "https://api9.axiom.trade/bundle-key-and-wallets-v2",
  { method: "POST", credentials: "include" }
);
const data = await response.json();
const bundleKey = data.bundleKey;
const wallets = data.wallets || [];
~~~

A successful path is conditional on response status and available data. `credentials: 'include'` requests inclusion of eligible browser credentials; it cannot override authorization, cookie policy, or CORS.

**Observed unmocked run:**

~~~text
Origin: https://trenchingkit.com
POST: https://api9.axiom.trade/bundle-key-and-wallets-v2
Response: 401 Unauthorized
Access-Control-Allow-Origin: https://axiom.trade
Browser outcome: CORS error, TypeError: Failed to fetch
~~~

This says the browser **attempted** the Axiom call, not that it received wallet material. The first execution stalled at this stage.

The endpoint is part of the legitimate site's infrastructure. Its presence here is evidence of the attacker's *target*, not evidence that Axiom operates the payload.

## 8. Hunting wallet bundles in localStorage

The bookmarklet attempts to read multiple keys, including:

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

The captured harness output confirms reads of `sBundles` and `bBundles` and attempts to query the six others. The code parses JSON arrays, gathers nonempty records and links them with wallet metadata.

This makes the attack opportunistic: it searches for more than one possible storage naming convention instead of depending exclusively on a single known key.

The chain names assigned by the script (`Solana` and `BNB/BSC`) indicate *intended categories*, not that every item discovered actually belongs to those chains.

## 9. AES-GCM decryption path

The recovered script uses Web Crypto APIs in a pattern matching:

~~~javascript
// Sanitized pseudocode; omits all real key material.
const aes = await crypto.subtle.importKey(
  "raw",
  decodeBase64Url(bundleKey),
  { name: "AES-GCM" },
  false,
  ["decrypt"]
);
const [ivText, ciphertextText] = encryptedRecord.split(":");
const bytes = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv: decodeBase64Url(ivText) },
  aes,
  decodeBase64Url(ciphertextText)
);
~~~

The IV/ciphertext separator matters for analyzing storage formats. If either component is malformed, Web Crypto rejects decryption.

The script converts resulting bytes into different representations: a Base58-style encoder for Solana-labeled records and a hexadecimal `0x` representation for additional bundles. Records are assembled with keys:

~~~javascript
{
  private: "[REDACTED]",
  public: "[walletAddress metadata]",
  chain: "Solana"  // or "BNB/BSC"
}
~~~

**Subtlety:** a record with a `private` string is not automatically a usable wallet private key. The source may record a string `ERROR` when decryption fails. The earlier harness verified presence of string properties but not valid cryptographic private keys.

## 10. Packaging for remote transmission

The payload prepares a JSON object containing:

~~~javascript
{
  keys: collectedKeyRecords,
  timestamp: Date.now(),
  source: "tracker",
  totalKeys: collectedKeyRecords.length
}
~~~

Then it applies `btoa(JSON.stringify(...))` and URL-encodes the Base64 string.

**Why Base64?** It allows binary-looking material and structured JSON to be placed in a query parameter in a relatively transport-friendly form. Base64 is *encoding, not encryption*.

The name `nocache` creates a plausibly benign explanation for a long query string, but in this sample it carries the serialized key records.

## 11. Disguised exfiltration via CSS and a fake image path

The constructed destination was:

~~~text
Host: curve-aware-epic-visitors.trycloudflare.com
Path: /api/logo.png
Query: uid=8826609600&nocache=<redacted encoded JSON>
~~~

The script constructs an `@font-face` rule whose `src: url(...)` contains this address, appends a style node, and inserts a hidden element that references the font family. That is an attempt to use *browser resource loading* to deliver a URL containing the keys.

The path `/api/logo.png` does **not** mean a PNG was uploaded; in the observed code it is the resource path embedded in a font URL.

This design can evade analysts who only search for `fetch`, `XMLHttpRequest`, or straightforward `POST /collect` exfiltration. It also explains why **blocking or instrumenting `fetch` alone is not adequate containment**.

**Crucial limit:** the original Triage trace contained no confirmed request to the tunnel. The synthetic run stopped insertion before a real request could occur.

## 12. Synthetic dynamic validation — what actually happened

The analyst controlled the execution with a disposable test environment and console instrumentation *before* triggering the bookmarklet. The harness:

1. Intercepted the Axiom API URL and returned fake `{bundleKey, wallets}` metadata.
2. Generated a temporary Web Crypto AES-256 key.
3. AES-GCM-encrypted intentionally invalid, labeled string material to mimic encrypted bundles, without creating a usable wallet.
4. Mocked browser storage reads for `sBundles` and `bBundles`; returned empty arrays for other bundle names.
5. Intercepted the identified malicious `style` element at the insertion boundary, recorded only sanitized metadata, and suppressed insertion.

Recorded events (2026-11-17 UTC):

| Timestamp | Event |
| --- | --- |
| 02:06:05.716 | `READY` |
| 02:06:10.479 | `MOCK_AXIOM_POST` |
| 02:06:10.544 | `MOCK_STORAGE` `sBundles` |
| 02:06:10.544 | `MOCK_STORAGE` `bBundles` |
| 02:06:10.544–.545 | `EMPTY_STORAGE` for other storage names |
| 02:06:10.762 | `BLOCKED_CSS_RESOURCE` |

Sanitized output:

~~~json
{
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

The ~283 ms between the intercepted Axiom call and blocked CSS insertion is a **single-run observation**, not a measured benchmark.

No real wallet credentials were supplied. Neither a successful on-chain transfer nor successful remote reception was demonstrated. This harness checks the expected data *shape*, not the authenticity of credentials.

## 13. What is and isn't proven

| Behavior | Evidence level |
| --- | --- |
| Website delivers a bookmarklet | Recovered source and network trace |
| Runtime POST to Axiom | Observed |
| Unauthorized response blocked on attack-site origin | Observed |
| Read of named storage keys | Observed under instrumentation |
| AES-GCM decryption logic present | Static source |
| Two private-field records serialized for CSS URL | Observed under synthetic fixture |
| CSS insertion intended for a remote tunnel | Static source + intercepted insertion |
| Real browser successfully sent secrets off-host | Not proven |
| Real victim lost funds | Not proven |
| On-chain recipient address | Not identified |
| Payload contains transaction-sending logic | Not identified in inspected flow |

## 14. Why this approach is effective

The attacker doesn't need an executable EXE, a macro, or a browser zero-day. The attack asks the user to run JavaScript within a privileged *application context* and hides the sensitive operation beneath a visually busy, seemingly familiar interface.

Its concealment relies on several layers at once:

- **Social engineering:** a trading utility/bookmarklet as the entry point.
- **Legitimate API abuse:** wallet-related request to a real platform endpoint.
- **Data-at-rest pivot:** browser-stored encrypted bundles plus a server-supplied bundle key.
- **Static-analysis friction:** string decoding, aliases, wrapper tables and opaque predicates.
- **UI distraction:** a convincing, noisy crypto social feed.
- **Network disguise:** a cloud tunnel, an image-shaped path and a query variable named `nocache`.
- **Alternative exfil channel:** CSS font loading rather than an obvious JavaScript `fetch` to the attacker domain.

These are **tactics visible in this specific recovered sample**, not evidence of a larger identified malware family or attribution to a named actor.

## 15. Investigator takeaways

- Inspect *bookmarklet contents*, not just downloaded binaries and HTML page titles.
- Cross-reference the source and network: the most meaningful API request was amid dozens of avatar-image loads.
- Understand origin: `credentials: 'include'` does not bypass CORS.
- Validate deobfuscation stages with syntax tests and source comparison. A cleaner-looking file can be wrong.
- Search for network transmission inside CSS, images, fonts and DOM insertions, not only direct HTTP APIs.
- Use synthetic fixtures and independent network isolation when reproducing code paths.
- Never publish decoded `nocache` parameters from actual victims; those could contain private keys.
- Preserve raw sample and exact normalization/hash rules for reproducibility.

See also [Detection, Prevention and Analysis Guide](DETECTION-AND-PREVENTION.md) and the [Main Investigation](../README.md).
