# Label audit: the 4 stepwise false alarms (2026-09-27)

No label was changed. Sources: the advisory texts (OSV), Pillow 10.0.0 source (`src/PIL/*.py` at tag 10.0.0),
OpenSSL security advisory 2026-06-09.

## 1. Pillow CVE-2026-54058 (native-reachable): current label *not affected* is right

**Trigger (advisory):** "When Pillow loads an uncompressed image whose tile uses the `raw` codec … and the image was
opened **from a filename**, it memory-maps the file and builds the row pointers directly into the mapping"; the
McIdas plugin supplies an unchecked stride. The out-of-bounds read is in that mmap branch.

**App:** `app/images.py:9` `with Image.open(stream) as im:` where `stream` is `upload.stream` (Werkzeug `FileStorage`).
No `formats=`, no extension or MIME check, so a user upload **does** reach the McIdas decoder.

**Pillow 10.0.0:** `Image.open` sets `filename = ""` unless it is given a `str`/`Path` (Image.py:3210–3217); the
plugin gets that empty filename (`ImageFile.__init__`, ImageFile.py:109–111), and `use_mmap = self.filename and
len(self.tile) == 1` (ImageFile.py:167) is false for a stream. The vulnerable mmap path is never taken; the raw decoder
reads from the stream instead.

**Verdict:** label right, tool wrong. (It would be affected if the app saved uploads to disk and opened them by name.)

## 2. Pillow CVE-2026-42310 (native-reachable): current label *not affected* is right

**Trigger:** "An attacker can supply a malicious PDF … PdfParser … follows Prev pointers in PDF trailers".

**App:** the same `Image.open(stream)` on uploads, then `thumbnail` and `save(format="JPEG")`.

**Pillow 10.0.0:** `PdfImagePlugin.py` only registers **save** handlers (`register_save`, `register_save_all`,
`register_extension`, `register_mime`, lines 279–284), with no `register_open`, so `Image.open` cannot read a PDF.
`PdfParser` runs only inside `_save`, and reads an existing file only when saving with `append=True` (line 52).
The app never saves PDF.

**Verdict:** label right, tool wrong. The spec's premise (`Image.open` with `format=PDF`) does not exist in Pillow.

## 3. Pillow CVE-2026-55379 (native-unreachable): current label *not affected* is right

**Trigger:** "`PIL/BdfFontFile.py` `bdf_char()` … passes the dimensions directly to `Image.new()` without calling
`Image._decompression_bomb_check()`": a crafted **BDF font file** loaded with `BdfFontFile`.

**App:** `app/images.py:9` `Image.new("RGB", (120, 24), COLORS.get(status, "#616161"))`, a fixed size (only the
colour depends on the URL segment, through a dict lookup with a constant fallback). No font file is ever loaded;
`BdfFontFile` is not an image plugin, so nothing in the app can reach `bdf_char()`.

**Verdict:** label right, tool wrong. The spec lists `PIL.Image.new` as a trigger, but the flaw is Pillow's own
`Image.new` call inside `BdfFontFile`, not an application's.

## 4. cryptography GHSA-537c-gmf6-5ccf (native-unreachable): current label *not affected* is right

**Trigger:** "wheels include a statically linked copy of OpenSSL … vulnerable to a security issue", details in
secadv 2026-06-09, which lists 18 issues: PKCS7_verify use-after-free; CMS AuthEnvelopedData; two QUIC issues;
OCSP stapling double-free; AES-OCB IV ignored on the `EVP_Cipher()` path; ASN1_mbstring_ncopy overflow; CMS PWRI
over-read; DER primitives > 2 GB (`d2i_*`); PKCS#12 PBMAC1 short HMAC keys; OCSP partial-chain NULL deref; CMS
password decryption; CRMF; CMS/PKCS7_decrypt Bleichenbacher oracle; CMP rootCaKeyUpdate; FFC-DH peer validation;
`X509_VERIFY_PARAM_set1_email`; AES-SIV / AES-GCM-SIV empty messages.

**App:** only `cryptography.fernet.Fernet` (`generate_key`, `encrypt`, `decrypt(ttl=3600)`): AES-128-CBC with PKCS7
padding plus HMAC-SHA256, through the streaming `EVP_CipherUpdate` / `EVP_CipherFinal` and HMAC APIs. No TLS, no
X.509, no PKCS#7/#12, no CMS, no ASN.1 parsing of input (a Fernet token is base64, not DER).

**Primitives:** none of the 18 issues is in AES-CBC or HMAC-SHA256. The only HMAC-related one (CVE-2026-34181) is
about PKCS#12 files with PBMAC1, and the only AES ones are OCB via `EVP_Cipher()` and SIV / GCM-SIV.

**Verdict:** label right, tool wrong. The spec lists the whole `cryptography` package as the native wrapper.

## Summary

All 4 are false alarms of the tool; I propose **no label change**. Nothing was written to `.depscan/LABEL_CHANGES.md`.
