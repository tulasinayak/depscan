"""Which Python APIs plausibly reach a native library bundled inside a wheel.

Used for `bundled_native` advisories (e.g. "vulnerable OpenSSL included in cryptography wheels",
"libwebp OOB write in Pillow"). A plain `import PIL` does not exercise libwebp; decoding an image does.

Extend freely: keys are the keywords detected in advisory text (lower case), values are symbol
prefixes. A usage site matches when its fully qualified symbol equals a prefix or starts with
"<prefix>.". This is a plausibility hint for the ExploitabilityAgent, never proof.
"""

NATIVE_KEYWORDS = ["openssl", "libwebp", "libjpeg", "libtiff", "zlib", "libxml2", "libxslt", "freetype",
                   "libpng", "libavif", "openjpeg", "lcms", "libyaml", "sqlite"]

# Phrases that mark an advisory as being about a native library shipped inside the wheel.
BUNDLED_PHRASES = ["bundled", "wheels", "statically linked", "vendored", "shipped with"]

_PIL_DECODE = ["PIL.Image.open", "PIL.Image.frombytes", "PIL.Image.frombuffer", "PIL.ImageFile.Parser",
               "PIL.Image.Image.save", "PIL.ImageFile"]

NATIVE_REACH: dict[str, list[str]] = {
    "libwebp": _PIL_DECODE + ["PIL.WebPImagePlugin", "PIL.features"],
    "libjpeg": _PIL_DECODE + ["PIL.JpegImagePlugin"],
    "libtiff": _PIL_DECODE + ["PIL.TiffImagePlugin"],
    "libpng": _PIL_DECODE + ["PIL.PngImagePlugin"],
    "libavif": _PIL_DECODE + ["PIL.AvifImagePlugin"],
    "openjpeg": _PIL_DECODE + ["PIL.Jpeg2KImagePlugin"],
    "lcms": ["PIL.ImageCms"],
    "freetype": ["PIL.ImageFont.truetype", "PIL.ImageFont.FreeTypeFont", "PIL.ImageFont"],
    "zlib": _PIL_DECODE + ["zlib", "gzip"],
    "libxml2": ["lxml.etree", "lxml.html", "lxml.objectify"],
    "libxslt": ["lxml.etree.XSLT"],
    "libyaml": ["yaml.CLoader", "yaml.CSafeLoader", "yaml.CDumper", "yaml.cyaml"],
    "sqlite": ["sqlite3"],
    "openssl": ["ssl", "cryptography.x509", "cryptography.hazmat", "cryptography.fernet", "OpenSSL",
                "requests", "urllib3", "httpx", "aiohttp", "http.client", "urllib.request", "smtplib",
                "imaplib", "ftplib", "hashlib"],
}


def native_libs_in(text: str) -> list[str]:
    low = text.lower()
    return [lib for lib in NATIVE_KEYWORDS if lib in low]


def reaches(symbol: str, libs: list[str]) -> str | None:
    """The library this symbol plausibly reaches, or None."""
    for lib in libs:
        for prefix in NATIVE_REACH.get(lib, []):
            if symbol == prefix or symbol.startswith(prefix + "."):
                return lib
    return None
