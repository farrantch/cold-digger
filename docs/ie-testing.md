# Internet Explorer reader validation

Unit tests exercise FILETIME precision, local weekly timestamps, URL prefixes, cache/history separation, container selection, unavailable/crashed readers, dirty ESE coverage, output masking and retry limits. Three optional integration tests use public [Plaso forensic fixtures](https://github.com/log2timeline/plaso/tree/00fcc6e7f95a002c85464f0dfd193396bd7d86d3/test_data), pinned to commit `00fcc6e7f95a002c85464f0dfd193396bd7d86d3`. They require Ubuntu's `python3-libmsiecf` and `python3-libesedb` packages. Fixtures are not bundled, and tests never download them automatically.

Download once while online, then run the tests offline:

```bash
fixture_dir=/tmp/cold-digger-ie-fixtures
fixture_base=https://raw.githubusercontent.com/log2timeline/plaso/00fcc6e7f95a002c85464f0dfd193396bd7d86d3/test_data
mkdir -p "$fixture_dir"
curl -fL "$fixture_base/msiecf/History.IE5/index.dat" -o "$fixture_dir/index.dat"
curl -fL "$fixture_base/msiecf/Content.IE5/index.dat" -o "$fixture_dir/cache-index.dat"
curl -fL "$fixture_base/WebCacheV01.dat" -o "$fixture_dir/WebCacheV01.dat"
DISK_ANALYZER_IE_FIXTURES="$fixture_dir" /usr/bin/python3 -m unittest tests.test_ie -v
```

Tests verify fixture SHA-256 values before use:

| Fixture | SHA-256 | Expected extraction |
| --- | --- | --- |
| `index.dat` | `d54847adc8be889cb687bd7c60af50153d310eb3fc32a79d20c93eecb655bfc1` | 17 URL summaries, including 2 recovered candidates; source offset 20480 has `2015-08-25T11:05:18.5120000Z` |
| `cache-index.dat` | `d6f7d3c4cd1b05b637dca8d41fcb652cc3809a0650181e447bf609bbc81d7db9` | Cache/redirect references, without visit timestamps |
| `WebCacheV01.dat` | `2713e7ff413c69659442c5dcb0f23f41230fa76bf760b8aeac0ffd430d10c83e` | 113 summaries from History/MSHist containers; exact 100-nanosecond timestamps |

The integration tests also compare artifacts byte-for-byte after extraction and retry index.dat after reaching a one-row limit. These samples validate real native-reader APIs and formats; they do not represent every IE release or every form of corruption. The WebCacheV24 filename is recognized, but there is no separate V24 fixture in this test set. Default CI runs unit tests and the existing synthetic disk-image recovery tests; these optional public-fixture tests require the environment variable above.
