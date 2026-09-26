# Contributing

Thanks for helping improve Cold Digger.

## Development setup

Cold Digger targets Ubuntu and Python 3.11–3.13. Install the system tools and
editable package as described in the README, then run:

```bash
python -m unittest discover -v
```

Tests that need Sleuth Kit, PhotoRec, FFmpeg, Pillow, or the Internet Explorer
readers skip explicitly when those dependencies are unavailable.

## Pull requests

- Open an issue first for large changes or new recovery formats.
- Keep input images read-only and preserve evidence provenance.
- Add tests for behavior changes, including failure and interruption paths.
- Never commit real disk images, recovered case data, private keys, seed phrases,
  browser history, or other sensitive material.
- Update the README, architecture notes, and changelog when applicable.

By contributing, you agree that your contribution is licensed under the MIT
License included in this repository.
