# Y2JB auto-close + Payload Manager

This folder contains a build based on the official `download0-autoclose.zip` asset from [notmaj0r/Y2JB, release Relapse](https://github.com/notmaj0r/Y2JB/releases/tag/Relapse).

## What it does

The image keeps the release's auto-close startup flow. The patched `Relapse.js` runs the faster Relapse payload, sends `Payload_Manager_v0.6.3.elf` to elfldr at `127.0.0.1:9021`, and reports success only after the transfer completes. The auto-close flow then closes YouTube. No PC or NAS is needed for that transfer.

The root workflow `.github/workflows/build-autoclose-payload-manager.yml` patches only the Relapse and Payload Manager files in the original UFS2 image and publishes the resulting `download0.dat` as a GitHub Actions artifact. It runs when these project files are pushed to `main`, or can be started manually from Actions.

## Build output

Download the artifact named `download0-dat-autoclose-payload-manager`. It contains `download0.dat` and `download0.dat.sha256`.

## Limitations

- The build has not been tested on a physical PS5.
- You still need to install the generated image in the YouTube data location for the matching title ID and launch YouTube.
- This does not start the exploit at console power-on.
- If the ELF transfer fails, the auto-close success path is not reached, leaving YouTube open so the error can be seen.

## Source and checksums

The base ZIP is pinned to SHA-256 `a044d046e283f1ea8e97c945278f6767c064e510701a7fa2d3d1276428e72a3a`. Payload and patch checksums are listed in `SHA256SUMS.txt`.
