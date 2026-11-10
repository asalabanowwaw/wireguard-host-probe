# wg-easy reference

Upstream project reviewed: https://github.com/wg-easy/wg-easy

The user chose to keep the existing native WireGuard backend instead of migrating to wg-easy's Docker/Nuxt application. This project therefore remains an independent Python implementation, not a wg-easy fork or deployment. The wg-easy feature set was used as a product reference for client enable/disable, QR export, search/filter/sort, bulk management and traffic telemetry. No wg-easy source code or artwork is copied into these implementations. Upstream wg-easy is licensed AGPL-3.0-only; its name is credited in the interface and documentation.

The original Diana artwork, CSS, dashboard implementation and existing native installer are maintained in this repository. The user's existing keys, settings and clients stay with the native `wgauto0` installation.
