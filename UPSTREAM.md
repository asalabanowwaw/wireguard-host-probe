# wg-easy reference

Upstream project reviewed: https://github.com/wg-easy/wg-easy

The user chose to keep the existing native WireGuard backend instead of migrating to wg-easy's Docker/Nuxt application. This project therefore remains an independent Python implementation, not a wg-easy fork or deployment. The wg-easy feature set was used as a product reference for client enable/disable, QR export, search/filter/sort, bulk management and traffic telemetry. No wg-easy source code or artwork is copied into these implementations. Upstream wg-easy is licensed AGPL-3.0-only; its name is credited in the interface and documentation.

The original Diana artwork, CSS, dashboard implementation and existing native installer are maintained in this repository. The user's existing keys, settings and clients stay with the native `wgauto0` installation.


## Optional AmneziaWG engine

The optional native installer builds official upstream projects, without Docker:

- https://github.com/amnezia-vpn/amneziawg-go at `b5928efb6ca19f0153958460c3d141f04abc5c2e` (v3.1.20260828).
- https://github.com/amnezia-vpn/amneziawg-tools at `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` (v3.1.20260812).

Upstream licenses remain with their projects (AmneziaWG Go: MIT; tools: GPL-2.0). No compiled upstream binaries are redistributed in this repository. Installation preserves upstream headers and changes the quick helper's interface-creation function to force the pinned Go engine. The original source URLs and this small local change are recorded in the installer. Protocol parameters follow the official Go README, including 3.1 header protection and content padding. Standard WireGuard/Xray exports are intentionally unavailable in that workspace.
