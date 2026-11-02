# Package notice inputs

`Tools/Package.py` assembles a trusted, already built Linux binary and its manuals.
Use its `--build-rustflags` output as `CARGO_ENCODED_RUSTFLAGS` for release builds,
as shown in the installation guide. The packager refuses binaries containing the
current home, Cargo-cache, checkout or explicit `CARGO_TARGET_DIR` paths before
executing them or creating an archive. This check covers known build locations;
it does not establish the provenance or privacy of a binary produced in another
environment.
It includes the notices from the locally resolved locked crate sources, plus the
pinned files here when an upstream crate omits its repository's licence texts.
The source inventory includes archive checksums from `Cargo.lock`. The MPL-2.0
HPKE sources are included in the binary package under `ThirdPartySources/` with
their declared licence and the full licence text.

`NoticeSources.json` maps exact crate versions to source URLs and SHA-256 digests.
The filenames are content hashes to share identical texts without changing their
content. These are licence files, not alternate dependency implementations.

The egui 0.37.0 publishing revisions recorded in the crates are unavailable from
its repository. Their Apache/MIT texts are taken from the corresponding official
0.37.0 release, pinned to `841a328ba2dd8f6996beb7189ebb7fc00e668a2a`.
Crate-local font licences are included separately. The HPKE manifests declare
MPL-2.0 although their enclosing repository supplies Apache/MIT texts; retain those
repository notices and include the Mozilla steward's full MPL-2.0 text as well.
This does not change any dependency's declared licence or HRC's Apache-2.0 licence.

When changing locked dependencies, review their actual notices and source
requirements. Update an exact-version mapping when necessary; do not carry a
previous version's notice over silently. Package generation uses these pinned
inputs offline and refuses missing or changed texts. It does not run network
retrieval or infer a new licence from a filename.
