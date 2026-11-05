# HRC website manuals

This MDS consumer builds the maintained HRC manuals for `/docs/hrc/` on the
HyperNet website.

HRC 0.1.0 completed the bounded qualification described by the integration profile.
Publish only the verified `v0.1.0` source selected by this release configuration.

## Source and publication scope

The HRC `0.1.0` publication configuration selects `source.tag = "v0.1.0"` and omits
`source.revision`. The builder resolves that exact tag to its full commit before
exporting. It exports only the 21 maintained Markdown manuals directly under
`Documentation/`, the root README, Apache-2.0
license, third-party adaptation notices and publisher public key: 25 pages. The
README is the manual home. Website build instructions and generated snapshots are
not product manuals.

Navigation separates operating procedures, implementation contracts and the
preserved design proposals. The original status and limits remain in each source.
The qualified release configuration uses the `stable` channel and indexable
metadata. Development previews must retain `preview` and `noindex`. No public
HRC repository or download URL is implied. The repository and package distribution
remain private after manuals are published. Package-specific dependency inventories
and source archives remain package deliverables described by the
[installation guide](../Installation.md).

MDS snapshots retain exact source bytes with a Git-object membership proof and
per-file SHA-256 digests. The source manifest identifies the full commit. This
proves source membership, not release approval. The builder prints the snapshot
manifest's SHA-256 and records the MDS version separately from the HRC version.
Only `site/docs/hrc/` is served. The configuration, snapshot, `source.json` and
`.mds/build.json` stay outside the public directory. They must not be deployed.

## Build and check

Use Node.js 22 or 24 and a prepared `@metalheart/mds` 0.1.0 package directory.
The selected package archive is `metalheart-mds-0.1.0.tgz`, SHA-256
`36a07b155fa46f934f25ed48553198c29de8f41a1fd473ab79fca79df2da9486`.
The MDS source equivalent is commit `12abec4b3172095dc0431d1c6e4c0ed4b9aa8470`.
Use its installed locked dependencies. No Rust build is needed.

From the HRC checkout, provide the prepared MDS package directory and one output
workspace outside the HRC repository:

```sh
node Documentation/Website/Build.mjs /path/to/mds /path/to/hrc-website
```

The adapter copies the declarative configuration into that workspace, previews
and exports the declared snapshot with MDS, removes the local repository path,
then calls MDS build and check. It reads the selected commit, not working-tree
manual edits. Later builds reuse that workspace; MDS refuses altered snapshot
or generated output bytes instead of silently discarding them. The adapter
does not install packages, start a server, create tags or deploy files.

The resulting configuration is portable with its snapshot and the same MDS
package. Normal MDS commands can inspect it independently:

```sh
node /path/to/mds/bin/mds.mjs check --config /path/to/hrc-website/mds.config.json
node /path/to/mds/bin/mds.mjs preview --config /path/to/hrc-website/mds.config.json --port 4177
```

Stop the preview after inspection. Its HRC home is
`http://127.0.0.1:4177/docs/hrc/`. The parent `/docs/` link and sibling Core/Suite
manual links need the complete HyperNet site for local navigation.
`check --release` refuses a preview channel.

## Routes and upstream links

The configuration is the complete source-to-route map. Preserve its slugs and
source headings across updates. All relative HRC manual and license links resolve
inside `/docs/hrc/`; MDS checks those paths and heading anchors. Local search is
owned at `/docs/hrc/search/` and requires no external search service.

Twelve explicit publication edits map documentation URLs from the exact Core
0.10.2 and Suite 0.10.1 release commits to the existing `/docs/core/` and
`/docs/suite/` routes. Each `publicationEdits[].source` names an HRC manual;
`from` must match its pinned upstream URL exactly once, and `to` selects the
corresponding published manual route. Reconcile the `from` values with the final
upstream commits in the HRC manuals before exporting. Preserve the source-to-route
mapping when changing a source pin. Code references and historical draft links
remain as authored. No technical prose or code example is rewritten during
publication.
Check the sibling routes against the complete site before deployment; the MDS
checker checks only its owned HRC tree.

The initial appearance is neutral, light, flat and standard typography, consistent
with the HyperNet manuals. MDS supplies the neutral mark; there is no separate HRC
brand asset. Reader appearance choices, keyboard navigation and local search use
the existing MDS runtime.

## Refresh and integrate a qualified release

1. Complete HRC qualification and update its authoritative status, compatibility,
   capacity and package instructions. Commit those manuals with the release work.
2. Set `site.version` to `0.1.0` and `source.tag` to `v0.1.0`, with no
   `source.revision`. Commit the final configuration and
   manuals before creating the release tag. The builder resolves that explicit
   tag to a full commit before exporting; a missing tag fails without using HEAD.
   The exported configuration and manifest retain both the full commit and tag.
   A supplied source revision must match its tag. Update the footer, navigation
   and publication edits as needed.
3. Rebuild in the same output workspace. Check every new or changed procedure,
   technical search, keyboard navigation and narrow-screen reading.
4. Once the selected source is qualified, set the intended channel and indexing
   policy in the maintained configuration. Rebuild and run MDS `check --release`.
5. Integrate the consumer into the HyperNet site's documentation build and add an
   HRC entry to its `/docs/` selection page. Preserve the existing Core and Suite
   consumers, landing pages and unrelated source edits. Check all sibling links
   against that complete site.
6. Publish only the generated `docs/hrc/` subtree and the reviewed selection-page
   change through the site's existing deployment procedure. Keep its previous
   deployment for rollback and verify the public home, installation, license,
   search assets and sibling links. No new DNS name or proxy route is needed.

Local generation does not change repository visibility or publish a release.
Public hosting and the final release identity remain separate delivery
steps.
