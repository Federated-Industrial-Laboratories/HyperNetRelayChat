# HRC text, lookup and search profile

Design 1, 31 October 2026. [Protocol](ProtocolPermissions.md) · [Storage](StateAndRecovery.md)

This selects the first text profile. It defines interoperable semantics, not a measured renderer or search implementation. The pilot budgets remain subject to qualification.

## 1. Version and original content

Use Unicode 17.0.0 and default extended grapheme clusters from UAX #29 revision 47. The inspected `unicode-segmentation 1.13.3` and `unicode-width 0.2.2` tables both declare Unicode 17.0.0. Pin these data versions; a dependency upgrade cannot silently change lookup keys, limits or cursor movement. [Segmentation standard](https://www.unicode.org/reports/tr29/tr29-47.html)

Decode UTF-8 strictly at the bounded wire boundary. Preserve original valid message bytes for signatures, storage and exports. Normalised lookup/search text is derived data, never replacement signed content. Reject surrogate encodings, overlong sequences and truncated scalars without exposing decoder internals. Message bodies permit line feed and tab, but reject other C0/C1 controls, including NUL and escape. Rendering still neutralises controls from every other external source and from older stored data.

Enforce both 8 KiB UTF-8 and 2,000 extended grapheme clusters per message. Identity lookup/display input has the existing 64-byte/32-grapheme ceiling and cannot contain line breaks, tabs or control characters. A single large combining sequence remains bounded by bytes. Editing, selection, deletion and truncation preserve whole grapheme clusters. Encrypted endpoints apply these content checks after authentication, using the storage specification's durable rejection/cursor rules.

## 2. Lookup keys and identity presentation

The lookup/search transformation is `NFC(DefaultFullCaseFold(NFD(text)))`, using Unicode 17 data and default full C/F mappings, without Turkic tailoring. Do not substitute ordinary lowercase or an extra compatibility-normalisation pass. Canonically equivalent spellings compare equally; case-fold expansions are intentional. Accents remain significant. The selected Rust implementation is ICU4X normalizer/casemap 2.3.0, with data pinned and checked against the Unicode 17 conformance files before use. Its source exposes full default folding separately from Turkic folding. [Case mapper](https://github.com/unicode-org/icu4x/blob/a14f2dad852be26bad277ae704abf27a15cbfed1/components/casemap/src/casemapper.rs)

Lookup always has an explicit service/origin namespace. Display spelling is retained. A normalised collision never merges accounts or picks the first result: a unique-alias operation returns `Conflict`, while a directory search returns a bounded disambiguation result. A direct message, mention, delegation or approval binds the selected stable account ID and origin, not a mutable nickname. Renaming cannot retarget a queued operation.

Do not equate visually confusable characters across scripts. Identity-sensitive views show the origin and stable identity detail, visibly annotate directional/invisible controls, and provide an escaped spelling when needed. Legitimate joining characters and emoji variation sequences remain supported; an invisible-character warning is not a reason to strip them from signed text. Trusted presentation separates identity fields from surrounding bidirectional text. Completion and confirmation show the resolved identity before an effect.

Bound normalisation output while producing it: at most 32 KiB per message and 4 KiB for the entire search query. Validate these bounds against the selected data; an unsupported expansion refuses the operation explicitly rather than truncating its lookup/index representation. A future text-profile migration rebuilds derived keys and indexes, reports collisions and preserves every original identity and message. Mixed profiles cannot silently compare keys as equivalent.

## 3. Search semantics and index

Search takes up to 16 non-empty literal terms totalling 1 KiB before normalisation, plus typed room, sender/represented-account and date filters. All terms must occur as contiguous substrings of the derived message text; matching is case-insensitive under the rule above and accent-sensitive. There is no implicit stemming, locale tailoring, regular expression, wildcard or raw FTS grammar. Preserve punctuation and spaces within a term. Empty text terms are invalid; a query with no text terms is a metadata-filtered history query.

Use FTS5's trigram tokenizer with `case_sensitive 1`, `remove_diacritics 0` and full detail on already normalised text. This avoids delegating Unicode case-folding to the tokenizer. Encode only terms of at least three scalars in `MATCH`, each as a quoted literal phrase with embedded double quotes doubled. Bind that expression as an SQL parameter and never splice user text into SQL. Shorter terms are checked afterward against the indexed candidates; they must not enter `MATCH` and eliminate otherwise valid results. Recheck literal matches against the same derived text before returning results. [FTS5 trigram behaviour](https://sqlite.org/fts5.html#the_trigram_tokenizer)

FTS5 full-text queries do not match terms shorter than three Unicode scalar values. If any term has at least three scalars, use that indexed candidate set and verify all terms. If every term is shorter, require metadata filters whose candidate set fits 256 messages and 1 MiB of derived text; determine that with bounded count/size queries. Otherwise return `Overloaded/QueryTooBroad` with a request to narrow the scope. Never silently return no matches because a query cannot use the index, or let a short term trigger an unlimited table scan.

Indexed queries evaluate the text index before joining event rows. This prevents repeated full-text evaluation for every unrelated room event. The event join still applies room, sender, time and recipient filters before returning a result; sorting, cancellation and work limits remain in force.

Apply current access, history windows and recipient ignore filters to candidate selection and again before exposing hits/snippets. Candidate IDs are internal data, not an existence oracle. Each page has at most 50 results or 256 KiB, a two-second work deadline and bounded progress cancellation. Sort by the selected home's committed ordering key, with event ID as a stable tie-breaker. A cursor retains query/profile identity and a committed high-water mark; it cannot restore old access or filters. Report interruption or a required restart explicitly rather than treating an incomplete search as exhaustive.

Encrypted search runs only over authorised decrypted local archives. Service-readable history uses the service's protected index. Search results retain event IDs and open original context. Produce bounded snippets from original content, with highlight ranges expanded to grapheme boundaries; normalised offsets cannot be applied directly to original UTF-8 bytes. Expiry removes content and derived index entries under the shared retention policy.

## 4. Display and qualification

Terminal column width is a presentation estimate, not a protocol character count. Use the pinned width implementation on complete grapheme clusters, with an explicit terminal ambiguity setting and bounded viewport work. Terminal/font behaviour varies; actual GUI/TUI checks must cover combining text, emoji sequences, CJK, right-to-left text, shaping and resize. Missing glyphs or width disagreement cannot change IDs, permissions or content limits. CLI structured output preserves valid Unicode using its documented encoding.

Qualify Unicode 17 normalisation, case-folding and grapheme conformance vectors, including equivalent decomposed text, full-fold expansions, dotted/dotless I, joining marks and newly assigned characters. Verify terminal escape refusal/neutralisation, encrypted invalid-content progress after restart, short CJK/emoji search, mixed long/short terms, quoted punctuation, index version migration/collisions, active-filter changes and bounded cancellation. Measure index amplification and candidate work against the accepted quotas; a trigram index is not a promise of low storage overhead.
