# Publisher policy consumer

`publisher-allowlist.json` is the generated publisher consumer from the private
`AtyaLibraries/platform` policy repository. It is not an independently maintained
package catalog.

The snapshot in this revision was copied from
`generated/publisher-allowlist.json` at platform commit
`34613b307f70508d7d7b6fb9916a2c43357b72cd`. Its source blob is
`bc4d0fbfe4e752f7db5da17ddf047a1bbb3eb4b8`, policy version `1.5.1`, and schema
version `1.0.0`.

The publisher consumes the snapshot at its own immutable workflow revision. This
keeps the production job independent of mutable remote policy and avoids granting
it cross-repository credentials. A policy change is rolled forward by regenerating
the consumer in platform, copying the generated file without manual edits, updating
the provenance values above, and reviewing the publisher change before it reaches
`main`. Until that happens, a newly admitted package fails closed.

Rollback is a revert of the publisher policy/workflow commit. Do not edit individual
mappings in this repository and do not fall back to dispatch-supplied package ids.
