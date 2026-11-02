# egret-starrocks

StarRocks images with security patches that egret needs before StarRocks can serve governed data
(Ranger grants, column masks, row filters) to users who write their own SQL.

This is **not an official StarRocks build**. It is the official release image of the tag in
[`UPSTREAM`](UPSTREAM) with two FE jars (`fe-core`, `fe-spi`) rebuilt from that tag plus
[`patches/`](patches). Every other file in the image, and the CN/BE images, are the official ones.

This repository and its images are public. Patch `0001` fixes an issue that was reported privately to
the StarRocks security team on 2026-11-02 and published here the same day, before an upstream fix:
until a StarRocks release contains it, any StarRocks with Iceberg catalogs is exposed (see the table).

## Patches

| Patch | Fixes | Upstream |
|---|---|---|
| `0001` | Iceberg metadata tables (`t$files`, `t$entries`, `t$manifests`, `t$partitions`, `t$snapshots`, ...) were read without any privilege check, exposing per-column bounds, partition values and row counts of `t` to any user, and the bounds of masked columns and filtered rows to masked/filtered users. Reading one now needs table-level SELECT on `t` and is refused (error 5210) when a row access or masking policy on `t` applies to the user. | Reported to the StarRocks security team on 2026-11-02; no upstream issue or fix yet. Published here 2026-11-02. |
| `0002` | Ranger column masks and row filters were not applied to statements run through `PREPARE`/`EXECUTE` or the MySQL binary protocol (`COM_STMT_PREPARE`/`COM_STMT_EXECUTE`), which egret's StarRocks connector uses for parameterised queries. | Public: issue [#78176](https://github.com/StarRocks/starrocks/issues/78176), PR [#78368](https://github.com/StarRocks/starrocks/pull/78368) (cherry-picked unchanged, original author kept). |
| `0003` | A row access or column masking policy rewrote an Iceberg table into a subquery that selected the hidden columns `_file` (the data file's object-store path) and `_pos` as ordinary ones, so `SELECT *` returned two extra columns only for users under a policy: a different result shape per user, broken `INSERT ... SELECT *`, and Iceberg views over `SELECT *` failing for those users. `*` now skips them under a policy as it does without one; a statement can still name them (an Iceberg DELETE reads them through the same rewrite). | No upstream issue or fix yet (found 2026-11-02; egret KI-337/KI-304). |
| `0004` | The FE's HTTP SQL API (`/api/v1/catalogs/<c>/databases/<d>/sql`, port 8030) and Arrow Flight SQL ran user SQL without marking its relations for the policy rewrite, so a user under a mask and a row filter read every row and column in the clear through either. Both now apply the policies. | Same gap fixed on main by the open PR [#78049](https://github.com/StarRocks/starrocks/pull/78049) (issue [#78175](https://github.com/StarRocks/starrocks/issues/78175)); it does not apply to 4.1.7, so this is a backport of its approach (same helper name). |
| `0005` | `SHOW CREATE CATALOG` had no privilege check: any user who could log in read every external catalog's properties (endpoints, warehouse, the first and last characters of its keys). It now needs a privilege on the catalog, as `SHOW CATALOGS` does to list it. | No upstream issue or fix yet. |
| `0006` | `FILES()` had no privilege: any user read and wrote object storage through it with no table privilege, mask or row filter, and with `aws.s3.use_instance_profile` through the BE's own cloud identity. Every use (`SELECT ... FROM FILES`, `INSERT INTO FILES`, `DESC FILES`) now needs OPERATE on SYSTEM (error 5211). | Open upstream: [#79980](https://github.com/StarRocks/starrocks/issues/79980), [#80233](https://github.com/StarRocks/starrocks/issues/80233). |
| `0007` | A materialized view's refresh reads its base tables without its user's masks and row filters and stores the result, so a user under both could create a materialized view over the table and read it all in the clear. Creating one over a table where such a policy applies to the creator is refused (error 5212), and a refresh stops once its user comes under one. Strict by design: the refusal does not look at which columns the view reads. | No upstream issue or fix yet. |

Drop a patch when the upstream release in `UPSTREAM` contains it.

## Images

| Image | Base | Use |
|---|---|---|
| `ghcr.io/egret-data/egret-starrocks-fe:<tag>-egret.<n>` | `starrocks/fe-ubuntu:<tag>` | FE for the kube-starrocks operator (egret's provisioner) |
| `ghcr.io/egret-data/egret-starrocks-allin1:<tag>-egret.<n>` | `starrocks/allin1-ubuntu:<tag>` | compose / local, and the e2e |

Use the official `starrocks/cn-ubuntu:<tag>` for compute nodes: no patch touches BE/CN.
`/opt/starrocks/fe/EGRET-PATCHES.txt` (allin1: `/data/deploy/starrocks/fe/EGRET-PATCHES.txt`) lists the
patches an image carries.

## Build

Published images are built only by CI (`.github/workflows/build.yml`): every push builds and runs the
e2e, and a tag `<UPSTREAM_TAG>-egret.<EGRET_PATCH_LEVEL>` also pushes both images to GHCR. CI builds with
JDK 17, as the official images, and with the thrift compiler version of the tag's `thirdparty/vars.sh`
(0.24.0 for 4.1.7); Ubuntu's `thrift-compiler` package is too old.

A local build is for development only. It needs git, JDK 17, Maven 3.9, `thrift` (same version as
CI) and `protoc` on `PATH`, Python 3, Docker.

```bash
scripts/apply.sh          # fetch the tag in UPSTREAM into work/starrocks, verify its commit, apply patches/
scripts/build-fe.sh       # build fe-spi + fe-core, copy the jars to out/
scripts/build-images.sh   # build both images (REGISTRY=... to change the registry)
tests/e2e/run.sh ghcr.io/egret-data/egret-starrocks-allin1:4.1.7-egret.1
```

## Security e2e

`tests/e2e/run.sh <allin1-image>` starts RustFS, an Iceberg REST catalog and the StarRocks image with
`access_control = ranger` on a private Docker network, and a stand-in Ranger Admin on the host that
serves the policies in `tests/e2e/policies.py`. `tests/e2e/checks.py` then reads through every path
(text protocol, SQL `PREPARE`, binary protocol, `EXECUTE AS` + binary protocol, Iceberg tables with
`plan_mode = distributed`, metadata tables) as users with no policy, with a mask and a row filter,
and with plain grants, and fails on any result the policies do not allow.

Run it against the official image too: the checks tagged with a patch number must fail there, which
shows that each check detects what its patch fixes. Checks tagged `-` (controls) and `guard` (a
behaviour a patch must not break) pass on both.

Result on 2026-11-02 against `4.1.7-egret.2` (patches `0001` to `0003`) with the checks for `0004` to
`0007` added: 28/34 passed, and the 6 failures were exactly those checks (bob read clear emails and `eu`
rows through the HTTP SQL API and Arrow Flight SQL; eve, with no grant, read `SHOW CREATE CATALOG ice`;
eve and bob read the orders parquet files through `FILES()`; mallory, under a mask and a row filter,
created a materialized view over `customers`, whose refresh stored all three rows with clear phone numbers).

Result on 2026-11-02 against the official `starrocks/allin1-ubuntu:4.1.7` with the `0003` checks
added: 10/19 passed, every `0001`/`0002`/`0003` check failed; bob's `SELECT *` on `orders` returned
`_file` (`s3://warehouse/sales/orders/data/...parquet`) and `_pos` after the table's three columns.

Earlier result (patches `0001`/`0002`, 15 checks) against the official image: 8/15 passed, every
`0001`/`0002` check failed (bob read clear phone numbers and every row through `PREPARE`, the binary
protocol and `EXECUTE AS`; eve, with no policy, read `orders$files` bounds and `orders$snapshots`).
Against `ghcr.io/egret-data/egret-starrocks-allin1:4.1.7-egret.1`: 15/15 passed. With 0001's
exemption for metadata collect jobs removed (a mutation build), the `guard` check failed: bob's
Iceberg query with `plan_mode = distributed` was refused, because the collect job runs as root and the
orders row filter also applies to root.

The local build used JDK 21 with `--release 17`; the official jars are built with JDK 17 and contain
681 more synthetic `$N` switch-map classes (no other class differs in name). CI builds with JDK 17.

## Known limits (not patched)

- `root` is not checked by Ranger (upstream [#72198](https://github.com/StarRocks/starrocks/issues/72198)); it
  is still subject to masks and row filters. Keep its password with the operator.
- Tag policies work with no patch (measured, `[tag]` checks): when the policy download carries a
  `TagEnricher` in the service definition and a `tagPolicies` block, as Ranger Admin serves a service
  linked to a tag service, the plugin fetches `/service/tags/download/<service>` on its own and applies
  tag masks, tag row filters and tag denies, through every path. The tag attachments must use the
  StarRocks resource names (`catalog`, `database`, `table`, `column`). Without the enricher it never
  requests the tags (upstream [#67458](https://github.com/StarRocks/starrocks/issues/67458) asks for
  this; PR [#70883](https://github.com/StarRocks/starrocks/pull/70883) documents it).
- `EXPLAIN COSTS` shows a filtered user the statistics of the whole table (row count, min and max of unmasked
  columns); masked columns show no values.
- Loads (`BROKER LOAD`, pipes, routine load) that name `aws.s3.use_instance_profile` read with the BE's
  identity; they need INSERT on the target table. Run BE/CN without a cloud role, or with one limited to the
  storage the engine must read.
- Arrow Flight SQL fails on the official images unless the FE JVM gets
  `--add-opens=java.base/java.nio=ALL-UNNAMED`; the e2e adds it to test `0004`.

## Moving to a new upstream release

1. Set `UPSTREAM_TAG`/`UPSTREAM_COMMIT` (and `JAR_SUFFIX` on a minor bump), reset `EGRET_PATCH_LEVEL` to 1.
2. `scripts/apply.sh`; drop patches upstream now contains, rebase the others
   (`git format-patch` from a branch on the new tag).
3. Build, run the e2e against the new official image (patch checks fail) and the new egret image
   (all pass), then tag.

## License

Apache License 2.0, as StarRocks. `NOTICE.upstream.txt` is StarRocks' NOTICE.
