# egret-starrocks

StarRocks images with security patches that egret needs before StarRocks can serve governed data
(Ranger grants, column masks, row filters) to users who write their own SQL.

This is **not an official StarRocks build**. It is the official release image of the tag in
[`UPSTREAM`](UPSTREAM) with two FE jars (`fe-core`, `fe-spi`) rebuilt from that tag plus
[`patches/`](patches). Every other file in the image, and the CN/BE images, are the official ones.

Keep this repository **private** while it carries a patch for an issue that upstream has not
disclosed (see the table).

## Patches

| Patch | Fixes | Upstream |
|---|---|---|
| `0001` | Iceberg metadata tables (`t$files`, `t$entries`, `t$manifests`, `t$partitions`, `t$snapshots`, ...) were read without any privilege check, exposing per-column bounds, partition values and row counts of `t` to any user, and the bounds of masked columns and filtered rows to masked/filtered users. Reading one now needs table-level SELECT on `t` and is refused (error 5210) when a row access or masking policy on `t` applies to the user. | Reported privately to the StarRocks security team (2026-11-02). Not public. |
| `0002` | Ranger column masks and row filters were not applied to statements run through `PREPARE`/`EXECUTE` or the MySQL binary protocol (`COM_STMT_PREPARE`/`COM_STMT_EXECUTE`), which egret's StarRocks connector uses for parameterised queries. | Public: issue [#78176](https://github.com/StarRocks/starrocks/issues/78176), PR [#78368](https://github.com/StarRocks/starrocks/pull/78368) (cherry-picked unchanged, original author kept). |

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

Needs git, JDK 17+, Maven 3.9, `thrift` and `protoc` on `PATH`, Python 3, Docker.

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

Result on 2026-11-02 against the official `starrocks/allin1-ubuntu:4.1.7`: 8/15 passed, every
`0001`/`0002` check failed (bob read clear phone numbers and every row through `PREPARE`, the binary
protocol and `EXECUTE AS`; eve, with no policy, read `orders$files` bounds and `orders$snapshots`).
Against `ghcr.io/egret-data/egret-starrocks-allin1:4.1.7-egret.1`: 15/15 passed. With 0001's
exemption for metadata collect jobs removed (a mutation build), the `guard` check failed: bob's
Iceberg query with `plan_mode = distributed` was refused, because the collect job runs as root and the
orders row filter also applies to root.

The local build used JDK 21 with `--release 17`; the official jars are built with JDK 17 and contain
681 more synthetic `$N` switch-map classes (no other class differs in name). CI builds with JDK 17.

## Moving to a new upstream release

1. Set `UPSTREAM_TAG`/`UPSTREAM_COMMIT` (and `JAR_SUFFIX` on a minor bump), reset `EGRET_PATCH_LEVEL` to 1.
2. `scripts/apply.sh`; drop patches upstream now contains, rebase the others
   (`git format-patch` from a branch on the new tag).
3. Build, run the e2e against the new official image (patch checks fail) and the new egret image
   (all pass), then tag.

## License

Apache License 2.0, as StarRocks. `NOTICE.upstream.txt` is StarRocks' NOTICE.
