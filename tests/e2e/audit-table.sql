-- The audit table egret creates on every StarRocks engine (egret-starrocks /opt/egret/auditloader.zip
-- loads it). The AuditLoader columns plus `command` and `querySource` (patch auditloader/0001), one
-- partition per day created on write, 30 days kept.
CREATE DATABASE IF NOT EXISTS starrocks_audit_db__;
CREATE TABLE IF NOT EXISTS starrocks_audit_db__.starrocks_audit_tbl__ (
  `queryId` VARCHAR(64),
  `timestamp` DATETIME NOT NULL,
  `queryType` VARCHAR(12),
  `clientIp` VARCHAR(32),
  `user` VARCHAR(64),
  `authorizedUser` VARCHAR(64),
  `resourceGroup` VARCHAR(64),
  `catalog` VARCHAR(32),
  `db` VARCHAR(96),
  `state` VARCHAR(8),
  `errorCode` VARCHAR(512),
  `queryTime` BIGINT,
  `scanBytes` BIGINT,
  `scanRows` BIGINT,
  `returnRows` BIGINT,
  `cpuCostNs` BIGINT,
  `memCostBytes` BIGINT,
  `stmtId` INT,
  `isQuery` TINYINT,
  `feIp` VARCHAR(128),
  `stmt` VARCHAR(1048576),
  `digest` VARCHAR(32),
  `planCpuCosts` DOUBLE,
  `planMemCosts` DOUBLE,
  `pendingTimeMs` BIGINT,
  `candidateMVs` VARCHAR(65533) NULL,
  `hitMvs` VARCHAR(65533) NULL,
  `QueriedRelations` ARRAY<VARCHAR(65533)> NULL,
  `warehouse` VARCHAR(128) NULL,
  `command` VARCHAR(64) NULL,
  `querySource` VARCHAR(32) NULL
) ENGINE = OLAP
DUPLICATE KEY (`queryId`, `timestamp`, `queryType`)
PARTITION BY date_trunc('day', `timestamp`)
DISTRIBUTED BY HASH (`queryId`) BUCKETS 1
PROPERTIES (
  "replication_num" = "1",
  "partition_retention_condition" = "`timestamp` >= current_date() - interval 30 day"
);
