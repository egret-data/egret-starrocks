"""Write what the fake Ranger serves:
policies.py <servicedef.json> <tag-servicedef.json> <policies.json> <tags.json> [--probe [--version N] [--revoke loader]]

alice: SELECT everywhere, no mask or filter (control).
bob:   SELECT everywhere, MASK_NULL on demo.customers.phone and ice.sales.orders.email,
       row filters id = 1 on demo.customers and region = 'us' on ice.sales.orders.
eve:   nothing.
tina:  SELECT on demo.* and ice.sales.* by resource policy; her masks, row filter and deny come ONLY from tag
       policies (PII -> MASK_NULL on customers.phone and orders.email, EU_RESTRICTED -> row filter
       region = 'us' on orders, SECRET -> deny on customers.grade), served the way Ranger Admin serves a
       service linked to a tag service: a TagEnricher in the service def, a tagPolicies block and the tags
       on /service/tags/download.
svc:   IMPERSONATE on every user (the way egret's delegator queries as the user).
egret_audit: INSERT on the audit table only, the AuditLoader plugin's stream-load user.
mallory: bob's grant, mask and row filter on demo.customers, and she may create and fill tables, views and
       materialized views in demo: the write paths (CTAS, INSERT ... SELECT, views, materialized views) must
       not carry data past her policy.
root:  the orders row filter too. Root is still subject to row filters and masks, and Iceberg metadata
       collect jobs (plan_mode = distributed) read t$logical_iceberg_metadata as root, so this makes the
       "guard" check fail if patch 0001 ever stops exempting those jobs.

With no flag the output is exactly what run.sh's checks expect. The probe flags (probe.sh) add:
--probe        udfdev (bob's grant, mask and row filter on demo.customers, CREATE FUNCTION in demo, USAGE on
               demo's functions), loader (INSERT on demo.s_target, r_target and pk_target, the row filter
               id = 1 on pk_target) and, on hive, jdbc and paimon, the policies ice.sales.orders has: alice
               reads all, bob and mallory get MASK_NULL on email and the row filter region = 'us', eve nothing.
--version N    policyVersion N (the plugin reloads when it grows), for a run that revokes a grant.
--revoke loader  leave out loader's INSERT items (needs --probe; the row filter stays).
"""
import json
import sys

ACCESS = [{"type": "select", "isAllowed": True}]

args = sys.argv[1:]
PROBE = "--probe" in args


def flag_value(name, default):
    return args[args.index(name) + 1] if name in args else default


POLICY_VERSION = int(flag_value("--version", 1))
REVOKE = flag_value("--revoke", None)
positional = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] not in ("--version", "--revoke"))]
if len(positional) != 4 or (not PROBE and (POLICY_VERSION != 1 or REVOKE)) or REVOKE not in (None, "loader"):
    sys.exit(__doc__)
SERVICE_DEF, TAG_DEF, POLICIES_OUT, TAGS_OUT = positional


def values(v):
    return {"values": [v], "isExcludes": False, "isRecursive": False}


def res(catalog, db, table, column=None):
    r = {"catalog": values(catalog), "database": values(db), "table": values(table)}
    if column:
        r["column"] = values(column)
    return r


def item(users, accesses=ACCESS, **extra):
    return dict({"roles": [], "users": users, "groups": [], "accesses": accesses, "delegateAdmin": False}, **extra)


policies = []


def policy(name, policy_type, resources, **items):
    policies.append(dict({
        "id": len(policies) + 1, "name": name, "service": "e2e", "serviceType": "starrocks",
        "isEnabled": True, "policyType": policy_type, "resources": resources, "policyItems": [],
        "denyPolicyItems": [], "allowExceptions": [], "denyExceptions": [], "policyPriority": 0,
        "isDenyAllElse": False, "policyLabels": [], "additionalResources": [], "description": "", "version": 1,
    }, **items))


# udfdev is bob on demo.customers (probe stacks only).
DEMO_BOB = ["bob", "udfdev"] if PROBE else ["bob"]
for catalog, db in (("default_catalog", "demo"), ("ice", "sales")):
    users = ["alice", "bob", "tina"] + (["udfdev"] if PROBE and catalog == "default_catalog" else [])
    policy(f"grant-{catalog}", 0, res(catalog, db, "*", "*"), policyItems=[item(users)])
policy("grant-mallory-select", 0, res("default_catalog", "demo", "*", "*"), policyItems=[item(["mallory"])])
policy("grant-mallory-tables", 0, res("default_catalog", "demo", "*"),
       policyItems=[item(["mallory"], accesses=[{"type": a, "isAllowed": True}
                                                for a in ("insert", "drop", "refresh", "alter")])])
policy("grant-mallory-create", 0, {"catalog": values("default_catalog"), "database": values("demo")},
       policyItems=[item(["mallory"], accesses=[{"type": a, "isAllowed": True}
                                                for a in ("create table", "create view",
                                                          "create materialized view")])])
policy("grant-mallory-mvs", 0, {"catalog": values("default_catalog"), "database": values("demo"),
                                "materialized_view": values("*")},
       policyItems=[item(["mallory"], accesses=[{"type": a, "isAllowed": True}
                                                for a in ("refresh", "drop", "alter")])])
policy("grant-mallory-views", 0, {"catalog": values("default_catalog"), "database": values("demo"),
                                  "view": values("*")},
       policyItems=[item(["mallory"], accesses=[{"type": "drop", "isAllowed": True}])])
policy("mask-phone", 1, res("default_catalog", "demo", "customers", "phone"),
       dataMaskPolicyItems=[item(DEMO_BOB + ["mallory"], dataMaskInfo={"dataMaskType": "MASK_NULL"})])
policy("mask-email", 1, res("ice", "sales", "orders", "email"),
       dataMaskPolicyItems=[item(["bob"], dataMaskInfo={"dataMaskType": "MASK_NULL"})])
policy("filter-customers", 2, res("default_catalog", "demo", "customers"),
       rowFilterPolicyItems=[item(DEMO_BOB + ["mallory"], rowFilterInfo={"filterExpr": "id = 1"})])
policy("filter-orders", 2, res("ice", "sales", "orders"),
       rowFilterPolicyItems=[item(["bob", "root"], rowFilterInfo={"filterExpr": "region = 'us'"})])
policy("audit-loader", 0, res("default_catalog", "starrocks_audit_db__", "starrocks_audit_tbl__"),
       policyItems=[item(["egret_audit"], accesses=[{"type": "insert", "isAllowed": True}])])
policy("impersonate", 0, {"user": values("*")},
       policyItems=[item(["svc"], accesses=[{"type": "impersonate", "isAllowed": True}])])

if PROBE:
    def grants(*types):
        return [{"type": t, "isAllowed": True} for t in types]

    policy("grant-udfdev-create-function", 0, {"catalog": values("default_catalog"), "database": values("demo")},
           policyItems=[item(["udfdev"], accesses=grants("create function"))])
    policy("grant-udfdev-use-function", 0, {"catalog": values("default_catalog"), "database": values("demo"),
                                            "function": values("*")},
           policyItems=[item(["udfdev"], accesses=grants("usage"))])
    policy("filter-pk-target", 2, res("default_catalog", "demo", "pk_target"),
           rowFilterPolicyItems=[item(["loader"], rowFilterInfo={"filterExpr": "id = 1"})])
    # The policies of ice.sales.orders, on the other catalogs. Not root's filter: that one exists for the
    # Iceberg metadata collect jobs, which these connectors do not run.
    for catalog in ("hive", "jdbc", "paimon"):
        policy(f"grant-{catalog}", 0, res(catalog, "sales", "*", "*"), policyItems=[item(["alice", "bob", "mallory"])])
        policy(f"mask-email-{catalog}", 1, res(catalog, "sales", "orders", "email"),
               dataMaskPolicyItems=[item(["bob", "mallory"], dataMaskInfo={"dataMaskType": "MASK_NULL"})])
        policy(f"filter-orders-{catalog}", 2, res(catalog, "sales", "orders"),
               rowFilterPolicyItems=[item(["bob", "mallory"], rowFilterInfo={"filterExpr": "region = 'us'"})])
    # Last, so that revoking them leaves every other policy id where it was.
    for table in ("s_target", "r_target", "pk_target"):
        if REVOKE != "loader":
            policy(f"grant-loader-insert-{table}", 0, res("default_catalog", "demo", table),
                   policyItems=[item(["loader"], accesses=grants("insert"))])

# Tag policies (service e2e_tag, the tag service-def) and the tags they match.
tag_policies = []


def tag_policy(name, policy_type, tag, **items):
    tag_policies.append(dict({
        "id": 1000 + len(tag_policies), "name": name, "service": "e2e_tag", "serviceType": "tag",
        "isEnabled": True, "policyType": policy_type,
        "resources": {"tag": {"values": [tag], "isExcludes": False, "isRecursive": False}},
        "policyItems": [], "denyPolicyItems": [], "allowExceptions": [], "denyExceptions": [],
        "dataMaskPolicyItems": [], "rowFilterPolicyItems": [], "policyPriority": 0, "isDenyAllElse": False,
        "policyLabels": [], "additionalResources": [], "conditions": [], "description": "", "version": 1,
    }, **items))


tag_policy("tag-pii-mask", 1, "PII",
           dataMaskPolicyItems=[item(["tina"], dataMaskInfo={"dataMaskType": "MASK_NULL"})])
tag_policy("tag-eu-filter", 2, "EU_RESTRICTED",
           rowFilterPolicyItems=[item(["tina"], rowFilterInfo={"filterExpr": "region = 'us'"})])
tag_policy("tag-secret-deny", 0, "SECRET", denyPolicyItems=[item(["tina"])])

TAGGED = [  # (tag, resource elements)
    ("PII", {"catalog": "default_catalog", "database": "demo", "table": "customers", "column": "phone"}),
    ("PII", {"catalog": "ice", "database": "sales", "table": "orders", "column": "email"}),
    ("EU_RESTRICTED", {"catalog": "ice", "database": "sales", "table": "orders"}),
    ("SECRET", {"catalog": "default_catalog", "database": "demo", "table": "customers", "column": "grade"}),
]
tag_names = sorted({t for t, _ in TAGGED})
service_tags = {
    "op": "add_or_update", "serviceName": "e2e", "tagVersion": 1, "isDelta": False,
    "tagDefinitions": {str(i + 1): {"id": i + 1, "name": n, "source": "e2e", "attributeDefs": []}
                       for i, n in enumerate(tag_names)},
    "tags": {str(i + 1): {"id": i + 1, "type": n, "attributes": {}} for i, n in enumerate(tag_names)},
    "serviceResources": [
        {"id": i + 1, "serviceName": "e2e", "isEnabled": True,
         "resourceElements": {k: {"values": [v], "isExcludes": False, "isRecursive": False} for k, v in r.items()}}
        for i, (_, r) in enumerate(TAGGED)],
    "resourceToTagIds": {str(i + 1): [tag_names.index(t) + 1] for i, (t, _) in enumerate(TAGGED)},
}

service_def = json.load(open(SERVICE_DEF))
# What Ranger Admin adds to the definition of a service linked to a tag service.
service_def["contextEnrichers"] = [{
    "itemId": 1, "name": "TagEnricher", "enricher": "org.apache.ranger.plugin.contextenricher.RangerTagEnricher",
    "enricherOptions": {"tagRetrieverClassName": "org.apache.ranger.plugin.contextenricher.RangerAdminTagRetriever",
                        "tagRefresherPollingInterval": "10000"}}]
tag_def = json.load(open(TAG_DEF))
json.dump({"serviceName": "e2e", "serviceId": 1, "policyVersion": POLICY_VERSION, "serviceDef": service_def,
           "policies": policies, "auditMode": "audit-default",
           "tagPolicies": {"serviceName": "e2e_tag", "serviceId": 2, "policyVersion": 1, "serviceDef": tag_def,
                           "policies": tag_policies, "auditMode": "audit-default"}},
          open(POLICIES_OUT, "w"))
json.dump(service_tags, open(TAGS_OUT, "w"))
print(f"wrote {len(policies)} policies, {len(tag_policies)} tag policies to {POLICIES_OUT}, "
      f"{len(TAGGED)} tag attachments to {TAGS_OUT}")
