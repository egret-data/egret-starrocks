"""Write the policy JSON the fake Ranger serves: policies.py <servicedef.json> <out.json>.

alice: SELECT everywhere, no mask or filter (control).
bob:   SELECT everywhere, MASK_NULL on demo.customers.phone and ice.sales.orders.email,
       row filters id = 1 on demo.customers and region = 'us' on ice.sales.orders.
eve:   nothing.
svc:   IMPERSONATE on every user (the way egret's delegator queries as the user).
mallory: bob's grant, mask and row filter on demo.customers, and she may create and fill tables, views and
       materialized views in demo: the write paths (CTAS, INSERT ... SELECT, views, materialized views) must
       not carry data past her policy.
root:  the orders row filter too. Root is still subject to row filters and masks, and Iceberg metadata
       collect jobs (plan_mode = distributed) read t$logical_iceberg_metadata as root, so this makes the
       "guard" check fail if patch 0001 ever stops exempting those jobs.
"""
import json
import sys

ACCESS = [{"type": "select", "isAllowed": True}]


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


for catalog, db in (("default_catalog", "demo"), ("ice", "sales")):
    policy(f"grant-{catalog}", 0, res(catalog, db, "*", "*"), policyItems=[item(["alice", "bob"])])
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
       dataMaskPolicyItems=[item(["bob", "mallory"], dataMaskInfo={"dataMaskType": "MASK_NULL"})])
policy("mask-email", 1, res("ice", "sales", "orders", "email"),
       dataMaskPolicyItems=[item(["bob"], dataMaskInfo={"dataMaskType": "MASK_NULL"})])
policy("filter-customers", 2, res("default_catalog", "demo", "customers"),
       rowFilterPolicyItems=[item(["bob", "mallory"], rowFilterInfo={"filterExpr": "id = 1"})])
policy("filter-orders", 2, res("ice", "sales", "orders"),
       rowFilterPolicyItems=[item(["bob", "root"], rowFilterInfo={"filterExpr": "region = 'us'"})])
policy("impersonate", 0, {"user": values("*")},
       policyItems=[item(["svc"], accesses=[{"type": "impersonate", "isAllowed": True}])])

service_def = json.load(open(sys.argv[1]))
json.dump({"serviceName": "e2e", "serviceId": 1, "policyVersion": 1, "serviceDef": service_def,
           "policies": policies, "auditMode": "audit-default"}, open(sys.argv[2], "w"))
print(f"wrote {len(policies)} policies to {sys.argv[2]}")
