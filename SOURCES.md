# Endpoint sources and classification

Snapshot: 2026-11-05. Public inventory: https://docs.paloaltonetworks.com/resources/edl-hosting-service

Feed hosting is separate from service classification. Only exact URL-feed addresses in `assets/edl-catalog.txt` are accepted by CLI and dashboard. HTTPS origin, path, credentials, query and fragment restrictions also apply; redirects are refused. This is a reviewed catalog, not a runtime discovery of arbitrary feeds.

| Group | URL feeds | IP feeds in source | Support |
|---|---:|---:|---|
| Akamai | 0 | 2 | Custom hostname; IP-only source |
| Android Enterprise | 3 | 0 | URL feed import |
| Atlassian Cloud | 0 | 170 | Custom hostname; IP-only source |
| Amazon Web Services | 0 | 1117 | Custom hostname; IP-only source |
| Broadcom | 20 | 396 | URL feed import |
| Datadog | 0 | 43 | Custom hostname; IP-only source |
| Fastly | 0 | 2 | Custom hostname; IP-only source |
| Google Cloud | 0 | 120 | Custom hostname; IP-only source |
| Google Workspace | 0 | 2 | Custom hostname; IP-only source |
| HashiCorp | 0 | 10 | Custom hostname; IP-only source |
| Okta | 0 | 9 | Custom hostname; IP-only source |
| Oracle Cloud | 0 | 162 | Custom hostname; IP-only source |
| Palo Alto Networks services | 9 | 0 | URL feed import |
| Samsung Knox | 15 | 4 | URL feed import |
| Salesforce | 9 | 63 | URL feed import |
| Cisco Webex | 1 | 1 | URL feed import |
| Zoom | 8 | 14 | URL feed import |
| Zscaler | 2 | 10 | URL feed import |

`m365`, `azure`, `msdefender`, `msintune` and `github` are explicitly excluded. GitHub is Microsoft-owned even though the source lists it as its own service group. Other separately named source groups remain available. Unknown new groups require review; absence from the exclusion list alone is not authorization to include them.

Domain suffixes are not used to infer service ownership. A listed dependency in an included feed is retained even if its domain belongs to another provider. Custom input is syntactically validated and explicitly operator-supplied; it is not an ownership certification. This tool provides no complete service allowlist.

## Update procedure

Run `python scripts/update-catalog.py` to fetch the documented inventory and print differences without changing files. Review new groups, source descriptions and ownership. Unknown groups cause an error until `assets/service-groups.json` or the explicit exclusions in the script are reviewed. `--write` updates the URL inventory and counts for approved groups; review the diff, update the snapshot date/documentation and run Cargo checks. Endpoint contents are fetched only on user selection and hash/timestamp provenance is recorded in each feed report.

No CNAME, reverse-DNS or IP-range expansion is used to fabricate service hostnames. Wildcard and path entries are retained as exclusions. Group labels are a directory aid; availability varies by region, tenant, authorization and request protocol.
