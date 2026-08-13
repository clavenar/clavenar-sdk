# Security Policy

<!-- clavenar-security-policy:v1 -->

- **Policy version:** 1.0.0
- **Effective date:** 2026-07-27
- **Canonical contact:** **vanteguardlabs@gmail.com**

This policy covers vulnerability disclosure for the complete Clavenar release
graph. Report suspected vulnerabilities privately; do not open a public issue.

## Reporting a vulnerability

Email the canonical contact and include:

- what is affected and the likely security impact;
- reproducible steps or a minimal proof of concept;
- the repository and commit, or the immutable release digest;
- the affected surface and any required configuration; and
- whether you want public credit.

Do not send live credentials, personal or customer data, or unnecessary
production detail. We do not currently publish a PGP key. Ask in the first
message if you need a separate encrypted channel.

## Supported versions

| Source or artifact | Support status |
|---|---|
| Current `main` branch | Receives source fixes and feeds the next release. It does not prove that a live deployment has updated. |
| Latest immutable release for the affected repository or stack | Receives coordinated security fixes. |
| Older releases, mutable tags, untagged snapshots, forks, and downstream modifications | Unsupported unless a repository-specific notice says otherwise. |

A repository with no published release supports its current `main` source
only. Fixes normally land on `main` and then in a new immutable release. We do
not rewrite existing releases.

## Scope

The following are in scope:

- all 30 repositories named by the canonical Clavenar stack release policy;
- source, packages, binaries, images, Helm artifacts, SBOMs, and provenance
  belonging to an exact published release;
- Clavenar-owned public web, release, and download endpoints; and
- documented authentication, authorization, isolation, cryptographic,
  audit-chain, policy-enforcement, update, and recovery boundaries.

Private repositories are in scope only for reporters who already have
authorized access. This policy does not grant access or authorize attempts to
obtain it.

Report dependency issues when they create a distinct Clavenar impact or expose
an unsafe integration or default. Issues with no Clavenar-specific impact may
be redirected to the upstream maintainer.

## Runtime and deployment boundary

Source, immutable artifacts, configured deployments, and externally observed
state are separate evidence states. A source capability or fix does not prove
that every deployment is configured, reachable, or updated.

Demo, simulator, development, evaluation, diagnostic, and administrative
surfaces are not customer-production promises. They remain in scope for
authentication, authorization, isolation, and unsafe-default defects when used
as documented. Exposure varies by release and configuration;
this policy never treats loopback placement alone as an authorization
boundary.

Operator-provided infrastructure, credentials, policy, network controls,
forks, and modifications are outside Clavenar's control. A Clavenar defect
that makes a documented configuration unsafe remains in scope.

## Workflow and release evidence

Only automation checked into the affected repository and receipts bound to an
exact immutable release show that a build, test, audit, SBOM, provenance,
signing, or publication step ran. This policy makes no broader workflow
promise. Repository workflows and the protected stack-release receipt are
authoritative only for the checks they record.

The centrally enforced `clavenar.security-policy/v1` contract rejects missing,
stale, or divergent root policies across the exact 30-repository release graph.

## Response process

- **Within 72 hours:** acknowledge the report and establish a private tracking
  channel.
- **Within 7 days:** share initial triage, affected scope, severity direction,
  and the CVE plan when applicable.
- **At least every 14 days while open:** provide progress or explain a material
  schedule change.
- **Target within 90 days:** publish a coordinated fix and disclosure, or agree
  on a revised date with the reporter.

Complex multi-repository or ecosystem fixes may take longer. We will explain
material delays, coordinate credit, and avoid publishing exploit details
before a fix is reasonably available.

## Safe harbor

We will not pursue civil or criminal action for research that:

- is conducted in good faith on systems and accounts the researcher owns or
  has explicit permission to test;
- avoids privacy violations, persistence, data destruction, service
  degradation, and access beyond what demonstrates the impact;
- stops and reports promptly after sensitive data or unintended access is
  encountered; and
- allows reasonable time for remediation before public disclosure.

This safe harbor does not authorize testing third-party systems, social
engineering, physical attacks, denial-of-service or volume testing, credential
stuffing, spam, or violations of applicable law.

## Disclosure

We prefer coordinated disclosure. A published advisory should name affected
versions and the immutable fixed release, credit the reporter if requested,
and separate verified impact from assumptions. Duplicate or already-public
reports remain useful when they identify a new affected path or material
impact.
