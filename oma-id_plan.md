# OMA-ID: Rails IAM and Managed Omarchy Workstations

**Document:** `oma-id_plan.md`  
**Revision:** 0.3 - owned Omarchy login stack decision and P0 native foundation  
**Prepared:** 2026-09-05  
**Status:** P0 discovery in progress; protocol and lease-decision spikes exist. No production application, verified native login, or upstream PR is represented as completed.  
**Primary platform:** Omarchy on x86_64, initially organization-owned workstations.  
**Server:** Ruby on Rails.  
**Working project name:** `oma-id`; availability of the name, domains, and trademarks has not been checked.

## 0. Read this first: the intended outcome

Build a self-hostable identity and workstation-management platform that lets an organization install Omarchy, select **Personal use** or **School / work**, and enroll a work machine directly into its own OMA-ID server. The organization should then be able to manage people, access, devices, configuration, updates, and a deliberately scoped set of support operations without requiring Microsoft Entra ID, Intune, a commercial RMM, or Windows for the supported workstation fleet.

OMA-ID must be a real Rails identity provider and management application, not merely a Rails dashboard in front of a mandatory Microsoft or Keycloak service. Reuse established protocol and operating-system components; do not invent cryptography or implement a new operating-system login stack casually.

The central architectural separation is:

| Responsibility | Proposed owner |
|---|---|
| People, groups, MFA, application SSO, access policy, device directory, management UI, audit | `oma-id`, a Rails modular monolith |
| Device enrollment, inventory, policy reconciliation, health, update coordination | `oma-id-agent`, a native Rust service |
| Narrow, privileged operating-system changes | A small local privileged helper, separately constrained from the network-facing agent |
| Linux account and authentication | `oma-id-agent`, a thin `pam_oma_id` client, and provisioned local Unix accounts |
| Offline authorization and revocation enforcement | Device-bound leases evaluated by `oma-id-agent`, independently of cached authentication |
| Personal/work choice and provisioning handoff | Small, opt-in changes to the Omarchy ISO and runtime provisioning repositories |
| Certificate issuance and signed software distribution | Established CA/signing components with separate keys and trust boundaries |

**The first technical milestone is an end-to-end identity/login experiment, not a large administration dashboard.** A successful browser login is not proof that SDDM, Quickshell, sudo, recovery, and offline revocation work.

### Interpretation of this plan

Statements marked **Observed** describe reviewed upstream documentation or source. References such as **[S03]** resolve to the source register at the end. Everything else is a **proposed project requirement, design choice, assumption, or test**, not a claim about existing Omarchy or OMA-ID functionality. Numeric defaults and capacity objectives are proposed starting points, not measured results.

MUST means a release acceptance requirement. SHOULD means the default unless an architecture decision record explains the exception. Future Codex work must preserve this distinction.

## 1. Scope, assumptions, and what "replace Microsoft" means

### 1.1 Initial assumptions

Start with a small, organization-owned fleet and one organization per self-hosted deployment. Model organization ownership explicitly from the beginning, but do not delay the first working deployment for a general-purpose multitenant SaaS offering. Shared-hosting support is a later, separately tested release gate.

The first hardware target is x86_64 UEFI, with a small, published supported-hardware list. ARM, arbitrary hardware, personally owned devices, and classroom kiosks are later profiles. The design must leave room for shared school/work machines without implementing every profile in the first pilot.

Use independently deployable OMA-ID infrastructure. Do not couple workstation availability to another business application's database, authentication session, release cadence, or tenant-switching middleware. A Rails application such as Umanni may become an OIDC client later; it must not be a prerequisite for OMA-ID to operate.

### 1.2 Replacement map

| Existing category | OMA-ID replacement target | Boundary |
|---|---|---|
| Entra workforce directory | People, groups, lifecycle, MFA, OIDC application SSO, access reviews | Application compatibility must be proven individually. |
| Entra device join / device access | Device enrollment, device keys, device directory, access decisions | Not an implementation of Microsoft's join protocol. |
| Intune workstation management | Inventory, configuration, software catalog, update rings, compliance evidence, recovery-key escrow | Linux-native policies, not a translator for every Windows CSP/GPO. |
| RMM | Health, alerts, approved diagnostic tasks, bounded remediation, support sessions | No claim of complete RMM parity in the first release. |
| Windows Pro workstation | Omarchy plus tested business workflows | Windows-only software, peripherals, and contractual requirements need their own migration decisions. |
| Defender / EDR / DLP / SIEM | Integrations and evidence export | OMA-ID is not initially an EDR, antivirus, DLP, or SIEM implementation. |
| Office, email, files, collaboration | Separate migration workstream | IAM and endpoint management do not replace these applications. |

**Observed:** Microsoft documents Entra as an access service for resources including Microsoft 365 and Azure. Consequently, retaining Microsoft-hosted workloads can leave identity dependencies that an Omarchy rollout alone does not remove. Inventory and resolve those dependencies before declaring Entra retired. [S34]

No production dependency on Microsoft is permitted for OMA-ID's own directory, enrollment, login, management, recovery, signing, or backups. Temporary migration connectors are allowed and must be removable.

### 1.3 Explicit non-goals for the first production release

Do not build an Active Directory domain controller, LDAP server, Kerberos KDC, MDM for phones, Windows/macOS agent, antivirus engine, remote-desktop codec, or general-purpose workflow language. Do not promise hardware anti-theft re-enrollment, universal Secure Boot compatibility, instantaneous revocation of disconnected machines, or automatic conversion of all SaaS applications to OMA-ID.

SAML-only applications, SCIM provisioning, shared labs, and higher-assurance attestation can be later workstreams, but they become **migration blockers** when an application or organizational requirement actually depends on them.

## 2. Verified upstream starting points

### 2.1 Omarchy integration locations

**Observed:** The earlier `basecamp/omarchy` address redirects to `omacom/omarchy`. The ISO installer is in `omacom/omarchy-iso`; its reviewed `quattro` branch documents unattended `cidata` inputs, a configurator, and an installed-system setup flow. Treat this as a development starting point, not proof that any particular downloaded ISO contains every reviewed change. [S01, S02]

| Reviewed location | Relevance to the proposed work |
|---|---|
| `omacom/omarchy-iso: configs/airootfs/root/configurator` | Interactive installation questions; shares account/setup form behavior with first boot. [S03] |
| `omacom/omarchy-iso: configs/airootfs/root/.automated_script.sh` | Live entry point, logging, autoinstall detection, and orchestrator arguments. [S04] |
| `omacom/omarchy-iso: configs/airootfs/usr/local/bin/omarchy-iso-install` | Orchestrator launcher; trace its implementation before modifying installation phases. [S35] |
| `omacom/omarchy: install/provisioning/setup-form.sh` | Shared prompts/validation used by installation and deferred owner setup. [S05] |
| `omacom/omarchy: bin/omarchy-provision-owner` | Deferred first-boot owner provisioning; extend rather than duplicate where practical. [S07] |
| `omacom/omarchy: install/login/sddm.sh` | Login/keyring configuration interaction; ISO owns autologin state in reviewed source. [S06] |

**Observed:** The reviewed shared form describes its password as serving the local user, root, and disk encryption. The reviewed SDDM script also removes password-based GNOME keyring hooks for Omarchy's default behavior. Managed mode must deliberately revisit these defaults rather than assume changing the identity provider is sufficient. [S05, S06]

**Observed:** Omarchy documents deferred setup for another owner and unattended installs. Its installation guide currently instructs users to disable Secure Boot and/or TPM. This is an upstream installation constraint to investigate, not OMA-ID's desired enterprise-security policy, and not a reason to characterize TPM or Secure Boot as Windows-only technologies. [S08]

**Required discovery output:** Pin the actual ISO checksum, source commits, package manifests, and hardware/firmware configuration used in tests. Source branches, documentation, and released media can differ. Re-read contribution rules and repository-local agent instructions at implementation time.

### 2.2 OMA-ID owns the narrow Omarchy login boundary

The project owner decided on 2026-09-05 that authd will not be a production runtime dependency. OMA-ID targets Omarchy specifically and will provision real local Unix accounts, use a native Rust agent for credential and authorization decisions, and connect PAM consumers through a thin local client. See `docs/adr/0004-owned-omarchy-login-stack.md`.

Initial browser/device authorization belongs in enrollment or a dedicated pre-login UI. Do not attempt to make the Quickshell password prompt conduct OIDC or display enrollment instructions.

PAM authentication and PAM account authorization are distinct. A valid local credential must not override an expired, stale, revoked, wrong-device, or wrong-person authorization lease.

NSS is out of the initial scope because users are provisioned locally before login. UID/GID allocation, account creation, homes, groups and retirement are still security-critical and require durable server mappings plus idempotent, collision-checked local operations.

## 3. Product releases and non-negotiable gates

| Release | User-visible result | What must not be claimed |
|---|---|---|
| `0.1 Lab` | Rails identity prototype, OMA-ID lease/agent prototype, reproducible Omarchy PAM/login experiments | No production fleet readiness. |
| `0.2 Managed pilot` | Device enrollment, inventory, audit, signed policy, safe recovery; may temporarily use clearly labeled local accounts | Local accounts are not cloud desktop login or complete identity lifecycle enforcement. |
| `1.0 Managed workstation` | Work/school installation, native organizational login, bounded offline policy, supported updates, recovery, deprovisioning | No complete Intune/RMM/EDR parity or support for every business app. |
| `1.x Expansion` | Selected SAML/SCIM integrations, richer support, shared-device profiles, stronger hardware trust | Each capability ships only with its own acceptance evidence. |

**Gate A - Login:** Actual Rails-issued identity works through the selected Omarchy login stack, including SDDM, unlock, sudo policy, and recovery.

**Gate B - Enrollment:** A clean ISO can produce an enrolled machine without shared secrets, permanent bootstrap administrators, or unnoticed unmanaged fallback.

**Gate C - Enforcement:** Disablement, policy expiry, permission changes, and online/offline behavior have measured and documented effects across all supported access paths.

**Gate D - Operations:** Failed updates, lost credentials, server outages, signing-key rotation, and backup restoration are rehearsed.

**Gate E - Migration:** Every required application, hardware workflow, and RMM capability has a working replacement or an explicit approved exception. Microsoft services are retired only after this gate.

## 4. Architecture decisions

### ADR-001: Rails is the authoritative control plane

Use a modular monolith: Rails, PostgreSQL, server-rendered administration with Phlex views and RubyUI (`ruby_ui`) components, Hotwire where useful, and background jobs. The project owner selected Ruby 4, Phlex, and RubyUI for the Rails application. Initial candidates are Rails 8.1 and Ruby 4.0.6; the local Ruby runtime is pinned in `mise.toml`. Verify the complete Rails/OIDC/UI dependency combination during P0 rather than assuming compatibility. Rails publishes a maintenance policy that must inform upgrades. [S21]

Use local mise-managed Ruby for initial Rails development and protocol experiments with fake identities, ephemeral keys, and development-only data. Run Rails locally; use Docker Compose for the development PostgreSQL service with a persistent named volume and localhost-only port binding. The initial database image is `postgres:18.6-bookworm`; this is a development dependency, not a containerized Rails requirement. Use `phlex-rails` for Rails integration, and verify RubyUI's asset requirements against the selected release. Keep authorization in application services/controllers, not only component visibility. Authentication and approval pages must use locally served assets and accessible keyboard interactions. Production deployment remains independently self-hostable as described in ADR-007.

Use Active Job with a PostgreSQL-backed queue initially; isolate login-critical database capacity from fleet ingestion and slow job processing. Add Redis or additional services only after a concrete requirement. A device heartbeat must not require Action Cable or a permanently open WebSocket.

Organize internal domains as Identity, Authorization, Devices, Enrollment, Policies, Operations, Audit, and Integrations. Keep clear interfaces, but do not begin with eight network microservices.

### ADR-002: Reuse identity protocols and implementations

Evaluate Doorkeeper with `doorkeeper-openid_connect` for OAuth/OIDC, and `webauthn-ruby` for passkey verification. Doorkeeper's device-grant extension is a separate dependency: the reviewed implementation is `exop-group/doorkeeper-device_authorization_grant`, not a guaranteed built-in feature. Compatibility, maintenance, security properties, and combined OIDC/device-flow behavior need tests before selection. [S17, S18, S19, S20]

Do not substitute a mandatory Keycloak instance for the Rails IAM product. A temporary reference IdP or authd build is useful only as comparative test evidence and is not a runtime requirement.

### ADR-003: Native Rust endpoint, not a Rails process in PAM

Use Rust for the endpoint agent, lease verifier, local IPC service and thin PAM integration. The agent owns OMA-ID-specific login behavior but must reuse reviewed libraries for cryptography, password hashing, serialization and PAM bindings. It must not copy authd implementation code or recreate a general identity-broker framework.

The network-facing agent runs without general root privileges. A separate local helper performs a fixed set of approved operations over authenticated local IPC. The helper independently validates signed authorizations, device scope, expiry, operation type, and inputs. It does not accept arbitrary shell text from the network agent.

### ADR-004: One organization per deployment first; explicit ownership everywhere

Start with an explicit `Organization` even in single-organization mode. Organization-owned records carry an immutable organization ID; cross-organization associations must be prevented with constraints, not just UI filters.

Use one stable OIDC issuer per initial deployment to avoid pretending a global gem configuration already supports tenant-specific issuers. Do not make display-name or organization-slug changes alter the issuer or subject IDs. A future hosted multitenant release must choose and test its realm/issuer model explicitly.

For shared hosting, add composite ownership constraints and PostgreSQL row-level security as defense in depth, with separate migration/runtime roles and transaction-local tenant context. PostgreSQL documents ownership/bypass exceptions; RLS must not be represented as automatic isolation. Test connection-pool reuse and background jobs. [S26]

### ADR-005: Declarative policies before arbitrary remote scripts

Represent desired configuration as typed, versioned data. The agent reconciles supported resources and reports observed results. Do not implement a remotely supplied script language as the main management protocol.

### ADR-006: Keep the upstream change small and provider-neutral

Propose a generic work/school provisioning interface with OMA-ID as the reference implementation. Do not hardcode a public OMA-ID SaaS URL, force an account, add telemetry to personal installs, or replace Omarchy's desktop environment.

An upstream merge is not a product dependency. A signed enterprise add-on/profile and a small, documented ISO patch set must support the pilot if maintainers decline or change the proposed interface.

### ADR-007: Self-hosting and portability are first-class

The server must run with ordinary Linux/container infrastructure, PostgreSQL, a compatible object store, SMTP when needed, and an established certificate authority. Prefer a small Docker Compose/Kamal-style deployment over a Kubernetes requirement. No paid cloud service is mandatory; managed database, KMS, and storage adapters may be optional deployments.

## 5. Identity and application-access design

### 5.1 People, credentials, and lifecycle

Separate a person's immutable directory identity from email, login aliases, role assignments, POSIX name, and application subject identifiers. Email changes must not create a new person or transfer an old person's access. Never merge identities solely because two providers return the same email.

Support invitations, activation, suspension, scheduled departure, credential recovery, and eventual deletion according to an organizational retention policy. Preserve sufficient tombstones to avoid accidentally reusing a former person's stable identifiers or POSIX ownership.

Use passkeys/WebAuthn as the preferred web authentication method. Require strong MFA for administrators, enrollment approval, recovery-key retrieval, policy publishing, and support operations. Register multiple recovery methods during onboarding; an email-only reset must not silently bypass administrator MFA. Browser passkeys do not automatically provide disk unlock or offline Linux login.

Password fallback, where required, must use a maintained credential library, rate limiting, credential-breach defenses, and tested recovery behavior. Never distribute the IAM server's password verifier to endpoints. Do not assume a platform authentication generator already provides enterprise MFA or safe account recovery.

### 5.2 Minimum roles

| Role | Permitted responsibilities | Important exclusions |
|---|---|---|
| Organization owner | Organization settings and delegation | High-risk actions still require step-up and audit. |
| Identity administrator | People, groups, app assignments | No automatic remote-root or escrow access. |
| Device administrator | Enrollment, device assignment, approved policy | Cannot create organization owners by assigning a device group. |
| Help desk | Scoped diagnostics, approved recovery workflow | No unrestricted scripts, covert desktop access, or bulk secret export. |
| Security auditor | Read security events and evidence | No mutation or secret disclosure. |
| Employee/student | Own profile, authorized applications, permitted device enrollment | No fleet visibility or default local administrative privileges. |

Authorization must evaluate the actor, organization, action, resource, assignment scope, and relevant policy. Server administrators and tenant administrators are different trust roles. Sensitive support access across tenants must be explicit, time-limited, and visible.

### 5.3 OIDC/OAuth contract

Implement and test discovery, authorization, token issuance, JWKS, UserInfo, revocation, and the chosen logout behavior. Prefer Authorization Code with PKCE for browser/native application sign-in. Disable the implicit flow and resource-owner-password grant. Apply exact redirect validation, issuer/audience checking, narrow scopes, refresh-token replay controls, and appropriate client authentication, following the OAuth security BCP. [S22, S24]

Register separate clients for application SSO, endpoint enrollment, and device service access. A public client ID is not a secret. A successful enrollment flow must not grant an agent the user's general application tokens.

Use short-lived access tokens and rotated refresh-token families. Store bearer-token material as securely as the protocol implementation allows; do not promise hashing where a component actually needs recoverable content. Revoke refresh families on disablement and credential-risk events. Do not put device enrollment secrets, passwords, recovery material, or the entire directory in token claims.

Use asymmetric ID-token signing, explicit algorithms, `kid`, and an overlap window for key rotation. Keep OIDC signing, device CA, policy signing, software release signing, and recovery wrapping keys separate. Applications must receive only the group/role claims they need.

Proposed starting defaults: five-minute application access tokens; application-specific browser session limits; ten-minute enrollment verification transactions. Final values depend on usability and threat-model tests. An existing application session may outlive an IdP session; document each application's logout and disablement semantics rather than promising global instant logout.

### 5.4 Device Authorization Grant is not device management

Use RFC 8628 for the installer or pre-login flow when the user authenticates in another browser. Implement user-code expiry, polling intervals, slowdown behavior, rate limits, and a confirmation screen that identifies the organization and requesting machine. [S23]

The OAuth result authenticates/authorizes a user interaction. It does not by itself establish device ownership, device-key possession, administrator approval, or compliance. The enrollment transaction must add those checks separately.

**Critical interoperability test:** The chosen Doorkeeper extensions must together return the ID token, refresh behavior, discovery metadata, and claims defined by the versioned OMA-ID enrollment and agent contract. Do not assume adding both gems makes the combined flow work.

### 5.5 Provisioning and access reviews

Initially support controlled CSV/API imports with preview, validation, duplicate detection, and an auditable mapping to immutable identities. Later implement SCIM provisioning for selected applications, distinguishing OMA-ID's outbound provisioning role from an optional inbound SCIM directory interface. SCIM is a separate protocol, not simply an OIDC claim sync. [S33]

SAML support is conditional on real application requirements and a maintained, reviewed implementation. Do not build an XML-signature implementation in the project. Keep application connector credentials separately scoped and encrypted.

## 6. The installer experience

### 6.1 Proposed interactive journey

The first meaningful ownership choice is:

> How will this computer be used?  
> **Personal use** - standard Omarchy setup.  
> **School / work** - connect this computer to an organization.

Personal use remains the default. Apart from the ownership choice, it must retain normal installation behavior without contacting a management server or enabling enterprise services.

For work/school use, connect to a network, identify the OMA-ID server, authenticate/approve enrollment, review management scope, and validate the installation profile before destructive disk operations. Reserve the enrollment during installation; activate management only after first boot proves the installed machine's key and baseline.

### 6.2 Fields and where they come from

| Field or interaction | Required? | Rules |
|---|---|---|
| Organization server URL | Yes | HTTPS; display the exact origin. Example only: `https://id.example.org`. No HTTP fallback. |
| Organizational sign-in | Yes, or technician preauthorization | Browser/device-code flow; do not collect an IAM password in the ISO. |
| Organization confirmation | Yes | Display verified server identity, organization name, support contact, and management scope. A logo alone proves nothing. |
| Enrollment invitation | Conditional | Short-lived, limited-use authorization supplied by IT; not a permanent shared secret. |
| Device name | Usually | Suggest a policy-compliant value; validate length, encoding, and uniqueness rules. |
| Ownership/profile | Server-authorized | Assigned workstation, shared workstation, or future lab profile; users cannot self-assign a privileged profile. |
| Assigned person | Usually derived | From the authenticated directory identity or an approved technician workflow. |
| Department/site | Optional or derived | Directory attributes or an authorized administrative choice, not a trust signal from arbitrary user input. |
| Disk-unlock secret | Required for baseline encrypted profile | Enter locally; do not send the user's passphrase to the server. |
| Local recovery provisioning | Required, automatic workflow | Unique per device, escrowed through a separately controlled process. |
| Proxy/private CA | Advanced | Explicit configuration with out-of-band trust validation; never a skip-certificate-check checkbox. |

Do not ask users to enter an OIDC client secret, application signing key, CA private key, raw PAM configuration, or package-install script. Client IDs and permitted enrollment methods come from trusted local adapter configuration and validated server metadata.

### 6.3 Three enrollment modes

**Self-service assigned workstation:** A permitted user authenticates, confirms the device details in their trusted browser, and enrolls within limits set by the organization. Group membership and enrollment policy, not just a matching email domain, authorize enrollment.

**Technician pre-provisioning:** IT authorizes a particular installation or short-lived batch, installs the baseline, and leaves final person assignment/authentication to first boot. Technician credentials must not become the employee's credentials or remain on the machine.

**Unattended fleet imaging:** Extend the existing `cidata` path with a versioned organization profile and narrowly scoped enrollment capability. Generic images contain no device private keys or reusable production credentials. A signed manifest without a secret can select policy, but does not automatically prove ownership or authorize enrollment.

### 6.4 Offline and error behavior

The baseline work/school flow requires connectivity for approval and activation. Offline imaging may finish into a clearly marked **awaiting organization activation** state, with no ordinary managed user session. It must not silently fall back to personal mode or an unrestricted local administrator.

Before disk changes, a user may cancel and explicitly select personal installation. After a managed installation starts, failure remains visible and resumable. Server unavailability, rejected approval, expired invitation, untrusted certificate, unsupported login profile, or failed escrow must never be reported as a successful enterprise setup.

Enrollment expiry during a long install does not justify a permanent token: resume a key-bound reservation or require renewed approval at first boot. Keep retry state durable, bounded, and free of reusable human credentials.

## 7. Enrollment protocol and device lifecycle

### 7.1 Trust establishment

The machine generates a unique key pair locally. Prefer hardware-backed, non-exportable storage when the selected hardware and software path are actually tested; otherwise use root-restricted storage protected by disk encryption, and report the lower assurance level accurately.

The installer authenticates the HTTPS server using the selected trust store. Initial trust comes from the correctly supplied organizational origin or an independently delivered enrollment profile, not from metadata signing itself with a key found in that same untrusted metadata. Private PKI onboarding requires an independently verified trust anchor.

A management server may supply validated configuration data. It must not direct the installer to execute arbitrary remote code or install packages from an arbitrary new trust root.

### 7.2 Enrollment sequence

1. Create a pending transaction with organization, enrollment mode, fresh nonce, device public key, supported protocol version, and minimally necessary device details.
2. Complete user authentication/approval in a trusted browser. Show the device name, organization, requested ownership mode, and a transaction identifier that can be compared with the installer.
3. Check enrollment permission, group/profile eligibility, invitation limits, hardware restrictions where applicable, and administrative approval requirements.
4. Bind approval to the transaction, device public key, organization, assigned identity, and profile version. Prove possession of the private key using a reviewed cryptographic library and a fresh server challenge.
5. Reserve installation. A pending reservation has no application access and cannot retrieve arbitrary organization secrets or fleet data.
6. Install the trusted packages and stage only the minimal key-bound activation state into the target filesystem, never into a reusable image baseline.
7. At first boot, prove the installed machine's identity, obtain device credentials, apply the baseline, establish recovery, and test local login.
8. Activate only after the server receives baseline evidence, escrow receipts where required, and a successful enrollment completion acknowledgment. Delete temporary capabilities and sensitive staging files.

Treat OAuth approval, device-key proof, policy acceptance, escrow completion, and activation as separate recorded events. Retries must not create duplicate devices or consume a one-time approval twice.

### 7.3 States

| State | Meaning and permissions |
|---|---|
| `pending` | Request exists; no organizational access. |
| `approved` | Person/profile authorized; installation reserved. |
| `enrolling` | Key-bound bootstrap may fetch only required configuration and submit activation evidence. |
| `active` | Management enabled; application and login access still depend on identity and policy. |
| `quarantined` | Normal organizational resource access blocked; narrowly permitted management/remediation may continue. |
| `retiring` | Deprovisioning requested; completion may depend on device connectivity. |
| `retired` | Enrollment ended; re-enrollment requires a new lifecycle/generation. |
| `revoked` | Credentials invalidated after compromise or a security decision; do not assume further remote commands can be delivered. |
| `failed` | Enrollment stopped with a recoverable or terminal reason; never equivalent to active. |

Connectivity, compliance, credential validity, and lifecycle state are separate dimensions. An offline machine is not necessarily compliant, retired, or compromised.

### 7.4 Device credentials

Use a dedicated device authentication channel, preferably mTLS with an established CA such as self-hosted `step-ca`, behind a narrow issuance adapter. Keep the CA root offline where operationally practical and constrain the online issuer. [S30]

A proposed starting device-certificate lifetime is seven days, renewed well before expiry. Application/device authorization must also consult current device status; certificate validity alone is not sufficient. Expired credentials require a restricted, reviewed recovery flow and proof of the existing key plus any required fresh approval, not a fleet-wide bootstrap password.

At a reverse proxy, validate client certificates and strip any user-supplied identity-forwarding headers. Rails must be reachable only through that trusted identity boundary for certificate-authenticated routes. Never accept a device ID from an unauthenticated header as evidence of enrollment.

Hardware serial numbers and MAC addresses are inventory hints, not cryptographic identity. Reinstall, motherboard replacement, cloned images, restored backups, and reassignments need explicit lifecycle rules and collision handling.

## 8. Native Linux login: prove it before promising it

### 8.1 Selected path

Package `oma-id-agent` and a thin `pam_oma_id` client for the selected Arch/Omarchy environment. Provision assigned identities as local Unix accounts before login; do not add NSS in the initial implementation. Prefer signed native Arch packages and preserve a transactional upgrade and recovery path.

Keep Rails as the issuer. Enrollment obtains only login-scoped identity data, never management-administrator credentials. Map immutable directory identities to authorized device users, home directories, and POSIX groups through a tested provisioning service.

Never promote the first managed user to owner automatically. Define assigned users, permitted groups, standard-user privileges and denial behavior explicitly. Keep the recovery administrator separate from managed identities.

### 8.2 Required feasibility matrix

| Test surface | Required evidence |
|---|---|
| Packaging | Reproducible build, file paths, systemd units, D-Bus policy, dependencies, licenses, upgrade/uninstall behavior. |
| Enrollment interoperability | Discovery, device flow, token validation, UserInfo, required claims, refresh, logout/revocation cases. |
| Account provisioning | Durable UID/GID mapping, collision checks, idempotency, home ownership, group changes, retirement, service-account exclusions. |
| TTY | First login, subsequent login, enrollment/MFA prompts, failed/expired credentials. |
| SDDM | Fresh user, cached user, cancel/retry, reauthentication, disabled user, missing network. |
| Quickshell lock (selected checkout) | Lock/unlock, suspend/resume, non-root invocation, expired authorization, missing/invalid lock configuration. |
| sudo / polkit / SSH | Authorization path and bypass testing, including SSH-key authentication where supported. |
| Desktop | Home creation, Omarchy user defaults, shell, secret storage/keyring, browser startup, logout. |
| Failure/recovery | Crashed daemon, damaged cache, unavailable IdP, broken PAM update, recovery account. |

Conduct first-time browser/device authorization in enrollment or the pre-session provisioning TUI, then create the assigned local account before ordinary login. Renewed organizational authentication must have an accessible pre-login path too. Do not assume an invisible QR-code prompt is usable.

Replacing SDDM with GDM is not the default solution. The owned PAM module is an accepted architecture decision, but still requires independent review and full consumer/control-flow evidence before release.

### 8.3 Fallback decision

If native authentication is blocked, continue the read-only/managed-device pilot with clearly labeled local accounts and browser SSO. Do not describe that milestone as complete central desktop authentication. Provisioning must reject names or IDs that shadow existing local identities.

Keep the PAM client limited to credential forwarding and authorization requests over authenticated local IPC. Put credential verification, rate limiting and lease decisions in the agent, using reviewed implementations rather than new cryptographic primitives. Independent review and full PAM control-flow tests are release gates.

A wrapper that periodically calls `usermod -L` is not adequate enforcement: it does not prove that public-key SSH, active sessions, lock screens, or other access paths are blocked.

### 8.4 POSIX identity and homes

Maintain a durable mapping from organization plus immutable directory identity to POSIX identity. Do not derive ownership from a mutable email address. Reserve a managed UID/GID range, check collisions, and never recycle IDs while retained data could still refer to them.

OMA-ID must allocate and persist the mapping centrally, then reconcile it locally without recycling IDs while retained data can refer to them. Shared NFS/Samba ownership is a separate gate, not implied by local login success.

Use a safe local username and record display/email aliases separately. Validate home paths, shell selection, group mappings, case normalization, reserved names, and Unicode input. Create homes using the supported session/provisioning path, with explicit permissions and appropriate Omarchy defaults. Reassignment must not grant a new user the previous user's home.

## 9. Offline access, revocation, and session policy

### 9.1 Separate authentication from authorization

A cached credential can establish that the same person unlocked a local credential. It does not establish that the organization still permits access. Define a signed, device-bound **offline authorization lease** separately from locally cached authentication material.

The lease includes the directory identity, device/enrollment generation, authorized operations, relevant policy version, issue/expiry times, and revocation epoch. Only an authenticated successful policy refresh may renew it. A background daemon failure cannot extend it.

Determine where each PAM consumer performs account checks. Screen lockers may exercise different PAM stages from login; enforce the lease at the actual tested path, not merely in an unused account hook. If a consumer omits account management, the authentication request must still obtain an explicit agent authorization decision.

### 9.2 Proposed initial policy

| Situation | Proposed behavior |
|---|---|
| First organizational login | Online authentication and device authorization required. |
| Previously authorized ordinary user, temporarily offline | Permit supported local login/unlock while an unexpired lease remains; initial proposed limit: 24 hours. |
| Shared lab or high-assurance profile | Online login or a shorter explicitly approved lease; no unbounded offline access. |
| Privilege elevation | Disabled by default for normal users; later JIT elevation requires fresh authorization. |
| Explicit authenticated server denial | Deny and invalidate applicable cached authorization; do not reinterpret denial as a network outage. |
| Timeout, DNS failure, or invalid TLS | Do not refresh trust or authorization; only previously valid offline permissions can remain. |
| Lease expiry | Deny new managed login, unlock, and elevation as defined by the tested profile. |
| Existing session | Apply a separately documented idle/expiry policy; warn before routine expiry, then lock or terminate according to profile. |
| Lost server connectivity | Retain a restricted recovery path, not a permanent administrator bypass. |

Network errors must not produce indefinite access. Conversely, an IdP outage should not unexpectedly destroy local work or make all recovery impossible.

### 9.3 Hard limitations to state honestly

A disconnected device cannot receive an immediate new revocation. The offline window is an explicit risk/availability tradeoff. Immediate revocation of a hostile, disconnected machine is not a product promise.

Signed leases prevent undetected modification, not replay of an old but valid state. Protect local high-water marks, detect clock rollback, and use monotonic time where available. Across reboots or snapshot restoration, require online revalidation when freshness cannot be established. Strong anti-rollback under physical/root compromise needs a separately validated hardware trust design.

A user with unrestricted root can disable an agent, modify authentication, or read unprotected local material. The baseline is a managed standard-user device. Developer-root devices must carry a distinct assurance label and cannot be treated as equivalently trustworthy.

## 10. Disk encryption, local privilege, and recovery

Keep four concepts distinct: the OMA-ID web credential, the Linux local/offline credential, the disk-unlock secret, and the break-glass recovery credential. They may have coordinated UX, but must not be one globally synchronized password.

The baseline uses encrypted local storage and disables SDDM autologin for managed users. Root password handling, membership in privileged groups, polkit rules, passwordless sudo helpers, and rootful container sockets must all be audited. Do not grant `wheel` or root-equivalent Docker access merely because the person enrolled the device.

Do not send a user's disk passphrase to Rails. Generate a separate per-device recovery key locally, escrow it encrypted to the recovery service, verify receipt and usability, and then finish activation. Escrow disclosure requires narrowly scoped authorization, step-up authentication, a reason, and an immutable audit event. Bulk recovery-key export is not a default feature.

Use established LUKS/systemd mechanisms for supported recovery or hardware-token integration. The systemd enrollment tooling supports mechanisms such as recovery keys and TPM/FIDO2-backed enrollment, but the exact Omarchy bootloader/initramfs path must be tested before using them here. [S29]

The initial managed baseline may retain manual disk unlock. Do not enable TPM-only auto-unlock while leaving an unverified boot chain. A higher-assurance profile must validate firmware configuration, Secure Boot ownership, signed boot artifacts, measured-boot assumptions, update behavior, and recovery after firmware/boot changes.

Provide a unique, tightly controlled local recovery identity or equivalent tested rescue workflow. Disable its network login by default; never use a shared fleet password. Recovery use must be logged locally and reported on reconnection, followed by credential rotation where appropriate. A centrally escrowed secret cannot be the only recovery method when the control plane itself is unavailable; establish an independently protected organizational recovery procedure.

Audit desktop secret storage explicitly. Do not assume browser tokens, Wi-Fi/VPN secrets, or SSH keys are protected adequately just because the root volume is encrypted, or that cloud authentication automatically unlocks a desktop keyring.

A password reset at the server does not automatically change cached offline credentials, disk-unlock secrets, or application sessions. The UI and runbooks must explain those separate effects.

## 11. Endpoint agent and management protocol

### 11.1 Components and boundaries

| Component | Responsibilities | Privilege boundary |
|---|---|---|
| `oma-id-agent` | Outbound check-in, inventory collection, policy fetch, local queue, status reporting | Dedicated service identity; no general root shell. |
| Privileged helper | Approved system configuration, package operations, supported account/session actions | Root, fixed local API, independently checked authorizations, no public listener. |
| Login authorization adapter | Cache/lease evaluation for the tested login and unlock paths | Minimal surface; no administrative web API or remote command runner. |
| Optional user-session companion | Enrollment notices, update prompts, visible support approval, lock status | User session; never holds organization signing or management-administrator secrets. |

The agent must initiate outbound HTTPS; no open inbound management port is required for normal operation. Separate per-device credentials from all user credentials. Restrict local IPC with peer-identity checks, file/socket permissions, bounded messages, and resource limits. Harden systemd units and filesystem access according to the actual capabilities each component requires.

A single release artifact can contain multiple binaries/services without collapsing their privileges. Avoid making the root helper a large dependency-heavy network daemon.

### 11.2 Check-in and durable delivery

Start with periodic HTTPS polling, jitter, and exponential backoff. A proposed normal check-in is every five minutes, with faster bounded polling during enrollment or an explicitly scheduled operation. Streaming is optional later, not necessary for the first release.

Each check-in carries device/enrollment identity, agent/protocol version, sequence number, reported policy version, health summary, and bounded acknowledgments. Authenticate the transport and authorize every route against device state. Protect against duplicate, delayed, and out-of-order messages.

Use at-least-once delivery with idempotency, not an unsupported exactly-once claim. Each command has an ID, target device/generation, authorized operation, payload hash, issue/expiry times, and execution constraints. Record durable receipt and result state before acknowledging completion. A reboot between execution and acknowledgment must not execute a destructive operation again.

Bound local spool size and retention; an initial target is 50 MiB, adjustable by profile. Drop/coalesce nonessential repetitive telemetry before losing important security events, and report gaps. Never download all artifacts or retain unbounded task output on small workstation disks.

### 11.3 Inventory and privacy

Collect only data needed for management: OS/build, kernel, agent version, installed approved-package inventory, hardware identifiers where justified, disk-encryption status, boot-security evidence level, patch state, service health, storage pressure, and recent successful check-in.

Do not collect keystrokes, personal documents, browser history, messages, webcam content, or continuous screenshots. Diagnostic output needs redaction and size limits. Expose to the user what the organization manages and collects. For schools, define retention, permissions, and applicable child/student privacy requirements before deployment; do not treat employee consent as a universal legal basis.

Report evidence provenance as `reported`, `locally_observed`, or `hardware_attested` only when justified. A signed report from a device key is authenticated reporting, not proof that an administrator-compromised operating system is honest.

### 11.4 Suggested API resources

These are proposed contracts, not implemented endpoints. Final routes must be documented in OpenAPI and tested against agent fixtures.

| Resource | Authentication | Contract requirement |
|---|---|---|
| `GET /.well-known/oma-enrollment` | Public HTTPS metadata | Protocol versions, canonical issuer, enrollment methods, support/organization display information; no secrets or executable content. |
| Enrollment transaction create/status | Rate-limited bootstrap flow | Nonce/key binding, expiry, enumeration protection, approval state. |
| Enrollment completion | One-use approved transaction plus key proof | Atomic transition, credential issuance, replay protection. |
| `POST /api/v1/device/check-ins` | Device identity | Bounded batch, sequence handling, state-aware authorization. |
| Device desired-policy fetch | Device identity | Signed immutable revision, digest, expiry, compatible agent versions. |
| Device action receipt/result | Device identity | Idempotency and correct target/generation; limited output. |
| Device credential renewal | Existing valid identity and current authorization | Rotation overlap, revocation checks, no arbitrary CSR subjects. |
| User login-authorization decision | Dedicated device/login authorization | Person/device/profile binding; no access through an ordinary app token. |
| Recovery operations | Separate privileged human workflow | Step-up, approval, audit, narrowly scoped output. |
| Administrative APIs | Human/service principal with explicit scopes | Same object-level authorization as the UI. |

A device must never enumerate other devices, fetch another organization's policy, or obtain its own privilege escalation by changing a request body. Reject unsupported critical fields/versions, malformed identifiers, path traversal, oversized payloads, and inconsistent organization references.

## 12. Configuration and policy engine

### 12.1 Policy model

Separate **desired state**, **observed state**, **compliance decision**, and **remediation status**. Publishing a policy is not proof that it applied. An unreachable device's old report must age into `unknown` or `stale`, not remain green indefinitely.

Each published policy revision is immutable and contains a schema version, monotonically increasing revision, organization/profile scope, creation/expiry information, supported agent range, payload digest, and signature. Build signed envelopes with established libraries and deterministic serialization; do not design a new cryptographic algorithm.

Use explicit precedence: organization security baseline, profile/group assignments, then approved device exceptions. For supported restrictions, merge by the more restrictive result where the semantics are unambiguous. Conflicting exact values or incompatible configurations must cause publication failure with an explanation, not a surprising last-write-wins result.

An exception has an owner, reason, approval, and expiry. The UI shows the effective result and which rule produced it. Group changes must recalculate policy and authorization; they must not require a reinstallation.

### 12.2 First supported resources

| Resource | Initial capability |
|---|---|
| Login policy | Authorized identities/groups, offline lease limit, session behavior, autologin disabled. |
| Local privilege | Standard-user baseline, explicitly approved groups, validated sudoers/polkit settings. |
| Screen locking | Managed idle/lock configuration and tested actual lock behavior. |
| Software | Approved packages and repository/channel selection; no arbitrary user-supplied package sources. |
| Updates | Ring, maintenance window, deferral limits, reboot notice policy. |
| Firewall/SSH | Explicit inbound policy; SSH disabled unless assigned; no accidental listener enablement. |
| Browser/workplace settings | A narrowly tested set of enterprise settings and approved certificates. |
| Recovery | Escrow required/verified status, controlled recovery workflow. |
| Health | Minimum supported agent/build, disk-space thresholds, required services. |

Network/VPN/Wi-Fi credential delivery is a later typed resource unless essential for initial connectivity. Bootstrap networking must not depend exclusively on credentials that can only be fetched after enrollment. Handle private CA and authenticated proxy environments deliberately.

### 12.3 Safe application

For each supported resource, implement detect, plan, validate, apply, verify, and recover operations. Render managed files into known paths; never concatenate user input into shell commands. Validate configurations with the owning subsystem before activation where possible.

Keep managed configuration separate from personal dotfiles where the application supports it. Security-critical enforcement must not depend only on a user-editable setting. If the chosen compositor or application cannot enforce a requested restriction against the user, report that limitation instead of claiming compliance.

Lock package/configuration operations to avoid racing the user or Omarchy's updater. Write files atomically, retain a known-good configuration, bound retries, and use canary rollout. Authentication/firewall changes require a recovery watchdog and an explicit post-change health check before removing the previous safe path.

## 13. Updates, snapshots, and software supply chain

**Observed:** Arch supports coherent full-system upgrades rather than partial upgrades. Fleet update controls must not turn into arbitrary package pinning against a moving repository. [S27]

Define an update bundle as a coherent repository snapshot/channel selection plus Omarchy runtime/settings, agent, login components, configuration schema, and boot artifacts known to work together. Stage it through lab, canary, pilot, and broad rings. If repository snapshots are used, keep dependency sets consistent and define a maximum permitted staleness; a permanently frozen image is not a patching strategy.

The update coordinator must integrate with the selected Omarchy update mechanism rather than run a second conflicting package manager workflow. Audit all normal user update entry points. Omarchy migrations must neither overwrite managed authentication settings nor restore autologin/privileged defaults unnoticed.

Before risky updates, verify power, available disk space, package signatures, recovery availability, and snapshot/backup prerequisites. Notify the user, respect a bounded deferral policy, record the transaction, and test success after reboot. Distinguish a postponed reboot from a healthy fully applied update.

A Btrfs snapshot is not a complete backup or necessarily a bootable rollback. The bootloader, EFI system partition, kernel/initramfs, authentication cache, and root snapshot must remain compatible. Test the entire boot path and recovery with the actual layout.

Keep device identity, revocation high-water marks, task receipts, and other security state out of ordinary OS rollback where practical, using a deliberately tested persistent layout. This reduces accidental rollback; it does not make state immune to a hostile root user or physical disk restoration. After rollback, revalidate management state before granting normal access.

Sign ISO/add-on releases, packages, and policy bundles with separate responsibilities. Verify an ISO signature against an independently trusted key; a checksum downloaded from the same compromised origin is not authenticity by itself. Maintain a software bill of materials, dependency lock files, provenance, and a vulnerability response process.

Use a maintained update-metadata design with protection against expired, substituted, or rolled-back metadata; TUF is a candidate rather than a reason to invent a custom secure updater. OMA-ID's policy rollback can publish a new authorized revision containing prior settings instead of accepting an old revision number. [S28]

Do not mix an unsigned self-updater with package-managed agent files. Choose one owning update path and test interruptions, revocation of a release, compromised signing credentials, and trust-root rotation.

## 14. RMM scope and support operations

### 14.1 First useful RMM slice

Ship health visibility, alerts, inventory, approved diagnostics, a small remediation catalog, update coordination, service restart where safe, and device/user notifications. Example typed actions include gathering a bounded service status, reporting disk pressure, reconciling a policy, or scheduling a reboot with notice.

Record who requested an operation, which devices were selected, the exact approved action/payload, approval context, expiry, start/result times, and outcome. Batch actions need target previews, canaries, concurrency limits, cancellation, and a maximum blast radius.

### 14.2 Remote assistance

Integrate rather than write remote-display transport. Evaluate a self-hostable option against the **actual Hyprland/Wayland, login-screen, and locked-session behavior**. RustDesk's documentation currently describes experimental Wayland support and login-screen restrictions; it cannot be assumed to supply universal unattended support on Omarchy. [S32]

Default interactive support requires visible user consent, an on-screen indicator, time limits, operator identity, and an easy way to stop the session. Unattended access is a distinct organization-owned-device policy, not a hidden fallback. Prevent credential prompts or private recovery material from being unnecessarily captured.

Remote terminal support is a separately permissioned capability. Never expose a public root shell or give the Rails web process direct host Docker-socket access to implement it.

### 14.3 Arbitrary scripts and destructive actions

A generic script runner is deferred. If justified later, treat it as a high-risk capability with an approved artifact catalog, explicit privilege level, code review, signature/digest, argument schema, expiry, output redaction, resource limits, and organization-scoped authorization. Signing a script from the same compromised control plane is not sufficient protection from control-plane compromise.

Remote wipe is also deferred until a reviewed, hardware-specific procedure exists. Require deliberate authorization and independent approval for destructive fleet operations. An offline device may never receive a wipe request, and deleting files or one LUKS keyslot is not a universal secure-erasure guarantee. Account for other keyslots, backups, snapshots, storage behavior, and keys already in memory. Do not ship destructive example commands in the initial agent.

### 14.4 Avoid rebuilding security products

Optionally integrate osquery for inventory/diagnostics; it has a documented remote-management protocol, so an adapter must implement and test that contract rather than treat it as arbitrary SQL over an unauthenticated endpoint. Keep queries scoped and reviewed. [S31]

Provide export/integration points for an organization's existing security tooling. An EDR alert, telemetry collection, policy compliance, and an identity decision are distinct concepts. Do not replace a required security control with a green dashboard tile.

## 15. Conditional access and device trust

Start with auditable rules based on person/group, application, authentication strength, and the proven freshness/assurance of a device signal. Keep device registration, compliance, and authorization separate. The application/token service is the enforcement point; a dashboard warning alone does not restrict access.

A browser on an unmanaged computer must not impersonate a managed device by setting a device-ID header, cookie, user-agent string, or copying an unbound token. Before enabling device-based application access, select a real proof mechanism: for example, a supported browser/client certificate flow through a dedicated gateway, or a reviewed challenge protocol binding the browser transaction to the enrolled device key.

A loopback agent alone is not proof: evaluate origin validation, CSRF, challenge expiry, browser-session binding, replay, and relay from another machine. Separate identity-only access from device-verified access in the product until this is solved. No device compliance claim should be enforced solely from client-submitted JSON.

Devices whose users have unrestricted root, machines without a validated boot chain, and machines with merely reported posture belong to lower-assurance categories. A hardware-attested profile requires fresh challenge verification, hardware/root-of-trust validation, measurement policy, and recovery/update handling; merely detecting a TPM is insufficient.

Do not design a circular dependency where a noncompliant device cannot reach the very enrollment or recovery endpoint needed to fix compliance. Restricted remediation access must be distinct from general application access.

## 16. Data model and Rails boundaries

The following are logical entities, not a demand to create every table in the first commit. Use database constraints, indexes, explicit lifecycle transitions, and transaction boundaries. Avoid callback chains that silently issue credentials or publish fleet commands.

| Domain | Initial entities | Key invariants |
|---|---|---|
| Organization | Organization, OrganizationSetting | Stable ID; deployment/issuer settings controlled and audited. |
| Directory | Person, LoginAlias, Group, GroupMembership | Immutable person identity; aliases unique in their realm; no email-based account merging. |
| Human authentication | Credential, WebAuthnCredential, Session, RecoveryMethod | Protected credential material; device enrollment credentials stored separately. |
| Authorization | Role, RoleAssignment, ApplicationAssignment | Explicit resource/org scope; no user-editable administrative role claims. |
| OAuth/OIDC | Application, Grant, TokenFamily, SigningKeyReference | Use the selected library's schema/contracts; issuer/client/person ownership enforced. |
| Enrollment | EnrollmentRequest, Invitation, Approval | Expiry, limited uses, key binding, atomic consumption. |
| Devices | Device, DeviceCredential, DeviceAssignment, PosixIdentityMapping | Generation-aware identity; uniqueness; no reuse of retired ownership accidentally. |
| Policy | Profile, PolicyRevision, PolicyAssignment, PolicyException | Immutable published content; signed digest; explicit precedence and exception expiry. |
| Compliance | DeviceFactBatch, ComplianceEvaluation | Observation time, receipt time, evidence source, policy version, freshness. |
| Operations | DeviceAction, ActionAttempt, ActionResult | Idempotency, scoped targets, bounded output, explicit approval and expiry. |
| Recovery | RecoveryArtifact, RecoveryAccessRequest | Encrypted payload/reference; separate access control; disclosure auditing. |
| Audit/integrations | AuditEvent, OutboxEvent, Connector, WebhookDelivery | Transactional recording, retry safety, secret references, tenant ownership. |

Use a transactional outbox for important side effects such as policy publication, user disablement propagation, or approved action issuance. A failed job must not lose a committed security decision. Retries must not create additional certificates, repeat a destructive action, or consume an invitation again.

Every API, worker, export, attachment, and search must apply the same authorization rules. In a future hosted service, tenant isolation tests must include OAuth applications/tokens and signed payload generation, not just ordinary Active Record models.

Audit events should include actor, authenticated principal, organization, action, target, result, correlation ID, and relevant before/after metadata with secrets redacted. Export security events to separately controlled append-oriented storage. Hash chaining inside the same editable database alone is not an independent tamper-proof audit trail.

## 17. Server deployment, reliability, and capacity

### 17.1 Deployment baseline

Provide a self-hosting package with a reverse proxy, Rails web process, separate workers, PostgreSQL, object storage adapter, and the chosen certificate/signing integrations. Keep public login/enrollment endpoints accessible without exposing database, worker, CA administration, or recovery administration interfaces.

Do not put production signing roots in the repository, baked container image, or an ordinary downloadable Rails configuration export. Use purpose-separated key references and an appropriate secret store. A small self-hosted deployment must still document how to back up and recover keys independently.

Maintain TLS, DNS, time synchronization, database, queue, storage, and external mail dependencies in the operations checklist. SMTP failure must not make every emergency administrator recovery path unusable. No third-party analytics or scripts on authentication/enrollment approval pages by default.

### 17.2 Availability and observability

Separate login/token request capacity from inventory ingestion, file downloads, large exports, and bulk jobs. Use bounded request sizes, database retention, indexed lookups, per-device/organization limits, and queue isolation. Do not run fleet operations synchronously in a web request.

Measure authentication latency, token errors, enrollment completion/failure, policy age, offline device count, credential expiry, failed renewals, action backlog, update failure, recovery use, and audit export lag. Logs must not include authorization codes, bearer tokens, passwords, disk secrets, or sensitive support output.

Proposed engineering objectives, to validate rather than advertise: a pilot of 10-25 devices; a load-test scenario of 1,000 devices polling every five minutes; bounded behavior during synchronized reconnects. The steady-state heartbeat rate in that scenario is approximately 3.3 requests/second, but bursts, token issuance, inventory size, and database work determine actual sizing. No production hardware sizing is assumed from this arithmetic.

For production, define organization-approved availability, recovery-point, and recovery-time objectives, then rehearse them. Back up the database, object data, CA/signing configuration, and required recovery material with appropriately separate access. Prove a restoration into a clean environment without silently changing issuer identity or losing device trust.

### 17.3 Outage policy

A Rails outage must not erase local credentials or discard known-good policy. Endpoints follow their existing bounded offline permissions. New enrollments, high-risk approvals, and permissions that require a fresh server decision pause or fail closed.

When service returns, spread retries with jitter, refresh revocation state before normal access, and reject stale duplicated commands. Queued high-risk actions must expire rather than execute unexpectedly days after their original context has changed.

## 18. Security review and abuse-resistant administration

Threat-model at least: stolen laptop; stolen invitation; malicious network; compromised standard user; administrator misuse; hostile local root; compromised Rails process; cross-organization access; stolen device key; signing-key compromise; malicious package; rollback/replay; and a support operator selecting the wrong device.

| Threat | Required mitigation or honest boundary |
|---|---|
| Stolen enrollment capability | Short expiry, constrained scope/use count, key/transaction binding, approval evidence, revocation. |
| Compromised enrolled device | Device-scoped credentials; no fleet/list/issuer keys; narrow APIs; quarantine/revocation. |
| Cross-organization bug | Constraints, object authorization, isolation tests; RLS where applicable. |
| Malicious URL/configuration | Strict validation; controlled redirects; no arbitrary shell/package URLs; SSRF/egress controls for server-side fetches. |
| Stolen administrator session | Step-up, scoped roles, session revocation, sensitive-action confirmation, independent approval for highest-risk actions. |
| Compromised control plane | Separate key purposes and privileges; bounded action catalog, canaries, external audit, independent approval/trust for high-risk releases. |
| Replay/rollback | Signed/versioned envelopes, expiry, idempotency, target generation, protected freshness state where possible. |
| Lost server or authenticator | Rehearsed local and organizational recovery; multiple protected authenticators; no universal secret. |
| Physical/root compromise | Lower assurance or supported attestation controls; never promise an ordinary agent is unremovable. |

Review web security as an IAM product: secure cookies, CSRF, session fixation, account enumeration, authorization checks, redirect validation, phishing-resistant administrative authentication, file upload/export isolation, and webhook signing. Device-code phishing requires explicit transaction confirmation and understandable origin/device information.

A Rails application compromise may still abuse any authority its service credentials legitimately hold. A separate signer that blindly signs every Rails request does not eliminate that risk. Highest-impact operations require an independently enforced approval or release boundary, not merely another process name.

Commission independent review of OAuth/OIDC composition, enrollment/key lifecycle, PAM integration, offline-policy enforcement, recovery escrow, and the privileged helper before broad production use. Track findings and remediation evidence; do not use self-issued "enterprise secure" labels as a substitute.

## 19. Upstream contribution strategy

### 19.1 Start with an RFC, not a giant PR

Prepare an issue/discussion proposing an optional managed-device provisioning interface. Include the user journey, exact behavior of personal mode, trust model, package-size/network implications, cancellation/failure behavior, and maintenance commitment. Confirm the preferred repository and branch with maintainers.

Proposed title:

> Optional work/school setup with a provider-neutral managed-enrollment handoff

Proposed scope statement:

> Add an opt-in ownership choice to installation and deferred first boot. Personal installations retain their current behavior. Managed installations use a versioned, validated profile and a trusted enrollment adapter; OMA-ID provides the first implementation. No hosted account, enterprise agent, or management-server connection is required for personal use.

Do not promise upstream acceptance, use Omarchy branding in a way that implies endorsement, or submit an unfinished authentication/security stack as a cosmetic menu change.

### 19.2 Proposed PR sequence

| Change | Likely repository | Acceptance focus |
|---|---|---|
| RFC and schema proposal | Maintainer-selected discussion/issue | Agreement on ownership and extension surface. |
| Versioned managed-profile contract and fixtures | `omarchy-iso`, with shared runtime interface as needed | Validation, backwards compatibility, no execution of server-provided code. |
| Personal/work choice and `cidata` support | `omarchy-iso` | Normal personal path unaffected; clear managed errors/cancellation. |
| Deferred organization setup hook | `omarchy` | Shared form reuse, first-boot resume, safe baseline, no personal-mode regression. |
| Optional trusted adapter/package integration | Relevant package/ISO repository, after discovery | Packaging, signatures, offline behavior, explicit selection. |
| Documentation and VM acceptance tests | Both repositories as appropriate | Reproducible end-to-end evidence and supported limitations. |

The UI belongs principally in the ISO repository, with shared/first-boot behavior in the runtime repository. Do not assume one PR to `omarchy` alone reaches the ISO. Reconfirm the repository layout at implementation time.

The first PR should not include an entire Rails server, remote shell, unreviewed PAM replacement, or permanent changes to every personal install. Keep OMA-ID's agent/server code in its own project.

### 19.3 Specific integration rules

Pass a versioned managed-install profile through a defined orchestrator interface instead of hiding it in arbitrary environment variables or mixing it into every personal credential field. Reuse shared validation where possible, but keep human passwords out of logged configuration.

Ensure secrets never appear in the live install log, debug output, terminal history, process arguments, downloadable support bundles, or a reusable `cidata` image. The reviewed autoinstall documentation notes plaintext disk-passphrase handling in its configuration; managed automation needs an explicit safe handling strategy rather than reusing that artifact indiscriminately. [S02]

Do not copy activated device keys into factory-reset baselines. Add explicit behavior for Omarchy factory reset/reassignment: retire or invalidate the old enrollment, remove old person data under policy, and require new authorization. Generic hardware without a protected external ownership anchor cannot be forced to re-enroll after an arbitrary personal reinstallation; document that limitation.

Publish the RFC/PR drafts and test evidence only when the project owner authorizes submission. This plan does not authorize Codex to post to upstream automatically.

## 20. Test strategy and release acceptance

### 20.1 Test layers

Use Rails unit/request/system tests, protocol interoperability tests, Rust unit/property/fuzz tests for untrusted inputs, package installation tests, and real VM installation/login tests. Test the production privilege split, not a development agent that runs everything as root.

Run the OpenID Foundation conformance suite for the chosen provider profile and independent relying-party tests. Passing internal integration tests is not the same as obtaining formal OpenID certification; record exactly what was run and passed. [S25]

Use the Omarchy ISO's existing unit/VM harness where feasible, with managed-mode cases added. Test both a pinned supported release and an update candidate. Add a small physical-hardware matrix for networking, graphics, suspend/resume, firmware, disk unlock, and security keys; a passing QEMU VM does not certify real hardware.

### 20.2 End-to-end acceptance scenarios

| ID | Scenario | Required result |
|---|---|---|
| E01 | Clean personal installation | No OMA-ID network traffic, enrollment state, enterprise services, or changed personal security defaults. |
| E02 | Clean work installation | Server shown correctly; authorized person/device enrolled; baseline verified; managed login succeeds. |
| E03 | Unauthorized person / wrong organization | Enrollment rejected without disclosure or partial administrative access. |
| E04 | Stolen/reused/expired invitation | Replay rejected; concurrent attempts do not exceed allowed use count. |
| E05 | Wrong device key / copied approval | Completion denied, including after a reboot or interrupted install. |
| E06 | Invalid TLS / malicious redirects | No certificate bypass, secret leakage, or arbitrary code execution. |
| E07 | Install or first boot loses power/network | Safe, bounded resumption; no activation until checks complete. |
| E08 | Human login through SDDM | Correct identity, home ownership, groups, session defaults, and no autologin bypass. |
| E09 | Screen lock, suspend/resume, reauthentication | Actual lock verified; authorized unlock works; denial and lease expiry are enforced. |
| E10 | Offline authorized user | Access only within configured lease; no renewal from timeout/error or clock rollback. |
| E11 | User disabled online | Tokens, refresh families, login/elevation, and configured existing-session handling behave as documented. |
| E12 | User disabled while device offline | Residual access bounded by the approved offline policy, with its hardware/root assumptions documented. |
| E13 | SSH key and alternate PAM paths | No bypass of account policy on a supposedly denied identity. |
| E14 | Group/role removal | Application and local privileges converge; stale sessions/credentials handled explicitly. |
| E15 | Broken PAM/policy update | Automatic safe fallback or tested rescue; no fleet-wide unrecoverable lockout. |
| E16 | Package/update failure, full disk, reboot interruption | Durable state and recoverable boot; no duplicate destructive actions. |
| E17 | Snapshot rollback / image clone | Security-state replay detected or fresh online validation required; clone not silently accepted. |
| E18 | Certificate/signing-key rotation | Compatible overlap; revoked/expired credentials rejected; no permanent bootstrap backdoor. |
| E19 | Recovery-key retrieval/use | Authorization and audit verified; no secrets in logs; recovery actually unlocks the intended device. |
| E20 | Quarantine/retire/reassign/reset | Access and identity state correct; old data not assigned to a new person; offline pending work visible. |
| E21 | Malicious/oversized policy or task payload | Parser/authorization rejection without privilege escalation or resource exhaustion. |
| E22 | Cross-device/cross-organization access attempt | Denied across UI, APIs, workers, tokens, policies, actions, exports, and attachments. |
| E23 | Control-plane restore and reconnect burst | Identity/trust preserved; no mass re-enrollment, expired task replay, or unbounded retry load. |
| E24 | Support session | Consent/visibility, scope, expiry, cancellation, and locked/login-screen limitations match the documentation. |

Test all supported keyboard layouts needed by the pilot, including password/passphrase entry and special characters. Avoid a fleet migration in which an employee can set a secret during install but cannot type it at pre-boot unlock.

### 20.3 Security regression gates

Critical authorization tests must run in CI and block release. Include tenant/device ID substitution, OAuth client confusion, refresh replay, token audience confusion, permission escalation via groups, enrollment race conditions, parser fuzzing, task replay, path/shell injection, and disclosure through diagnostics.

For dangerous operations, test in disposable environments with fake or explicitly designated test devices. No automated test may format the developer's disk, alter the development host's PAM stack, or enroll a real employee machine as a side effect.

## 21. Phased implementation backlog

Work in vertical slices. Each package must deliver its own tests, operational notes, and evidence. The names below are work-package IDs, not calendar estimates.

| Package | Depends on | Deliverable | Exit evidence |
|---|---|---|---|
| P0 - Baseline and risk spikes | None | Pinned versions/commits; threat model; owned lease/agent/PAM spike; actual SDDM/Quickshell experiment; dependency and license matrix | Reproducible VM results and an explicit feasible/blocked decision for each critical path. |
| P1 - Rails identity foundation | P0 baseline | Deployment skeleton, organization, people/groups, administrator bootstrap, passkeys/recovery, scoped authorization, audit | Independent administrator and normal-user workflows; unauthorized actions rejected; recovery drill. |
| P2 - Enrollment and agent interoperability | P1 plus P0 login findings | Discovery, code+PKCE, required device flow, JWKS/UserInfo, token lifecycle, real agent client | Tested Rails issuer -> enrollment -> agent/local identity, with negative protocol cases. |
| P3 - Enrollment and device PKI | P1/P2 contracts | Approval transaction, device-key proof, credential lifecycle, inventory device record | Replay-safe enrollment, wrong-key rejection, rotation and revocation tests. |
| P4 - Read-only native agent | P3 | Privilege-separated services, check-in, inventory, durable bounded queue | Offline/reconnect, clone, malformed-response, isolation, and service-hardening tests. |
| P5 - Managed policy and recovery | P4 | Signed policy, first typed resources, escrow, recovery workflow, safe application | Bad policy cannot cause unrecoverable login/network loss; recovery actually works. |
| P6 - Native login and offline authorization | P2/P5 | POSIX mapping, desktop setup, lease enforcement, denial propagation, session policy | Gate A and E08-E15 pass on VM plus supported hardware. |
| P7 - ISO and first-boot integration | P3/P5/P6 | Personal/work choice, profile handoff, `cidata`, resumable activation, personal regression tests | Gate B; a clean ISO completes enterprise setup without manual root patching. |
| P8 - Updates and operational resilience | P5/P7 | Ring rollout, coherent updates, boot/rollback recovery, signing rotation, server restore | Gate D; failed update and lost-server rehearsals pass. |
| P9 - Bounded RMM and application migration | P4/P5/P8 | Diagnostic/remediation catalog, support adapter, required app connectors, dependency inventory | Required support/business workflows work with documented limitations. |
| P10 - Production hardening and controlled pilot | P6-P9 | Independent review, remediation, observability, runbooks, acceptance report | Gates A-D satisfied; no unaccepted critical/high-severity findings. |
| P11 - Retirement and expansion | P10 | Application-by-application cutover, Microsoft/RMM retirement decision, next-profile backlog | Gate E signed off; rollback retained until migration success is established. |

Some work can proceed in parallel after contracts are agreed, but P7 must not hide unresolved P6 login failures behind a successful-looking installer screen.

### P0 tasks in more detail

**Selected desktop source correction (2026-09-05):** The clean local `../omarchy` checkout matches pinned commit `493067741e081c3b09082da6bfd51e99ec24ef00`. It launches Quickshell via `omarchy-shell lock lock`, with distinct `omarchy-lock-password` and `omarchy-lock-fingerprint` PAM services. Quickshell is therefore the required lock consumer for this baseline; older Hyprlock profiles require separate evidence. WSL and disposable Arch containers can establish build/package evidence, but cannot establish graphical unlock, suspend/resume, encrypted boot, or recovery gates. See `docs/p0/native-baseline.md`.

**Executed P0 evidence:** The latest local Ruby 4/Rails harness passed 40 tests and 269 assertions with zero failures, errors, or skips. It covers durable refresh-family tracking, ancestor replay revocation, wrong-client/family isolation, PostgreSQL lock contention, atomic audit failure recovery, a fresh-process replay probe, JWT algorithm substitution, discovery host tampering, and device scope enforcement. Lab discovery, device-denial, scope, and family adapters remain explicit; raw mode reproduces dependency gaps. See `docs/p0/protocol-experiment.md` and `docs/adr/0003-refresh-family-replay.md`. These are lab results, not production directory/authorization review, a real enrollment client, browser authentication, native login, offline enforcement, or a passed P0 gate.

**Comparative authd evidence:** A disposable Arch container used the pinned authd archive, official Arch image digest, and 2026-09-04 archive repositories. Authctl, the PAM client, NSS, the OIDC broker, broker tests, and generic provider tests passed. The daemon build timed out downloading Go modules; PAM generation stopped because `protoc-gen-go` was not installed. This evidence informed ADR-0004 but authd is no longer a selected runtime dependency. No PAM or NSS files were installed, no host mounts were used, and no login claim follows from these results. See `docs/p0/native-baseline.md`.

Record the real source/package/ISO revisions. Build the pinned OMA-ID agent and PAM test client in isolated Arch. Test its lease and local-account contract first, then connect the minimal Rails issuer and disposable Omarchy consumer paths. Inspect required claims, local mapping, first-login interaction, unlock, and offline behavior. Record exact failures rather than changing unrelated components until something appears to work.

Evaluate the Doorkeeper/device-grant/OIDC combination against the selected Ruby/Rails versions. Verify ID-token issuance in the required flow, refresh lifecycle, PKCE behavior where applicable, and key rotation. Inspect maintained releases and security advisories; do not choose a fork merely because its README says it supports the version.

Decide the minimum supported Omarchy build and packaging path. Audit existing privileges, autologin, keyring, factory-reset, snapshot, and upgrade behavior. Draft the upstream RFC and resolve the baseline design decisions below before building a broad dashboard.

### Decisions that must be recorded, not silently guessed

| Decision | Proposed default | Required evidence or owner |
|---|---|---|
| Native login implementation | Owned Rust agent + thin PAM client + provisioned local users | Owner accepted ADR-0004; P0/P2/P6 integration evidence remains required. |
| Offline-policy enforcement | Signed device-bound lease in the agent | Actual PAM/locker call-path review and independent security review. |
| Installer ownership | Small changes in ISO plus runtime first boot | Maintainer feedback and pinned source layout. |
| Server tenancy | One organization per deployment initially | Product owner; hosted tenancy requires a new isolation gate. |
| Ordinary offline window | 24 hours | Organization risk/availability approval and enforcement tests. |
| Baseline privileges | Standard user; no root-equivalent groups | Supported application/developer workflow review. |
| Disk unlock | Manual encrypted boot initially | Hardware/boot/recovery tests; higher assurance has a separate profile. |
| Remote support | Adapter selected by Wayland tests | Actual consent/login/locked-session evidence. |
| Software licenses | Choose before public distribution | License inventory; preserve upstream obligations and notices. |
| Production fleet scope | Organization-owned assigned workstations | Pilot owner; shared labs and BYOD are separate profiles. |

## 22. Migration and retirement runbook

Begin with an inventory of people, groups, privileged roles, devices, app SSO integrations, provisioning connectors, certificates, recovery keys, scripts, firewall/VPN settings, data locations, security controls, and actual RMM tasks. Define a named owner and success test for each dependency.

Create OMA-ID identities using explicit mappings, not an assumption that passwords or authenticators can be copied from another identity provider. Users enroll new authentication/recovery methods. Preserve external IDs only as migration references. Avoid changing email and identity ownership simultaneously without a tested mapping.

Move a disposable lab machine first, then volunteer pilot machines. Before reimaging any Windows device, verify data backup and restoration, required recovery material, the user's application workflows, and an approved rollback route. Keep existing services available until the pilot passes; do not cancel licenses first and discover an app cannot authenticate afterward.

Migrate SSO one application at a time, testing normal users, administrators, recovery, logout, disablement, provisioning, and service accounts. Where federation is supported but an application still requires its vendor's tenant, record the remaining dependency rather than calling it fully eliminated.

For each old RMM/Intune capability, record **replaced**, **not needed**, **approved exception**, or **blocked**. Remove the previous agent only after the corresponding support, security, update, and recovery requirements are met and evidence is retained.

Retirement requires explicit sign-off on identity, endpoints, applications, security, support, data retention, and recovery. Rotate temporary migration credentials, remove obsolete connectors, revoke retired device credentials, and verify no scheduled tasks still depend on old services.

### Offboarding a person

Immediately disable new organizational authorization and revoke relevant sessions/token families. Remove application assignments and provision deactivation through supported connectors. Push updated login policy to reachable devices; show pending offline devices and their last valid lease expiry. Handle existing sessions according to policy, preserve necessary company data, and do not equate account deletion with remote file erasure.

### Reassigning or retiring a machine

Revoke old person assignments, preserve required data through an approved process, remove their local data and credential cache, rotate recovery material as appropriate, and start a new assignment/enrollment generation. Factory reset and reprovisioning need explicit tests; snapshots must not revive the previous person's credentials or silently clone device identity.

A lost or compromised device may be revoked before it can acknowledge cleanup. The dashboard must accurately show that remote cleanup is unconfirmed, not claim success because a task was queued.

## 23. Suggested repository structure and documentation

This is a proposed future layout, not files created by this planning exercise:

```text
oma-id/
  AGENTS.md
  README.md
  oma-id_plan.md
  server/                 Rails application
  agent/                  Rust workspace and local helper
  packaging/arch/         Reviewed native packaging definitions
  integration/omarchy/    Minimal patch sets and integration fixtures
  protocol/               OpenAPI, JSON schemas, compatibility fixtures
  tests/interop/          OIDC, enrollment, and agent interoperability
  tests/vm/               Disposable ISO/login/update scenarios
  docs/adr/               Architecture decisions
  docs/security/          Threat model, key lifecycle, review findings
  docs/runbooks/          Deployment, restore, recovery, update, offboard
  docs/upstream/          RFC and PR drafts
```

Keep upstream Omarchy changes independently reviewable. A monorepo can coordinate server/agent contracts without embedding upstream source history or shipping unrelated modifications.

Required early documents: compatibility matrix; threat model; authentication/enrollment sequence; key inventory and rotation plan; failure-state table; API schemas; local privilege boundary; and a supported-versus-unverified capability list. Required production documents: deployment, restore, lost-authenticator recovery, device rescue, incident response, offboarding, upgrade/rollback, and signing-key compromise runbooks.

Review dependency licenses before distributing binaries or derivatives. Omarchy, comparative authd material, Ruby gems, Rust crates, and support tools do not necessarily have the same licensing terms. Preserve applicable notices and source obligations; do not copy authd implementation code into OMA-ID modules.

## 24. Codex execution contract

Use the following as the initial development instruction:

> Read `oma-id_plan.md` completely. Begin with P0 only. Inspect the real repositories and their local instructions, pin source/package versions, and produce the compatibility matrix, threat model, dependency decisions, and isolated login/protocol experiments. Keep Rails as the authoritative IAM server. Implement ADR-0004 as a narrow Rust agent, thin PAM client, and provisioned local Unix accounts; authd is comparative evidence only and NSS is out of initial scope. Use local mise-managed Ruby 4 for initial Rails development, with Phlex and RubyUI for the UI. Local protocol experiments must use fake identities, ephemeral keys, and isolated development data. Do not substitute a mandatory Microsoft/Keycloak backend, build a large CRUD dashboard before the identity risk is tested, or claim SDDM/Quickshell/offline enforcement works without evidence. Run OS/PAM/account/install experiments only in disposable containers/VMs; never change the host PAM stack, format host disks, enroll production devices, or publish an upstream issue/PR without explicit authorization. Report verified capabilities, failing tests, unresolved assumptions, and the next smallest implementation step. After P0, implement one work package at a time with tests and documentation, preserving all security and recovery gates in this plan.

For each subsequent work package, produce a brief outcome report containing implemented behavior, tests run and results, affected trust boundaries, compatibility changes, migration/recovery instructions, and remaining blockers. Mark a gate passed only with reproducible evidence. Do not weaken a requirement simply to make a test green; propose an ADR explaining the tradeoff instead.

### First production demonstration

The project is ready for its first managed-workstation demonstration when an authorized user can boot a supported ISO, select work/school, enter the OMA-ID URL, approve the correct device in a trusted browser, install encrypted Omarchy, complete recovery setup, and enter a managed desktop as a non-administrator. The machine must appear with accurate identity/compliance evidence, survive a normal supported update, work within its tested offline policy, and respond correctly to disablement and recovery tests.

That demonstration is the first coherent product. Broader RMM parity, every SaaS connector, shared classrooms, and higher-assurance hardware trust come afterward unless a specific pilot requirement makes them a release blocker.

## 25. Source register

Sources below were reviewed on **2026-09-04**. Branch URLs are mutable; pin commits and versions during P0. References document upstream facts and standards, not endorsement of OMA-ID or proof that this proposed integration has been implemented. URLs are included in literal form so this file remains useful outside the chat.

| ID | Primary source and purpose | URL |
|---|---|---|
| S01 | Omarchy current repository / redirect target | `https://github.com/omacom/omarchy` |
| S02 | ISO repository README; architecture, autoinstall, tests | `https://github.com/omacom/omarchy-iso/blob/quattro/README.md` |
| S03 | ISO configurator source | `https://raw.githubusercontent.com/omacom/omarchy-iso/quattro/configs/airootfs/root/configurator` |
| S04 | Live ISO entry point | `https://raw.githubusercontent.com/omacom/omarchy-iso/quattro/configs/airootfs/root/.automated_script.sh` |
| S05 | Shared Omarchy setup form | `https://raw.githubusercontent.com/omacom/omarchy/quattro/install/provisioning/setup-form.sh` |
| S06 | SDDM/keyring installation behavior | `https://raw.githubusercontent.com/omacom/omarchy/quattro/install/login/sddm.sh` |
| S07 | Deferred owner provisioning | `https://raw.githubusercontent.com/omacom/omarchy/quattro/bin/omarchy-provision-owner` |
| S08 | Omarchy installation / deferred setup guidance | `https://omarchy.org/manual/getting-started/` |
| S09 | Omarchy security, reset, password, signing guidance | `https://omarchy.org/manual/security/` |
| S10 | authd supported installation instructions | `https://ubuntu.com/docs/authd/stable-docs/howto/install-authd/` |
| S11 | authd identity-provider support | `https://ubuntu.com/docs/authd/stable-docs/reference/identity-providers/` |
| S12 | authd broker/access configuration | `https://ubuntu.com/docs/authd/stable-docs/howto/configure-authd/` |
| S13 | authd architecture | `https://ubuntu.com/docs/authd/stable-docs/explanation/authd-architecture/` |
| S14 | authd user management and NSS limitations | `https://ubuntu.com/docs/authd/stable-docs/explanation/user-management/` |
| S15 | authd non-root PAM change, PR #1649 | `https://github.com/canonical/authd/pull/1649` |
| S16 | Archived broker repository and migration notice | `https://github.com/ubuntu/authd-oidc-brokers` |
| S17 | Doorkeeper guides / extension model | `https://doorkeeper.gitbook.io/guides` |
| S18 | Doorkeeper OpenID Connect extension | `https://github.com/doorkeeper-gem/doorkeeper-openid_connect` |
| S19 | Device Authorization Grant extension | `https://github.com/exop-group/doorkeeper-device_authorization_grant` |
| S20 | WebAuthn Ruby server library | `https://github.com/cedarcode/webauthn-ruby` |
| S21 | Rails maintenance policy | `https://guides.rubyonrails.org/maintenance_policy.html` |
| S22 | OAuth 2.0 Security BCP, RFC 9700 | `https://datatracker.ietf.org/doc/html/rfc9700` |
| S23 | Device Authorization Grant, RFC 8628 | `https://datatracker.ietf.org/doc/html/rfc8628` |
| S24 | OpenID Connect Core | `https://openid.net/specs/openid-connect-core-1_0.html` |
| S25 | OpenID Foundation conformance suite | `https://gitlab.com/openid/conformance-suite` |
| S26 | PostgreSQL row-security policies and caveats | `https://www.postgresql.org/docs/current/ddl-rowsecurity.html` |
| S27 | Arch system maintenance / full upgrades | `https://wiki.archlinux.org/title/System_maintenance` |
| S28 | The Update Framework overview | `https://theupdateframework.io/docs/overview/` |
| S29 | systemd cryptographic enrollment documentation source | `https://github.com/systemd/systemd/blob/main/man/systemd-cryptenroll.xml` |
| S30 | Self-hosted step-ca documentation | `https://smallstep.com/docs/step-ca/` |
| S31 | osquery remote configuration/enrollment protocol | `https://osquery.readthedocs.io/en/stable/deployment/remote/` |
| S32 | RustDesk Linux / Wayland restrictions | `https://rustdesk.com/docs/en/client/linux/` |
| S33 | SCIM protocol, RFC 7644 | `https://www.rfc-editor.org/rfc/rfc7644.html` |
| S34 | Microsoft Entra service dependencies | `https://learn.microsoft.com/en-us/office365/servicedescriptions/azure-active-directory` |
| S35 | ISO orchestrator launcher source | `https://raw.githubusercontent.com/omacom/omarchy-iso/quattro/configs/airootfs/usr/local/bin/omarchy-iso-install` |

---

**Implementation status at this revision:** P0 foundation underway: repository guidance, source-capture tooling, a pinned discovery inventory, initial threat model, and experiment procedures exist. The project owner selected local mise-managed Ruby 4 and Phlex/RubyUI for Rails development. See `docs/p0/README.md` for executed checks and remaining blockers. No production Rails server, agent, ISO, native login integration, performance benchmark, or security certification is complete. Discovery snapshots are not supported release claims.
