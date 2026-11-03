# CPSM 현재 ERD

기준: `cpsm-server/src/store.js`의 `configureDatabase()`를 격리된 임시 디렉터리에서 실행해 확인한 SQLite schema. 현재 schema는 **38개 테이블**이다. 이 ERD는 key 및 관계 컬럼 중심도이며 전체 컬럼/제약은 [`../SCHEMA.md`](../SCHEMA.md)와 `src/store.js`를 따른다.

## 관계 표기

- `--` : 실제 SQLite `FOREIGN KEY` 제약이 있음.
- `..` : 서버 코드에서 확인되는 논리적 참조/인가 관계이며, SQLite FK 제약은 없음.
- polymorphic references (`family_members.member_type/member_id`, `audit_log.actor_type/actor_id`)는 컬럼 조합으로 해석한다.
- 기존 schema는 telemetry 4개 FK 외에 대부분 application-level integrity를 사용한다. 점선 관계를 DB-enforced 관계로 해석하면 안 된다.

## Identity, Family, mapping, consent

```mermaid
erDiagram
  DEVICES {
    TEXT device_id PK
    TEXT public_key
    TEXT platform
    TEXT registration_status
    TEXT metadata_json
  }
  FAMILIES {
    TEXT family_id PK
    TEXT status
  }
  PARENT_PROFILES {
    TEXT parent_id PK
    TEXT family_id
    TEXT device_fingerprint UK
    TEXT status
  }
  CHILD_PROFILES {
    TEXT child_id PK
    TEXT device_id UK
    TEXT status
  }
  FAMILY_MEMBERS {
    TEXT family_id PK
    TEXT member_type PK
    TEXT member_id PK
    TEXT role
    TEXT status
  }
  PARENT_CHILD_MAPPINGS {
    TEXT mapping_id PK
    TEXT family_id UK
    TEXT parent_id UK
    TEXT child_id UK
    TEXT status
    INTEGER parent_consent
    INTEGER child_consent
  }
  CONSENT_REQUESTS {
    TEXT request_id PK
    TEXT mapping_id
    TEXT recipient_type
    TEXT recipient_id
    TEXT status
  }
  PAIRING_SESSIONS {
    TEXT session_id PK
    TEXT issuer_type
    TEXT issuer_id
    TEXT child_device_id
    TEXT mapping_id
    TEXT status
    INTEGER expires_at
  }
  PARENT_SESSIONS {
    TEXT token_hash PK
    TEXT family_id
    TEXT parent_id
    INTEGER expires_at
  }
  DEVICE_NOTIFICATION_KEYS {
    TEXT notification_key_id PK
    TEXT device_id
    TEXT provider
    TEXT token
    TEXT status
  }
  AUDIT_LOG {
    TEXT id PK
    TEXT actor_type
    TEXT actor_id
    TEXT action
    TEXT request_id
    TEXT metadata_json
  }

  FAMILIES ||..o{ PARENT_PROFILES : family_id
  FAMILIES ||..o{ FAMILY_MEMBERS : family_id
  PARENT_PROFILES ||..o{ FAMILY_MEMBERS : polymorphic_parent_member
  CHILD_PROFILES ||..o{ FAMILY_MEMBERS : polymorphic_child_member
  DEVICES ||..o| CHILD_PROFILES : device_id
  FAMILIES ||..o{ PARENT_CHILD_MAPPINGS : family_id
  PARENT_PROFILES ||..o{ PARENT_CHILD_MAPPINGS : parent_id
  CHILD_PROFILES ||..o{ PARENT_CHILD_MAPPINGS : child_id
  PARENT_CHILD_MAPPINGS ||..o{ CONSENT_REQUESTS : mapping_id
  PARENT_PROFILES ||..o{ PARENT_SESSIONS : parent_id
  FAMILIES ||..o{ PARENT_SESSIONS : family_id
  PARENT_PROFILES ||..o{ PAIRING_SESSIONS : issuer_parent
  CHILD_PROFILES ||..o{ PAIRING_SESSIONS : issuer_or_claimed_child
  PARENT_CHILD_MAPPINGS ||..o{ PAIRING_SESSIONS : mapping_id
  DEVICES ||..o{ DEVICE_NOTIFICATION_KEYS : device_id
```

`family_members` is the active membership/role surface. `parent_child_mappings` separately records the relationship and both compatibility consent flags. QR `pairing_sessions` point to a pending mapping until explicit confirmation. Parent session bearer values are stored as hashes. `device_notification_keys` is unique by `(device_id,provider,token)`.

## Device activity, policy and commands

```mermaid
erDiagram
  DEVICES {
    TEXT device_id PK
    INTEGER local_policy_version
    INTEGER last_event_seq
    TEXT registration_status
  }
  FAMILIES {
    TEXT family_id PK
    TEXT status
  }
  EVENTS {
    TEXT id PK
    TEXT device_id UK
    TEXT event_id UK
    INTEGER sequence
    TEXT type
    TEXT payload_json
  }
  COMMANDS {
    TEXT id PK
    TEXT device_id UK
    TEXT idempotency_key UK
    TEXT type
    TEXT state
    TEXT payload_json
    TEXT expires_at
  }
  APPROVAL_REQUESTS {
    TEXT id PK
    TEXT device_id
    TEXT event_id
    TEXT kind
    TEXT status
    TEXT decision
  }
  POLICIES {
    TEXT policy_id PK
    INTEGER version
    TEXT signature
    TEXT rules_json
  }
  FAMILY_POLICIES {
    TEXT family_id PK
    INTEGER version
    TEXT policy_json
  }
  DEVICE_POLICY_ASSIGNMENTS {
    TEXT assignment_id PK
    TEXT device_id UK
    TEXT family_id UK
    TEXT policy_id
    INTEGER version
    TEXT status
  }
  POLICY_SYNC_RECEIPTS {
    TEXT receipt_id PK
    TEXT device_id
    TEXT policy_id
    INTEGER version
    INTEGER accepted
  }
  REQUEST_NONCES {
    TEXT device_id PK
    TEXT nonce PK
    INTEGER expires_at
  }
  PARENT_TOKENS {
    TEXT token PK
    TEXT created_at
  }

  DEVICES ||..o{ EVENTS : device_id
  DEVICES ||..o{ COMMANDS : device_id
  DEVICES ||..o{ APPROVAL_REQUESTS : device_id
  FAMILIES ||..o| FAMILY_POLICIES : family_id
  DEVICES ||..o{ DEVICE_POLICY_ASSIGNMENTS : device_id
  FAMILIES ||..o{ DEVICE_POLICY_ASSIGNMENTS : family_id
  DEVICES ||..o{ POLICY_SYNC_RECEIPTS : device_id
  POLICIES ||..o{ DEVICE_POLICY_ASSIGNMENTS : policy_id_legacy_reference
  COMMANDS ||..o| APPROVAL_REQUESTS : command_created_after_decision
  DEVICES ||..o{ REQUEST_NONCES : device_id
```

`commands` has unique `(device_id, idempotency_key)`; `events` has unique `(device_id, event_id)`; `device_policy_assignments` has unique `(device_id, family_id)`. These are uniqueness constraints, not foreign keys. Screen-time approval/request objects and commands have application-level links. `family_policies.policy_json.rules[]` may contain an optional device target; the server validates confirmed family membership on write and filters signed policy rules per target device. This scope is encoded in JSON and adds no table or relational constraint.

## Missions and app-install requests

```mermaid
erDiagram
  MISSIONS {
    TEXT mission_id PK
    TEXT family_id
    TEXT device_id
    TEXT created_by_parent_id
    TEXT title
    TEXT instructions
    INTEGER bonus_minutes
    TEXT status
  }
  MISSION_CREATE_REQUESTS {
    TEXT family_id PK
    TEXT parent_id PK
    TEXT request_id PK
    TEXT payload_fingerprint
    TEXT mission_id UK
  }
  MISSION_SUBMISSIONS {
    TEXT submission_id PK
    TEXT mission_id
    TEXT family_id
    TEXT device_id
    TEXT status
    TEXT submitted_at
  }
  MISSION_REVIEWS {
    TEXT review_id PK
    TEXT submission_id UK
    TEXT mission_id
    TEXT parent_id
    TEXT decision
    TEXT reviewed_at
  }
  MISSION_REWARDS {
    TEXT reward_id PK
    TEXT submission_id UK
    TEXT mission_id
    TEXT device_id
    INTEGER bonus_minutes
    TEXT command_id
  }
  APP_INSTALL_REQUESTS {
    TEXT request_id PK
    TEXT device_id
    TEXT family_id
    TEXT package_name
    TEXT status
    TEXT expires_at
  }
  COMMANDS {
    TEXT id PK
    TEXT device_id UK
    TEXT idempotency_key UK
    TEXT type
    TEXT state
  }
  DEVICES {
    TEXT device_id PK
  }
  FAMILIES {
    TEXT family_id PK
  }
  PARENT_PROFILES {
    TEXT parent_id PK
  }

  FAMILIES ||..o{ MISSIONS : family_id
  DEVICES ||..o{ MISSIONS : assigned_device
  PARENT_PROFILES ||..o{ MISSIONS : created_by_parent_id
  MISSIONS ||..o{ MISSION_SUBMISSIONS : mission_id
  MISSION_SUBMISSIONS ||..o| MISSION_REVIEWS : submission_id
  MISSION_SUBMISSIONS ||..o| MISSION_REWARDS : submission_id
  MISSION_CREATE_REQUESTS ||..|| MISSIONS : mission_id
  COMMANDS ||..o| MISSION_REWARDS : command_id
  FAMILIES ||..o{ APP_INSTALL_REQUESTS : family_id
  DEVICES ||..o{ APP_INSTALL_REQUESTS : device_id
```

Mission create idempotency is scoped by `(family_id, parent_id, request_id)` and stores only a SHA-256 fingerprint of normalized create fields; `mission_id` is unique. One review and one reward maximum per submission are enforced by unique indexes. The reward command is a separate queue record and only positive-minute rewards reference it. App-install requests have a partial unique index for one pending `(device_id,package_name)`; approval records permission only and creates no install command.

## Location and geofence records

```mermaid
erDiagram
  LOCATION_CONSENTS {
    TEXT device_id PK
    TEXT family_id
    INTEGER parent_consented
    INTEGER child_consented
    INTEGER permission_granted
  }
  LOCATION_REQUESTS {
    TEXT request_id PK
    TEXT command_id UK
    TEXT family_id
    TEXT device_id
    TEXT parent_id
    TEXT status
    TEXT sample_id
    TEXT expires_at
  }
  LOCATION_SAMPLES {
    TEXT device_id PK
    TEXT sample_id PK
    TEXT request_id
    TEXT family_id
    TEXT captured_at
    REAL latitude
    REAL longitude
    REAL accuracy_m
  }
  GEOFENCES {
    TEXT geofence_id PK
    TEXT family_id
    TEXT created_by_parent_id
    TEXT name
    REAL latitude
    REAL longitude
    INTEGER radius_m
  }
  GEOFENCE_STATES {
    TEXT device_id PK
    TEXT geofence_id PK
    TEXT state
    TEXT sample_id
  }
  LOCATION_TRANSITIONS {
    TEXT transition_id PK
    TEXT family_id
    TEXT device_id
    TEXT geofence_id
    TEXT sample_id
    TEXT transition_type
    TEXT event_time
  }
  DEVICES {
    TEXT device_id PK
  }
  FAMILIES {
    TEXT family_id PK
  }
  COMMANDS {
    TEXT id PK
    TEXT device_id
  }

  DEVICES ||..o| LOCATION_CONSENTS : device_id
  FAMILIES ||..o{ LOCATION_CONSENTS : family_id
  DEVICES ||..o{ LOCATION_REQUESTS : device_id
  FAMILIES ||..o{ LOCATION_REQUESTS : family_id
  COMMANDS ||..o| LOCATION_REQUESTS : command_id
  LOCATION_REQUESTS ||..o{ LOCATION_SAMPLES : request_id
  DEVICES ||..o{ LOCATION_SAMPLES : device_id
  FAMILIES ||..o{ LOCATION_SAMPLES : family_id
  FAMILIES ||..o{ GEOFENCES : family_id
  DEVICES ||..o{ GEOFENCE_STATES : device_id
  GEOFENCES ||..o{ GEOFENCE_STATES : geofence_id
  GEOFENCES ||..o{ LOCATION_TRANSITIONS : geofence_id
  DEVICES ||..o{ LOCATION_TRANSITIONS : device_id
  FAMILIES ||..o{ LOCATION_TRANSITIONS : family_id
```

Location values remain in location-specific tables. The first valid sample establishes geofence baseline; derived transitions are not interpolated routes. Location cooldown is computed from per-device terminal `location_requests.updated_at` and a server configuration value; it adds no table or FK. All relations in this diagram are logical references; SQLite has no declared FK constraints for the location tables.

## Release telemetry

```mermaid
erDiagram
  APP_VERSIONS {
    TEXT platform PK
    TEXT product PK
    INTEGER version_code PK
    TEXT sha256
  }
  APP_VERSION_CHANGES {
    TEXT change_id PK
    TEXT platform FK
    TEXT product FK
    INTEGER version_code FK
    TEXT issue_id
  }
  DEVICE_ERRORS {
    TEXT error_id PK
    TEXT fingerprint UK
    TEXT product
    TEXT status
    INTEGER is_fixed
  }
  DEVICE_ERROR_OCCURRENCES {
    TEXT occurrence_id PK
    TEXT error_id FK
    TEXT device_id UK
    TEXT client_error_id UK
  }
  ERROR_APP_VERSION_LINKS {
    TEXT error_id FK PK
    TEXT platform FK PK
    TEXT product FK PK
    INTEGER version_code FK PK
    TEXT relation PK
  }
  DEVICES {
    TEXT device_id PK
  }

  APP_VERSIONS ||--o{ APP_VERSION_CHANGES : fk_release_version
  APP_VERSIONS ||--o{ ERROR_APP_VERSION_LINKS : fk_release_version
  DEVICE_ERRORS ||--o{ DEVICE_ERROR_OCCURRENCES : fk_error
  DEVICE_ERRORS ||--o{ ERROR_APP_VERSION_LINKS : fk_error
  DEVICES ||..o{ DEVICE_ERROR_OCCURRENCES : device_id
```

These are the only declared FK families in the current schema: release changes and error/version links point to `app_versions`; error occurrences and error/version links point to `device_errors`. `device_error_occurrences` also has unique `(device_id, client_error_id)`; `device_errors.fingerprint` is unique.

## Remaining support tables

```mermaid
erDiagram
  STORAGE_META {
    TEXT key PK
    TEXT value
  }
  PARENT_TOKENS {
    TEXT token PK
    TEXT created_at
    TEXT last_used_at
  }
```

`storage_meta(key,value)` tracks schema initialization/migration; `parent_tokens(token,created_at,last_used_at)` is legacy notification compatibility. Both are present in the 38-table inventory but do not add domain relationships beyond those shown above.
