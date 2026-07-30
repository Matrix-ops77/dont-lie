# Don't-Lie — Data Processing Addendum (DPA)

**Last updated:** 2026-07-30

**Scope:** This DPA supplements the Terms of Service. It applies
**only** if and when Don't-Lie operates a hosted service that
processes personal data on behalf of the customer (the
"Controller"). As of the v0.3.x release, **no such hosted service
exists**. The v0.3.x release is local-first open-source software
that runs on the customer's own hardware; the customer is the sole
Controller and Processor of their data, and Don't-Lie has no access
to it. This DPA is published in advance so that when the hosted
service ships, the contractual posture is already documented.

## 1. When this DPA applies

This DPA applies from the launch date of the first Don't-Lie hosted
service, which will be announced in the changelog and on the
project website (when one exists). It does not apply retroactively
to anyone who installed the v0.3.x local-first software.

## 2. Roles under GDPR (when the hosted service is live)

- **Controller:** the customer.
- **Processor:** Don't-Lie (the entity that will operate the
  hosted service; the legal entity will be named at hosted-service
  launch).
- **Subprocessors:** to be listed at hosted-service launch with at
  least 30 days notice to existing customers.

For the v0.3.x local-first software: there is no Processor in the
GDPR sense. The customer runs the software on their own
infrastructure and is the sole party with access to the data.

## 3. Subject matter, nature, and types of data

When the hosted service ships, the subject matter will be the
storage, retrieval, signing, verification, and export of AI
receipts on behalf of the customer. The categories of personal
data will be:

- Customer account email and billing metadata (collected by the
  hosted service for account management).
- AI receipts the customer chooses to sync to the hosted service
  (which may include personal data the customer included in prompts
  or responses).

The hosted service will not collect data that the customer does
not explicitly upload to it.

## 4. Security measures (planned for hosted service launch)

The hosted service will apply:

- AES-256-GCM at rest.
- TLS 1.3 in transit.
- Argon2id-derived vault keys for any customer-controlled
  encryption.

The following items are **not** in place today and will not be
claimed in the public paperwork until they are:

- **Third-party penetration tests:** not contracted. If the hosted
  service ships, pen-test cadence will be disclosed in a future
  revision of this DPA after the first report is delivered.
- **SOC 2 Type II audit:** not engaged. If the hosted service
  ships, SOC 2 status will be disclosed in a future revision of
  this DPA after the first report is delivered.

Until then, customers evaluating Don't-Lie for compliance use cases
should run the local-first software in their own environment, where
the security boundary is the customer's own infrastructure. This
is the supported deployment model for v0.3.x.

## 5. Customer obligations

The customer is responsible for:

- Establishing the lawful basis for processing (consent,
  legitimate interest, contract necessity) under GDPR or
  equivalent regimes.
- Ensuring the contents of their prompts and responses are
  lawful in their jurisdiction.
- Verifying the public keys they trust as receipt signers.

## 6. Data subject requests

When the hosted service is live, Don't-Lie will assist the customer
in responding to data subject requests (access, deletion,
portability) within 30 days. For the v0.3.x local-first software,
the customer handles data subject requests directly against their
own vault, which they already control end-to-end.

## 7. Breach notification

When the hosted service is live, Don't-Lie will notify the customer
within 72 hours of becoming aware of a personal data breach
affecting their data. This commitment does not apply to the
local-first software; in that case the customer is responsible
for their own breach response, because no third party (including
Don't-Lie) has access to the vault.

## 8. Return and deletion

When the hosted service is live, on termination, customer data will
be deleted within 30 days unless retention is required by law.
For the v0.3.x local-first software, the customer deletes their
own vault file at any time.

## 9. Subprocessor changes

When the hosted service is live, Don't-Lie will maintain a current
list of subprocessors and notify the customer of changes at least
30 days in advance. The current list is "None" until the hosted
service ships.

## 10. Governing law

Delaware, USA, for the contractual terms. For the GDPR-mandated
rights of EU data subjects, the customer's home Member State law
applies to the substance of those rights, with Delaware law
governing the commercial contract.

## 11. Contact

A hosted-service contact address will be published when the
hosted service ships. Until then, file a public issue at
`github.com/Matrix-ops77/dont-lie/issues`.
