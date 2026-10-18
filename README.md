# Sealed workers

Generic, manually dispatched workers for authenticated encrypted offline workloads.
The owner prepares a bundle with a complete file inventory, an entry point and
independent shard assignments. Workers authenticate and validate it, execute it
with a bounded lifetime, and encrypt outputs and diagnostics before publication.

Public content consists of worker source, opaque job identities, ciphertext,
ciphertext hashes and generic execution status. Workload logs and results are not
written to public Actions logs. The payload process receives an allowlisted
environment without the repository token or decryption key. Checkout credentials
are not persisted. This is intended for trusted owner-authored payloads; it is not
a sandbox for hostile code, and execution metadata such as timing is public.

Jobs are independent and GitHub enforces the account's concurrent runner limit.
There are no scheduled workflows, automatic policy promotions or external service
credentials. Re-running a job creates a separate sealed result for that attempt.

Outputs use Actions artifacts with three-day retention. The export directories
contain only encrypted bundles and generic receipts; compact indexes and full
details are separate artifacts. Sealed input bundles remain release assets.
An optional explicit shard list supports reviewed recovery of missing results.

Run the generic contracts with `python -m unittest -q test_worker`.
