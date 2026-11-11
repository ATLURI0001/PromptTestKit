# Security

Do not include API keys in configuration, prompts, issue reports, or committed
run artifacts. Credentials are read from environment variables. Redirects are
disabled to avoid forwarding credentials to another endpoint. Non-local endpoints
require HTTPS. Provider error bodies are not copied into reports.

Run artifacts contain model output and assertions and can contain sensitive data.
Review them before sharing or uploading workflow artifacts. HTML reports escape
model text and apply a restrictive content security policy; they load no scripts
or remote assets. Fingerprints identify inputs; they are not cryptographic
signatures and do not authenticate artifact authorship.

Treat suite files as trusted local configuration: they can reference files via
relative or absolute paths. This CLI is not a sandbox for untrusted suites.

Report security issues privately through the repository's GitHub Security
Advisories when enabled; otherwise ask the maintainer for a private channel
without disclosing exploit details in a public issue.
