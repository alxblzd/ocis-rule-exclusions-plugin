# Personal ownCloud Infinite Scale Rule Exclusions for OWASP CRS

## Description

This personal plugin contains rule exclusions developed for my own [ownCloud Infinite Scale (oCIS)](https://github.com/owncloud/ocis) deployment protected by the [OWASP Core Rule Set (CRS)](https://coreruleset.org/).

This repository is not an official ownCloud or OWASP CRS plugin, is not affiliated with either project, and is not currently intended for submission to their organizations or plugin registries. References to those projects describe technical compatibility only.

The repository is formatted according to the [OWASP CRS Template Plugin](https://github.com/coreruleset/template-plugin) where its conventions apply to a personal, third-party rule-exclusion plugin.

## Scope

The exclusions cover oCIS workflows observed in my environment. They may be useful as a reference for similar deployments, but they are not a promise of general oCIS compatibility or support. Optional integrations, custom extensions, reverse-proxy behavior, and different clients may require additional [custom rule exclusions](https://coreruleset.org/docs/concepts/false_positives_tuning/).

Compatibility can vary between oCIS and CRS releases. Test the plugin in a non-production environment before deploying or upgrading it.

## Covered false positives

Version 0.1.3 covers the following oCIS workflows observed in this deployment:

- loading `/config.json` or `/web/config.json`, which can trigger CRS rule `930130`;
- using OData `$filter` and `$orderby` parameters on supported Graph endpoints, which can trigger CRS rule `942290`;
- updating users through the Graph API, including password changes, which can trigger CRS rule `911100` on the `PATCH` method;
- using WebDAV methods below `/dav/`, which can trigger CRS rule `911100`;
- creating and uploading files through TUS endpoints below `/data`, which can trigger CRS rules `911100`, `920340`, `920420`, and `920640`;
- uploading arbitrary binary content that would otherwise be parsed as form arguments and trigger request-body rules; and
- storing files with extensions restricted by the generic CRS policy below `/dav/spaces/`, which can trigger CRS rule `920440`.

The rules are scoped by endpoint, request method, content type, or variable wherever possible. Anomaly evaluation remains active; rule `949110` is not removed directly.

For opaque TUS and binary upload bodies, request-body inspection is disabled only on the matching upload transaction. The request URI and headers remain inspected. This prevents arbitrary file bytes from being misinterpreted as application arguments, but it also means CRS does not inspect the uploaded file content itself. Use a dedicated malware or content-scanning service if uploaded files must be inspected.

## Rule ID range

This personal plugin locally uses the `9,542,000-9,542,999` rule ID block:

- `9,542,000-9,542,099` for initialization; and
- `9,542,100-9,542,499` for request exclusions.

This is a local allocation and is not registered or reserved with the OWASP CRS project. Verify that no other locally installed plugin uses these IDs. If the project is ever prepared for general third-party distribution, its ID allocation must be reviewed and registered first.

## Template alignment

The repository follows the CRS template conventions for plugin filenames and load order, the opt-in disable variable, the `...099` disable rule, request-rule ID allocation, per-rule documentation, FTW regression-test layout, and commit-pinned reusable CI workflows.

The three standard plugin files are present. The `-after.conf` file intentionally contains no active rules because this plugin currently defines request exclusions only. Unlike the official template repository, this personal project has no external attribution file, does not inherit the CRS Renovate configuration, does not claim a registered rule-ID allocation, and is not submitted to the CRS plugin registry.

## Installation

For current instructions covering the available installation methods, see [How to Install a Plugin](https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin) in the official CRS documentation.

### Multi-application environments

If the same web application firewall protects several applications, scope this plugin to the oCIS virtual host or application. See [Conditionally enable plugins for multi-application environments](https://coreruleset.org/docs/concepts/plugins/#conditionally-enable-plugins-for-multi-application-environments) in the CRS documentation.

## Configuration considerations

### Request and upload size limits

ModSecurity request-body limits are independent of the exclusions provided by this plugin. File uploads larger than the configured limits will still be rejected.

Adjust `SecRequestBodyLimit` and, when applicable, `SecRequestBodyNoFilesLimit` to values appropriate for your deployment. Apply these settings as narrowly as possible and consider the memory, disk, timeout, and denial-of-service impact of accepting large request bodies.

The exact configuration context depends on the web server and ModSecurity implementation. Refer to the documentation for your engine and reverse proxy before changing these limits.

### Additional tuning

Higher CRS paranoia levels, third-party integrations, and custom clients may produce false positives that are outside this plugin's generic scope. Review the relevant audit-log entries and add narrowly scoped local exclusions where necessary.

### Engine compatibility

The plugin uses standard `ctl` actions rather than an engine-specific `RAW` request-body processor. It is intended to remain portable across ModSecurity 2, libModSecurity 3, and Coraza, but it is currently validated against Coraza with CRS 4.29.0 in my environment. Treat compatibility with any other engine or deployment as unverified until its tests pass there.

## Testing

After enabling the plugin, verify the main oCIS workflows used by your deployment, including authentication, browsing, uploads, downloads, sharing, and client synchronization.

If a standard oCIS workflow is blocked by CRS, open an [issue](https://github.com/alxblzd/ocis-rule-exclusions-plugin/issues/new) and include:

- the oCIS, CRS, and WAF engine versions;
- the CRS paranoia level and anomaly-scoring settings;
- the affected request or workflow; and
- sanitized audit-log entries containing the triggered rule IDs.

Do not include credentials, access tokens, personal data, or file contents in reports.

Regression tests are stored below `tests/regression/ocis-rule-exclusions`. The GitHub Actions workflows run only in this repository with read-only repository permissions and without inherited secrets. They call public, commit-pinned reusable test workflows maintained by the CRS project; this does not submit the plugin, publish results to CRS, or modify any upstream repository.

## Project status

This is a personal, deployment-driven project published for transparency and reuse as a reference. Its scope and release decisions remain under the sole control of the repository owner. External contributions are not currently solicited, and publication of this repository does not imply support, official status, or plans to submit or upstream the plugin.

## License

Copyright (c) 2026 alxblzd.

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
