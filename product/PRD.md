# BreachAtlas product requirements v0

Status: planning; application source not implemented. English-facing app/docs are the release default. See Persian assessment for commercial hypotheses.

Target user: تحلیلگر مستقل DFIR و مشاور رخداد

Job to complete: case کوچک با integrity و custody history قابل‌حمل

Differentiation hypothesis: bundle قابل‌حمل و verifier مستقل؛ نصب بسیار سبک برای یک analyst

## MVP acceptance scope

- یک analyst و یک case namespace
- stream upload و SHA-256 manifest
- append-only custody با checkpoint خارج از host
- timeline CSV/JSON و export verifier

## Excluded until another decision

- جست‌وجوی OpenSearch
- analyzer plugin دلخواه
- chain-of-custody رسمی قضایی
- team case collaboration و SIEM integration

## End-to-end outcomes

1. evidence را upload/seal کن؛ byte عوض‌شده verifier را شکست دهد
2. hold فعال اجازهٔ delete و expire ندهد
3. export در دستگاه جدا بدون سرور با trust key مستقل بررسی شود و timezone خام حفظ شود

Functional requirements F01–F20 and nonfunctional/release requirements are mapped one-to-one in `plans/requirements.json`. Tests belong with their feature commit, not postponed until launch. Success: a clean installed selected profile performs the core task and recovers from documented failures. Public demand remains unvalidated until real trials are recorded.

## UI flow

Select/import scoped input -> validate limits and permission -> show actual processing state -> explain result and confidence -> review/triage where appropriate -> export -> recover in clean environment. Loading, empty, stale, partial, unauthorized, rejected input, timeout/cancel and permanent failure are explicit. Provide table/keyboard alternatives to canvas, charts and graph paths. No sensitive content in page telemetry.
