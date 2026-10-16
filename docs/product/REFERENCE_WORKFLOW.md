# BreachAtlas: reference workflow

Status: planned domain acceptance; the current JSON structure preview does not implement this workflow.

Upload synthetic evidence -> seal -> add custody -> parse bounded timeline -> hold/delete negative test -> export -> verify on another host with external trust -> recover consistency.

Required invariants:

- Sealed source bytes never modified
- Legal hold takes precedence over deletion
- Raw timestamp and confidence survive normalization

Required UAT:

- evidence را upload/seal کن؛ byte عوض‌شده verifier را شکست دهد
- hold فعال اجازهٔ delete و expire ندهد
- export در دستگاه جدا بدون سرور با trust key مستقل بررسی شود و timezone خام حفظ شود

Machine contract: tests/scenarios/clone-to-value.json. C01/C04 create and freeze the actual synthetic positive/negative fixture formats; no real secrets, user source/traffic/case data or unlicensed corpus. A clean source clone must reproduce the entire workflow with restart and restore at C30.
