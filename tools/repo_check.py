#!/usr/bin/env python3
from pathlib import Path
root = Path(__file__).resolve().parents[1]
lessons = sorted((root / "lessons").glob("lesson-*"))
missing = []
for lesson in lessons:
    if not (lesson / "README.md").exists(): missing.append(str(lesson / "README.md"))
    if not (lesson / "CHECKLIST.md").exists(): missing.append(str(lesson / "CHECKLIST.md"))
print(f"Lessons found: {len(lessons)}")
if missing:
    print("Missing files:")
    for m in missing: print("-", m)
    raise SystemExit(1)
print("Repository structure check passed.")
