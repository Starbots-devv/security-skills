"""Record a clean source commit in ignored wheel metadata; never runs in the product CLI."""
import json
from pathlib import Path
import subprocess

root=Path(__file__).resolve().parents[1]
def git(*args):return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
if git('status','--porcelain'):raise SystemExit('Commit or resolve all source changes before stamping a review build.')
commit=git('rev-parse','HEAD')
(root/'src/starbots_security/data/build.json').write_text(json.dumps({'source_commit':commit},sort_keys=True)+'\n',encoding='utf-8',newline='\n')
print(commit)
