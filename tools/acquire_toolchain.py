"""Inert preparation only. Defaults to offline verification; --download explicitly enables public retrieval.

No acquired program is executed. Exact sources/hashes/licenses are in the packaged lock.
Signature identity and complete transitive redistribution clearance remain unresolved.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

LOCK_PATH = Path(__file__).resolve().parents[1] / 'src/starbots_security/data/toolchain-lock.json'
LOCK = json.loads(LOCK_PATH.read_text(encoding='utf-8-sig'))


def sha_file(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def safe(path):
    path=path.absolute()
    if any(p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()) for p in (path,*path.parents)):
        raise ValueError('Links or junctions are forbidden')
    return path


def verify(root):
    root=safe(root)
    for name,expected in LOCK['files'].items():
        path=safe(root/name)
        if not path.is_file() or sha_file(path)!=expected:raise ValueError('Missing or mismatched pinned artifact: '+name)
    return len(LOCK['files'])


def store(root,name,data,expected):
    if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Acquired artifact hash differs from lock: '+name)
    path=safe(root/name);path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        if sha_file(path)!=expected:raise ValueError('Refusing to overwrite mismatched existing artifact: '+name)
        return
    path.write_bytes(data)


def retrieve(root,name,url,expected):
    path=safe(root/name)
    if path.is_file():
        if sha_file(path)!=expected:raise ValueError('Existing artifact mismatch: '+name)
        return path
    # No environment proxies or credential-bearing headers. Only public lock-derived URLs.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url,timeout=60) as response:
        data=response.read(512*1024*1024+1)
    if len(data)>512*1024*1024:raise ValueError('Acquisition size limit exceeded')
    store(root,name,data,expected)
    return path


def prepare(root):
    root=safe(root);root.mkdir(parents=True,exist_ok=True)
    for tool in LOCK['review']['tools']:
        artifact=retrieve(root,tool['artifact'],tool['source_url'],tool['artifact_sha256'])
        if tool['name']=='osv':
            store(root,tool['path'],artifact.read_bytes(),tool['binary_sha256'])
            license_url='https://raw.githubusercontent.com/google/osv-scanner/'+tool['source_commit']+'/LICENSE'
            retrieve(root,tool['license_path'],license_url,tool['license_sha256'])
        else:
            # Read only two named regular members; never extract an archive tree.
            with tarfile.open(artifact,'r:gz') as archive:
                for member,dest,expected in [(tool['name'],tool['path'],tool['binary_sha256']),('LICENSE',tool['license_path'],tool['license_sha256'])]:
                    info=archive.getmember(member)
                    if not info.isfile() or info.size>200*1024*1024:raise ValueError('Unexpected archive member')
                    with archive.extractfile(info) as stream:store(root,dest,stream.read(),expected)
        if tool['name']=='gitleaks':
            retrieve(root,tool['rules_path'],'https://raw.githubusercontent.com/gitleaks/gitleaks/'+tool['source_commit']+'/config/gitleaks.toml',tool['rules_sha256'])
    for name,encoded in [('configs/empty-ignore',''),('configs/osv-scanner.toml','IyBINCBleHBsaWNpdCBvdmVycmlkZTogbm8gaWdub3JlZCB2dWxuZXJhYmlsaXRpZXMgb3IgcGFja2FnZSBvdmVycmlkZXMuDQo='),('configs/trivy.yaml','e30NCg==')]:
        store(root,name,base64.b64decode(encoded),LOCK['files'][name])
    for snapshot in LOCK['review']['osv_snapshots']:
        retrieve(root,snapshot['path'],snapshot['source_url'],snapshot['sha256'])
    return verify(root)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--download',action='store_true',help='Explicitly permit public source downloads, then verify; never executes tools')
    args=parser.parse_args()
    try:count=prepare(args.directory) if args.download else verify(args.directory)
    except (ValueError,OSError) as exc:parser.exit(1,str(exc)+'\n')
    print('Verified '+str(count)+' pinned local files; no downloaded program was executed.')


if __name__=='__main__':main()
