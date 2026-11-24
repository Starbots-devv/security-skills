"""Bounded local data handling. Imported text is never executable authority."""
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import tempfile

class ValidationError(ValueError):
    def __init__(self, code, message):
        self.code=code
        super().__init__(message)

def fail(code,message):
    raise ValidationError(code,message)

def inspect_data(value,depth=0):
    if depth>32:fail('RESOURCE_LIMIT','JSON exceeds 32 nesting levels')
    if isinstance(value,float):fail('INVALID_SCHEMA','Use decimal strings, not binary floats')
    if isinstance(value,int) and not isinstance(value,bool) and abs(value)>9007199254740991:fail('RESOURCE_LIMIT','Integer exceeds safe 53-bit range')
    if isinstance(value,str):
        try:value.encode('utf-8')
        except UnicodeError:fail('INVALID_SCHEMA','Invalid Unicode string')
    if isinstance(value,dict):
        for k,v in value.items():
            if not isinstance(k,str) or not k.isascii():fail('INVALID_SCHEMA','Object keys must be ASCII strings')
            inspect_data(v,depth+1)
    elif isinstance(value,list):
        for item in value:inspect_data(item,depth+1)

def json_bytes(value):
    inspect_data(value)
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode('utf-8')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def resolve_local(root,path):
    if not isinstance(path,str) or not path or '\x00' in path or ':' in path or PureWindowsPath(path).is_absolute():fail('PATH_DENIED','Expected a relative local artifact path')
    parts=path.replace('\\','/').split('/')
    if any(x in ('','.','..') or x.endswith((' ','.')) or re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)',x,re.I) for x in parts):fail('PATH_DENIED','Unsafe path component')
    base=Path(root).resolve()
    candidate=base.joinpath(*parts)
    current=base
    for part in parts:
        current=current/part
        if current.is_symlink() or (hasattr(current,'is_junction') and current.is_junction()):fail('PATH_DENIED','Symbolic links and junctions are not permitted')
    final=candidate.resolve()
    if not final.is_relative_to(base):fail('PATH_DENIED','Artifact escapes the allowed root')
    return final

def read_bytes(root,path,max_bytes=10*1024*1024):
    p=resolve_local(root,path)
    try:
        with p.open('rb') as f:raw=f.read(max_bytes+1)
    except OSError:fail('PATH_DENIED','Artifact cannot be read under the selected root')
    if len(raw)>max_bytes:fail('RESOURCE_LIMIT','Artifact exceeds size limit')
    return raw

def _pairs(pairs):
    result={}
    for k,v in pairs:
        if k in result:fail('INVALID_SCHEMA','Duplicate JSON object key')
        result[k]=v
    return result

def parse_json(raw):
    try:
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=lambda x:fail('INVALID_SCHEMA','Nonfinite number'),parse_float=lambda x:fail('INVALID_SCHEMA','Decimal strings required'))
        inspect_data(value)
        return value
    except (UnicodeError,json.JSONDecodeError):fail('INVALID_SCHEMA','Invalid UTF-8 JSON')
    except RecursionError:fail('RESOURCE_LIMIT','JSON nesting limit exceeded')

def load_json(root,path,max_bytes=10*1024*1024):
    return parse_json(read_bytes(root,path,max_bytes))

def write_bytes(root,path,raw):
    destination=resolve_local(root,path)
    destination.parent.mkdir(parents=True,exist_ok=True)
    temp=None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,delete=False) as f:
            temp=f.name;f.write(raw)
        os.replace(temp,destination)
    finally:
        if temp and Path(temp).exists():Path(temp).unlink()
    return destination

def write_json(root,path,value):
    return write_bytes(root,path,json_bytes(value))

def verify_ref(root,ref):
    raw=read_bytes(root,ref['path'])
    if digest(raw)!=ref['sha256']:fail('HASH_MISMATCH','Artifact digest differs from the reviewed reference')
    return raw

def verify_subject(root,subject,*,client_id,project_id):
    if subject['client_id']!=client_id or subject['project_id']!=project_id:fail('IDENTITY_MISMATCH','Subject belongs to another client or project')
    p=subject['payload'];raw=read_bytes(root,p['manifest_path'])
    if digest(raw)!=p['manifest_sha256']:fail('HASH_MISMATCH','Subject manifest changed')
    manifest=parse_json(raw)
    if set(manifest)!={'subject_id','revision','client_id','project_id','artifacts'}:fail('INVALID_SCHEMA','Unexpected subject manifest structure')
    if any(manifest[k]!=v for k,v in [('subject_id',p['subject_id']),('revision',p['revision']),('client_id',client_id),('project_id',project_id),('artifacts',p['artifacts'])]):fail('IDENTITY_MISMATCH','Subject manifest does not match the supplied subject')
    if len(p['artifacts'])>1000:fail('RESOURCE_LIMIT','Too many subject artifacts')
    total=len(raw);seen=set()
    for ref in p['artifacts']:
        path=ref['path'].replace('\\','/')
        if path in seen or path==p['manifest_path']:fail('INVALID_SCHEMA','Duplicate or self-referencing artifact')
        seen.add(path);total+=len(verify_ref(root,ref))
        if total>100*1024*1024:fail('RESOURCE_LIMIT','Bundle exceeds 100 MiB')
    return manifest
