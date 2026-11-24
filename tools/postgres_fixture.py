"""Start/stop only the explicitly selected isolated synthetic PostgreSQL fixture."""
import argparse
import json
from pathlib import Path
import tempfile
import time
import uuid
from starbots_security.application import DOCKER_EXECUTABLE,DOCKER_EXECUTABLE_SHA256,_docker_command,_rls_process
from starbots_security.io import load_json,write_bytes,json_bytes

IMAGE='docker.io/library/postgres@sha256:d8703cd7fba306b9fec9268ecedfa8a966846c053036a60e3635791957eb2f66'
PIN=IMAGE.split('@')[1]
STARTUP='initdb -D /tmp/starbots-pg -A trust -U postgres --no-locale --encoding=UTF8 >/tmp/init.log 2>&1 && exec postgres -D /tmp/starbots-pg -k /tmp -c listen_addresses= -c shared_buffers=32MB -c max_connections=20 -c fsync=off'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--start-runtime');mode.add_argument('--stop-runtime')
    args=parser.parse_args()
    runtime=dict(docker_executable=str(DOCKER_EXECUTABLE),docker_executable_sha256=DOCKER_EXECUTABLE_SHA256)
    with tempfile.TemporaryDirectory(prefix='sb-pg-config-') as config:
        base=_docker_command(runtime,config)
        def call(*arguments):return _rls_process(base+list(arguments),timeout=30).strip()
        if args.stop_runtime:
            p=Path(args.stop_runtime);runtime=load_json(p.parent,p.name)
            if runtime['docker_executable_sha256']!=DOCKER_EXECUTABLE_SHA256 or runtime['image_digest']!=PIN:raise ValueError('Runtime identity mismatch')
            cid=runtime['container_id'];info=json.loads(call('inspect',cid))[0]
            if info['Id']!=cid or info['Image']!=PIN or info['Config']['Labels'].get('starbots.review.owner')!='local-fixture':raise ValueError('Refusing removal of an unowned container')
            call('rm','--force','--volumes',cid)
            print(json.dumps(dict(removed=True,container_id=cid)));return
        output=Path(args.start_runtime)
        if output.exists():raise ValueError('Runtime output must be a new file')
        # Never pull implicitly; acquisition and review are a separate operation.
        call('image','inspect',IMAGE)
        name='starbots-review-pg-'+uuid.uuid4().hex
        cid=call('create','--pull','never','--name',name,'--label','starbots.review.synthetic=true','--label','starbots.review.owner=local-fixture','--network','none','--read-only','--user','70:70','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','512m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777','--tmpfs','/var/lib/postgresql:rw,noexec,nosuid,nodev,size=1m,uid=70,gid=70','--entrypoint','/bin/sh',IMAGE,'-c',STARTUP)
        try:
            info=json.loads(call('inspect',cid))[0]
            if info['Image']!=PIN:raise ValueError('PostgreSQL image digest mismatch')
            call('start',cid)
            deadline=time.monotonic()+30
            while True:
                try:
                    version=call('exec',cid,'psql','-h','/tmp','-U','postgres','-d','postgres','-Atc','select version();');break
                except RuntimeError:
                    if time.monotonic()>=deadline:raise
                    time.sleep(.2)
            runtime.update(container_id=cid,image_digest=PIN)
            write_bytes(output.parent,output.name,json_bytes(runtime))
            print(json.dumps(dict(started=True,runtime=str(output),postgresql=version,network='none',published_ports=[])))
        except Exception:
            call('rm','--force','--volumes',cid);raise

if __name__=='__main__':main()
