#!/usr/bin/env python3
"""Emit only SRXFER02 frames; patient output never shares stdout with this helper."""
import hashlib, io, json, os, stat, struct, sys, tarfile, unicodedata

MAGIC=b'SRXFER02'; HEADER=struct.Struct('>HHIQ'); MANIFEST=1; CHUNK=2; SUCCESS=3
def digest(data): return 'sha256:'+hashlib.sha256(data).hexdigest()
records=[]
for base, dirs, files in os.walk('/output'):
    dirs.sort(); files.sort()
    for filename in files:
        path=os.path.join(base, filename); relative=os.path.relpath(path, '/output').replace(os.sep, '/')
        if unicodedata.normalize('NFC', relative) != relative or not stat.S_ISREG(os.lstat(path).st_mode): raise SystemExit(70)
        data=open(path,'rb').read(); records.append({'path':relative,'type':'regular','mode':stat.S_IMODE(os.stat(path).st_mode),'size':len(data),'sha256':digest(data),'producer':'patient','sealer':'host_supervisor','trust':'untrusted_patient','truncated':False})
records.sort(key=lambda item:item['path'].encode('utf-8'))
tree=digest(json.dumps({'artifacts':records,'aggregate_bytes':sum(item['size'] for item in records)},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
manifest={'schema_id':'external_validation.artifact_manifest.v1','schema_version':'1','artifacts':records,'tree_hash':tree,'aggregate_bytes':sum(item['size'] for item in records)}
archive=io.BytesIO()
with tarfile.open(fileobj=archive,mode='w:',format=tarfile.USTAR_FORMAT) as tar:
    for item in records: tar.add('/output/'+item['path'],arcname=item['path'],recursive=False)
def frame(kind, sequence, payload): return HEADER.pack(kind,0,sequence,len(payload))+payload
payload=json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode(); stream=sys.stdout.buffer
stream.write(MAGIC+(2).to_bytes(2,'big')+b'\0\0'); stream.write(frame(MANIFEST,0,payload)); stream.write(frame(CHUNK,1,archive.getvalue())); stream.write(frame(SUCCESS,2,json.dumps({'archive_sha256':digest(archive.getvalue())},separators=(',',':')).encode())); stream.flush()
