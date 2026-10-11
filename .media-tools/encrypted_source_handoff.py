"""Least-privilege authorized media handoff; never publish plaintext media."""
import argparse, base64, concurrent.futures, hashlib, io, json, os, re
import struct, tempfile, time, urllib.error, urllib.parse, urllib.request, zipfile, zlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
SESSION = os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
PRIVATE = Path(os.environ['RUNNER_TEMP'])/'media-private-key.pem'

def prepare():
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    PRIVATE.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    PRIVATE.chmod(0o600)
    out=Path('exchange-public'); out.mkdir(exist_ok=True)
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    (out/'public.json').write_text(json.dumps({'session':SESSION,'public_key':public}))
    print('Ephemeral public key ready; private key stays on the runner.')

def receive():
    repo=os.environ['GITHUB_REPOSITORY']; branch=os.environ['GITHUB_REF_NAME']
    request_url='https://raw.githubusercontent.com/'+repo+'/'+branch+'/.media-exchange/request-'+SESSION+'.json'
    request=None
    for _ in range(120):
        try:
            req=urllib.request.Request(request_url+'?t='+str(int(time.time())),headers={'User-Agent':'Authorized-Media-Transfer'})
            with urllib.request.urlopen(req,timeout=30) as r: request=json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code!=404: raise RuntimeError('Request unavailable: HTTP '+str(e.code)) from None
        time.sleep(10)
    if not request: raise RuntimeError('Encrypted request timeout')
    if request.get('session')!=SESSION: raise RuntimeError('Session mismatch')
    private=serialization.load_pem_private_key(PRIVATE.read_bytes(),password=None)
    key=private.decrypt(base64.b64decode(request['wrapped_key']),OAEP)
    plain=AESGCM(key).decrypt(base64.b64decode(request['nonce']),base64.b64decode(request['ciphertext']),SESSION.encode())
    job=json.loads(zlib.decompress(plain)); PRIVATE.unlink()
    receiver=serialization.load_pem_public_key(job['output_public_key'].encode())
    tmp=Path(tempfile.mkdtemp(prefix='private-media-')); tmp.chmod(0o700)
    def download(a):
        aid=a['id']; ext=a['ext']; u=urllib.parse.urlparse(a['url'])
        if not re.fullmatch(r'[A-Z0-9_]{1,30}',aid) or ext not in ('.mp4','.mp3','.wav','.png'):
            raise ValueError('Invalid asset identifier')
        if u.scheme!='https' or not u.hostname or not u.hostname.endswith('.cloudfront.net'):
            raise ValueError('Only authorized HTTPS media CDN sources are accepted')
        dst=tmp/(aid+ext)
        for attempt in range(3):
            try:
                req=urllib.request.Request(a['url'],headers={'User-Agent':'Authorized-Media-Transfer/1.0'})
                with urllib.request.urlopen(req,timeout=90) as r, dst.open('wb') as f:
                    size=0
                    while True:
                        b=r.read(1024*1024)
                        if not b: break
                        size+=len(b)
                        if size>180*1024*1024: raise ValueError('Per-file limit exceeded')
                        f.write(b)
                if size<128: raise ValueError('Empty media')
                digest=hashlib.sha256(dst.read_bytes()).hexdigest()
                if a.get('sha256') and digest!=a['sha256']: raise ValueError('Checksum mismatch')
                print('Retrieved '+aid,flush=True)
                return {'id':aid,'ok':True,'file':dst.name,'size':size,'sha256':digest}
            except urllib.error.HTTPError as e: error='HTTP '+str(e.code)
            except Exception as e: error=type(e).__name__
            if dst.exists(): dst.unlink()
            time.sleep(attempt+1)
        return {'id':aid,'ok':False,'error':error}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(download,job['assets']))
    report=tmp/'retrieval_report.json'; report.write_text(json.dumps({'assets':results},indent=2))
    files=[tmp/r['file'] for r in results if r['ok']]+[report]
    groups=[]; current=[]; size=0
    for f in files:
        if current and size+f.stat().st_size>60*1024*1024:
            groups.append(current); current=[]; size=0
        current.append(f); size+=f.stat().st_size
    if current: groups.append(current)
    out=Path('sealed-output'); out.mkdir(exist_ok=True)
    for n,group in enumerate(groups,1):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_STORED) as z:
            for f in group: z.write(f,f.name)
        key=os.urandom(32); nonce=os.urandom(12)
        cipher=AESGCM(key).encrypt(nonce,buf.getvalue(),(SESSION+':'+str(n)).encode())
        h=json.dumps({'session':SESSION,'part':n,'nonce':base64.b64encode(nonce).decode(),'wrapped_key':base64.b64encode(receiver.encrypt(key,OAEP)).decode()}).encode()
        (out/('part-%02d.sealed'%n)).write_bytes(b'MENC1'+struct.pack('>I',len(h))+h+cipher)
    import shutil
    shutil.rmtree(tmp)
    print('Exported encrypted media only. Successes: '+str(sum(r['ok'] for r in results))+'; unavailable: '+str(sum(not r['ok'] for r in results)),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('mode',choices=['prepare','receive'])
    mode=parser.parse_args().mode
    if mode=='prepare': prepare()
    else: receive()
