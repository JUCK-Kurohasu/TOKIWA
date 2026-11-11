import json,time,urllib.request,urllib.parse,sys,re
G='http://127.0.0.1:21302'; A='http://127.0.0.1:21300/api/v1'; J=open('run/admin.jwt').read().strip()
TOK=re.search(r'dbg_[A-Za-z0-9]+',urllib.request.urlopen(G+'/').read().decode()).group(0)
def send(name,method='POST',path='/api/login',body=None,ctype=None,hdr=None):
    h={'User-Agent':'btest-'+name}; 
    if ctype: h['Content-Type']=ctype
    h.update(hdr or {})
    r=urllib.request.Request(G+path,data=body,headers=h,method=method)
    try: s=urllib.request.urlopen(r).status
    except urllib.error.HTTPError as e: s=e.code
    return s
cases={
 'form': dict(body=f'user=x&debug={TOK}'.encode(),ctype='application/x-www-form-urlencoded'),
 'form_pctenc_': dict(body=('user=x&debug='+TOK.replace('_','%5F')).encode(),ctype='application/x-www-form-urlencoded'),
 'multipart': dict(body=(f'--b\r\nContent-Disposition: form-data; name="debug"\r\n\r\n{TOK}\r\n--b--\r\n').encode(),ctype='multipart/form-data; boundary=b'),
 'json_after_5k': dict(body=json.dumps({'pad':'A'*5000,'debug':TOK}).encode(),ctype='application/json'),
 'json_unicode_esc': dict(body=('{"debug":"'+''.join('\\u%04x'%ord(c) for c in TOK)+'"}').encode(),ctype='application/json'),
 'put_json': dict(method='PUT',path='/api/products/1',body=json.dumps({'debug':TOK}).encode(),ctype='application/json'),
 'options_hdr': dict(method='OPTIONS',path='/api/products',hdr={'X-Debug-Auth':TOK}),
 'other_hdr_name': dict(method='GET',path='/api/products',hdr={'X-Debug-Token':TOK}),
 'path_pctenc_': dict(method='GET',path='/api/internal/'+TOK.replace('_','%5F')+'/'),
 'query_pctenc_': dict(method='GET',path='/api/products?ref='+TOK.replace('_','%5F')),
}
st={k:send(k,**v) for k,v in cases.items()}
time.sleep(20)
r=urllib.request.Request(A+'/deception/trips?limit=200',headers={'Authorization':'Bearer '+J})
trips=json.load(urllib.request.urlopen(r))['items']
by={}
for t in trips:
    ua=json.dumps(t)
    m=re.search(r'btest-([a-z0-9_]+)',ua)
    if m: by.setdefault(m.group(1),[]).append(t.get('reason') or t.get('trip_type') or t.get('kind'))
for k in cases: print(f'{k:18} status={st[k]} trips={by.get(k,[])}')
if trips: print('sample keys',list(trips[0].keys()))
