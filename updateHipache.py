import boto
import requests
import subprocess
import redis

try:
    from secret import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
except:
    AWS_ACCESS_KEY_ID = None
    AWS_SECRET_ACCESS_KEY = None

def getCreds():
    conn = boto.connect_s3(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    bucket = conn.get_bucket('0NK38GF20CCT6VYTBG02'.lower() + '-keys')
    bucket.get_key('client.key').get_contents_to_filename('client.key')
    bucket.get_key('client.crt').get_contents_to_filename('client.crt')
    bucket.get_key('myca.crt').get_contents_to_filename('myca.crt')

def getBase(hostname, port):
    base = 'https://{0}:{1}/v2/keys'.format(hostname, port)
    return base

def getHipacheNodes(hostname="localhost", port=4001):
    base = getBase(hostname, port)
    r = requests.get(base + '/hipache/', verify=False, cert=('client.crt', 'client.key'))
    if not r.ok:
        return list()
    instances = [i['key'] for i in r.json()['node']['nodes'] ]
    print 'found hipache nodes ', instances
    return instances

def getAllListedNodes(instance, hostname='localhost', port=4001):
    base = getBase(hostname, port)
    r = requests.get(base + instance, verify=False, cert=('client.crt', 'client.key'))
    if not r.ok:
        return
    nodes = dict([(i['key'].split('/')[-1],i['value']) for i in r.json()['node']['nodes'] if 'connected' not in i['key']])
    print 'found listed nodes ', nodes, ' for instance ', instance 
    return nodes

def getConnectedNodes(instance, hostname='localhost', port=4001):
    base = getBase(hostname, port)
    r = requests.get(base + instance + '/connected/', verify=False, cert=('client.crt', 'client.key'))
    if not r.ok:
        return
    nodes = dict([(i['key'].split('/')[-1],i['value']) for i in r.json()['node']['nodes'] if 'connected' in i['key']])
    print 'found listed nodes ', nodes, ' for instance ', instance 
    return nodes

def getExternalPort(instances):
    toHipache = {}
    for did, port in instances.items():
        s = subprocess.Popen(["sudo", "docker", "port", did, port], stdout = subprocess.PIPE)
        exPort = s.communicate()
        if s.returncode == 0:
            toHipache[did] = exPort[0].split(':')[-1].strip()
    print 'external port map ', toHipache        
    return toHipache

def getRedis():
    s = subprocess.Popen(['sudo', 'docker', 'ps'], stdout = subprocess.PIPE)
    did = s.communicate()
    index = [i for i,txt in enumerate(did[0].split()) if 'hipache' in txt][0] - 1
    s = subprocess.Popen(['sudo', 'docker', 'port', did[0].split()[index], '6379'], stdout = subprocess.PIPE)
    exPort = int(s.communicate()[0].split(':')[-1].strip())
    r = redis.StrictRedis(host='localhost', port=exPort, db=0)
    return r

def setHipache(ports, aname, hostname, port):
    try:
        r = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4', timeout=0.2)
    except requests.Timeout:
        r = None
    if r is not None and r.ok:
        ip = r.text
    else:
        ip = 'localhost'
    base = getBase(hostname, port)
    key = base + aname + '/connected/' 
    r = requests.delete(key, verify=False, cert=('client.crt', 'client.key'), params = {'recursive':'true'})
    for did, port in ports.items():
        value = '{0}:{1}'.format(ip, port )
        key = base + aname + '/connected/' + did
        print 'setting value = ' + value + ' for key ' + key
        r = requests.put(key, verify=False, cert=('client.crt', 'client.key'), params = {'value':value})
    #for name, port in ports.items():
    #    r.rpush("frontend:"+hostname, aname)
    #    r.rpush("frontend:"+hostname, "http://" + ip + ":"+str(port))
        
def updateRedis(aname, hostname, cHosts):
    frontend = 'frontend:' + hostname
    r = getRedis()
    if len(r.lrange(frontend,0,-1)) != 0:
        clearRedis(frontend, r)
    print 'Adding ', aname, ' to frontend', frontend
    r.rpush(frontend, aname)    
    for host in cHosts.values():
        print 'Adding ', host, ' to frontend ', frontend
        r.rpush(frontend, 'http://' + host)

def clearRedis(frontend, r):
    r.delete(frontend)

def updateAllRedis(updateableNodes = dict(), hostname='localhost', port=4001):
    nodes = getHipacheNodes(hostname, port)
    for nodeFull in nodes:
        node = nodeFull.split('/')[-1]
        if node in updateableNodes:
            cns = getConnectedNodes(nodeFull, hostname, port)
            for x in updateableNodes[node]:
                updateRedis(node, x, cns)

def setAll(hostname, port):
    getCreds()
    i = getHipacheNodes(hostname, port)
    for n in i:
        nodes = getAllListedNodes(n, hostname, port)
        ports = getExternalPort(nodes)
        setHipache(ports, n, hostname, port)

#    i = getHipache(name)
#    if i is not None:
#        h = getExternalPort(i)
#        setHipache(h, name, hostname)

if __name__ == '__main__':
    try:
        r = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4', timeout=0.2)
    except requests.Timeout:
        r = None
    if r is not None and r.ok:
        ip = r.text
    else:
        ip = 'rymurr.com'

    setAll(ip, 4001)
    updateAllRedis({'ghost-cort': ['loftypen.com'], 'twilio':['rymurr.com']}, 'rymurr.com', 4001)
