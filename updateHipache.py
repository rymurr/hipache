import boto
import requests
import subprocess
import redis
import docker

config = {'rymurr/ghost-cort':{22:'backup',2368:'hipache','site':['loftypen.com','www.loftypen.com']},
          'rymurr/ghost-ryan':{22:'backup',2368:'hipache', 'site':['rymurr.com','www.rymurr.com']},
          'rymurr/twilio':{80:'hipache', 'site':['twilio.rymurr.com']},
         }
try:
    from secret import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    TOKEN = None
except:
    try:
        sts = boto.connect_sts()
        ar = sts.assume_role(role_arn="arn:aws:iam::710599580852:role/remote", role_session_name="rymurr")
        AWS_ACCESS_KEY_ID = ar.credentials.access_key
        AWS_SECRET_ACCESS_KEY = ar.credentials.secret_key
        TOKEN = ar.credentials.session_token
    except:
        TOKEN = None
        AWS_ACCESS_KEY_ID = None
        AWS_SECRET_ACCESS_KEY = None

def getFromDocker():
    c = docker.Client()
    containers = c.containers()
    ip = getIp()
    toHipache = {}
    for container in containers:
        image = container['Image'].split(':')[0]
        name = image.split('/')[-1]
        if not image in config.keys():
            continue
        toHipache[name] = {}
        cfg = config[image]
        ports = container['Ports']
        
        for port in ports:
            if port['PrivatePort'] in cfg and cfg[port['PrivatePort']] == 'hipache':
                toHipache[name][container['Names'][0].strip('/')] = port['PublicPort']
    return toHipache
                

def getCreds():
    conn = boto.connect_s3(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, security_token=TOKEN)
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

def getIp():
    try:
        r = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4', timeout=0.2)
    except requests.Timeout:
        r = None
    if r is not None and r.ok:
        ip = r.text
    else:
        ip = 'localhost'
    return ip

def setHipache(ports, aname, hostname, port):
    ip = getIp()
    base = getBase(hostname, port)
    for did, port in ports.items():
        value = '{0}:{1}'.format(ip, port )
        key = base + aname + '/connected/' + did
        print 'setting value = ' + value + ' for key ' + key
        r = requests.put(key, verify=False, cert=('client.crt', 'client.key'), params = {'value':value})
        
def updateRedis(aname, hostname, cHosts):
    frontend = 'frontend:' + hostname
    r = getRedis()
    if cHosts is None:
        return
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
    i = getFromDocker()#getHipacheNodes(hostname, port)
    for n,ports in i.items():
        setHipache(ports, '/hipache/'+n, hostname, port)

if __name__ == '__main__':
    ip = 'rymurr.com'
    setAll(ip, 4001)
    updateAllRedis({'ghost-cort': ['loftypen.com','www.loftypen.com'], 'twilio':['twilio.rymurr.com']}, 'rymurr.com', 4001)
