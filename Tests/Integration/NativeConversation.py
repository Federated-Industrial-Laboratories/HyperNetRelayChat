# SPDX-License-Identifier: Apache-2.0
"""Real HRC CLI workflow over externally provisioned, authentic HyperNet companions.

The fixture supplies only HyperNet prerequisites and bounded transport faults.
Every HRC registration, permission change, message and query uses the executable.
No database keys, signing secrets or private SQL state are read by this driver.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import time


def address(identity):
    if 'home' in identity:
        return address(identity['home']) + ':' + identity['local']
    if 'service' in identity:
        return address(identity['network']) + ':' + identity['service']
    if 'origin' in identity:
        return address(identity['origin']) + ':' + identity['local']
    return identity['network'] + ':' + identity['incarnation']


class Conversation:
    def __init__(self, configuration, controls, record):
        self.config = configuration
        self.controls = controls
        self.record = record
        self.binary = str(Path(configuration['binary']).resolve(strict=True))
        self.root = Path(configuration['directory'])
        self.root.mkdir(mode=0o700)
        self.exchange = self.root / 'Exchange'
        self.recovery = self.root / 'Recovery'
        for path in (self.exchange, self.recovery):
            path.mkdir(mode=0o700)
        self.home = configuration['home']
        self.service = self.root / 'Service'
        self.profiles = {}
        self.sessions = {}
        self.server = None
        self.serial = 0
        self.deadline = time.monotonic() + configuration.get('maximumSeconds', 900)

    def clock(self, companion):
        return ['--companion', str(companion), '--clock-observation', self.config['clock']['observation'],
                '--clock-key', self.config['clock']['monitorKey']]

    def cli(self, name, *arguments, failure=False):
        remaining = self.deadline - time.monotonic()
        assert remaining > 0, 'native HRC workflow deadline expired'
        result = subprocess.run([self.binary, *map(str, arguments)], capture_output=True,
                                timeout=min(35, remaining))
        assert len(result.stdout) <= 1024*1024 and len(result.stderr) <= 65536
        item = dict(case=name, exitCode=result.returncode,
                    stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
        self.record(item)
        if failure:
            assert result.returncode != 0, name + ': expected refusal'
            return result
        assert result.returncode == 0, name + ': ' + item['stderr']
        return json.loads(result.stdout)

    def json_file(self, value):
        self.serial += 1
        path = self.exchange / ('Request' + str(self.serial) + '.json')
        with path.open('x') as output:
            path.chmod(0o600)
            json.dump(value, output, ensure_ascii=False)
        return path

    @staticmethod
    def outcome(value, status='committed', code=None):
        assert value['outcome']['status'] == status, value
        if code is not None:
            assert value['outcome']['code'] == code, value
        return value['outcome'].get('body')

    def session(self, name):
        value = self.cli(name+'Session', 'profile', 'session', '--profile', self.profiles[name])
        assert value['status'] == 'Authenticated'
        self.sessions[name] = value['session']
        return value['session']

    def api(self, name, operation, target, body):
        session = self.session(name)
        actor = {'mode': 'direct', 'acting': session['acting']}
        if session['classification']['kind'] == 'agent':
            actor = {'mode': 'independentAgent', 'acting': session['acting'],
                     'operator': session['classification']['operator']}
        action = dict(home=self.home, operationId=dict(window=session['window']['id'], operation=os.urandom(32).hex()),
                      actor=actor, target=target, operation=operation, body=body,
                      expected={}, approval=None, agreement=None)
        return self.cli(name+'Api'+str(operation), 'api', '--profile', self.profiles[name],
                        '--request', self.json_file(action))

    def start(self):
        self.server = subprocess.Popen([self.binary, 'service', 'run', '--directory', str(self.service), '--diagnostics'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert select.select([self.server.stdout], [], [], 15)[0], 'HRC service readiness deadline'
        ready = json.loads(self.server.stdout.readline())
        assert ready['status'] == 'Ready' and ready['home'] == self.home, ready
        self.record(dict(case='HrcServiceReady', passed=True, home=self.home))

    def stop(self):
        if self.server is not None:
            if self.server.poll() is None:
                self.server.terminate()
            try:
                out, err = self.server.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                out, err = self.server.communicate(timeout=5)
                raise AssertionError('HRC service did not stop within its cleanup budget')
            assert len(out) <= 65536 and len(err) <= 65536
            self.record(dict(case='HrcServiceStopped', exitCode=self.server.returncode,
                             stdout=out.decode(errors='replace'), stderr=err.decode(errors='replace')))
            self.server = None

    def setup(self):
        companions = self.config['companions']
        assert len({v['principal'] for v in companions.values()}) == 3
        descriptor = self.cli('HrcServiceCreated', 'service', 'init', '--directory', self.service,
            '--network', self.home['network']['network'], '--incarnation', self.home['network']['incarnation'],
            '--service', self.home['service'], *self.clock(companions['Alice']['directory']))
        assert descriptor['home'] == self.home
        accounts = {}
        for name in ('Alice', 'Bob', 'Agent'):
            invitation = self.exchange / (name+'Invitation.json')
            registration = self.exchange / (name+'Registration.cbor')
            profile = self.root / name
            args = ['service','invite','--directory',self.service,'--principal',companions[name]['principal'],'--output',invitation]
            if name == 'Agent':
                args += ['--operator', address(accounts['Alice'])]
            self.cli(name+'Invited', *args)
            created = self.cli(name+'ProfileCreated', 'profile','create','--directory',profile,
                '--invitation',invitation,'--recovery-key-file',self.recovery/(name+'.key'),
                '--registration-output',registration,*self.clock(companions[name]['directory']))
            accounts[name] = created['account']
            enrolled = self.cli(name+'Enrolled','service','enrol','--directory',self.service,'--registration',registration)
            assert enrolled['account'] == accounts[name]
            self.profiles[name] = profile
        self.start()
        for name in self.profiles:
            assert self.session(name)['acting']['account'] == accounts[name]
        assert self.sessions['Agent']['classification']['kind'] == 'agent'
        self.record(dict(case='DistinctNativeHrcPrincipals',passed=True,
                         principals={k:v['principal'] for k,v in companions.items()}))

    def room(self, name):
        response = self.cli('Create'+name,'room','create','--profile',self.profiles['Alice'],'--name',name)
        return self.outcome(response)['room']

    def send(self, name, room, text, grant=None, failure=False):
        args = ['send','--profile',self.profiles[name],'--room',address(room),'--text',text]
        if grant is not None:
            args += ['--grant',grant]
        return self.cli(name+'Send',*args,failure=failure)

    def events(self, name, room, term=None):
        args = ['history' if term is None else 'search','--profile',self.profiles[name],'--room',address(room),'--limit','50']
        if term is not None:
            args += ['--term',term]
        return self.outcome(self.cli(name+'History' if term is None else name+'Search',*args),'result')['events']

    def grant(self, room, expires_ms=None, export_name='AgentGrant.json'):
        now = int(time.time()*1000)
        expiry = expires_ms or now+600000
        permissions = dict(agent=self.sessions['Agent']['acting'], rooms=[room], recipients=[],
            operations=[20,21,22,30,31], mode='autonomous', notBeforeMs=now-2000, expiresMs=expiry,
            historyFromMs=now-60000, historyUntilMs=expiry, maxOperationsPerMinute=30,
            purpose='Bounded native conversation qualification')
        result = self.cli('AgentGrant','agent','grant','--profile',self.profiles['Alice'],
                          '--permissions',self.json_file(permissions))
        grant = self.outcome(result)
        reference = grant
        exported = self.exchange/export_name
        self.outcome(self.cli('AgentInspect','agent','inspect','--profile',self.profiles['Alice'],
                     '--grant',reference['id'],'--generation',reference['generation'],'--export',exported),'result')
        return reference, exported

    def main(self):
        self.setup()
        room = self.room('Native room')
        other = self.room('Other room')
        for name in ('Bob','Agent'):
            for target in (room,other):
                self.outcome(self.cli(name+'Joined','room','join','--profile',self.profiles[name],'--room',address(target)))
        text = 'Native café e\u0301 👩🏽‍🚀 مرحبا conversation'
        self.outcome(self.send('Alice',room,text))
        self.outcome(self.send('Agent',room,'Independent native agent'))
        events = self.events('Bob',room)
        assert any(e['body'].get('text') == text and e['actor']['mode']=='direct' for e in events if isinstance(e['body'],dict))
        assert any(e['actor']['mode']=='independentAgent' for e in events)
        assert any(e['body'].get('text') == text for e in self.events('Bob',room,'café') if isinstance(e['body'],dict))
        reference, exported = self.grant(room)
        delegated = 'Delegated native reply'
        self.outcome(self.send('Agent',room,delegated,exported))
        self.outcome(self.send('Agent',other,'Out of scope',exported),'rejected','denied')
        def lifecycle(operation):
            nonlocal reference
            reference=self.outcome(self.cli('Agent'+operation.title(),'agent',operation,
                '--profile',self.profiles['Alice'],'--grant',reference['id'],'--generation',reference['generation']))
        lifecycle('pause')
        self.outcome(self.send('Agent',room,'Paused effect',exported),'rejected','denied')
        lifecycle('resume')
        exported=self.exchange/'AgentResumedGrant.json'
        self.outcome(self.cli('AgentInspectResumed','agent','inspect','--profile',self.profiles['Alice'],
            '--grant',reference['id'],'--generation',reference['generation'],'--export',exported),'result')
        self.outcome(self.send('Agent',room,'Resumed effect',exported))
        lifecycle('revoke')
        self.outcome(self.send('Agent',room,'Revoked effect',exported),'rejected','denied')
        events = self.events('Bob',room)
        matching = [e for e in events if isinstance(e['body'],dict) and e['body'].get('text')==delegated]
        assert len(matching)==1 and matching[0]['actor']['mode']=='delegated'
        assert matching[0]['actor']['represented']==self.sessions['Alice']['acting']['account']
        self.record(dict(case='NativeHumanIndependentAndDelegatedConversation',passed=True,
                         unicode=True,indexedSearch=True,outOfScopeRefused=True,paused=True,resumed=True,revoked=True))
        expiry=int(time.time()*1000)+7000
        _, expiring=self.grant(room,expiry,'ExpiringGrant.json')
        remaining=(expiry-int(time.time()*1000)+300)/1000
        if remaining>0:
            time.sleep(min(remaining,8))
        self.outcome(self.send('Agent',room,'Expired permission effect',expiring),'rejected','expired')
        self.record(dict(case='NativeExpiredDelegationRefusesEffect',passed=True))
        self.filters(room)
        self.stop(); self.start()
        assert any(e['body'].get('text')==text for e in self.events('Alice',room,'café') if isinstance(e['body'],dict))
        self.acknowledgement_loss(room)
        self.authority_refusal(room)
        self.record(dict(case='NativeHrcConversation',passed=True,protocol='hrc/1',
                         allHrcOperationsThroughCli=True,noDirectFallback=True))

    def filters(self, room):
        alice = self.sessions['Alice']['acting']['account']
        bob = self.sessions['Bob']['acting']['account']
        self.outcome(self.api('Bob',60,{'kind':'account','id':bob},dict(subject=alice,enabled=True)))
        hidden = 'Ignored recipient marker'
        self.outcome(self.send('Alice',room,hidden))
        assert not self.events('Bob',room,hidden)
        assert len(self.events('Alice',room,hidden))==1
        self.outcome(self.api('Bob',60,{'kind':'account','id':bob},dict(subject=alice,enabled=False)))
        restriction = dict(subject=bob,enabled=True,durationMs=60000,reason='Native silence qualification')
        self.outcome(self.api('Alice',62,{'kind':'room','id':room},restriction))
        self.outcome(self.send('Bob',room,'Silenced publication'),'rejected','denied')
        assert not self.events('Alice',room,'Silenced publication')
        restriction['enabled']=False
        self.outcome(self.api('Alice',62,{'kind':'room','id':room},restriction))
        self.record(dict(case='NativeRecipientIgnoreAndRoomSilence',passed=True,
                         recipientSearchFiltered=True,sharedHistoryPreserved=True,publicationPrevented=True))

    def acknowledgement_loss(self, room):
        proxy = self.controls['begin_ack_loss']('Bob')
        try:
            proxy.arm()
            text = 'Committed once despite lost acknowledgement'
            self.send('Bob',room,text,failure=True)
            assert proxy.dropped.wait(2), 'No actual service response was discarded'
            pending = self.cli('PendingAfterAckLoss','outbox','--profile',self.profiles['Bob'])
            assert len(pending)==1, 'Expected one unresolved operation after acknowledgement loss'
            before = self.events('Alice',room,text)
            assert len(before)==1
            assert pending[0]['operationId']==before[0]['operationId']
            assert pending[0]['actionDigest']==before[0]['actionDigest']
            self.stop(); self.start()
            resolved = self.cli('ResolveAfterRestart','resolve','--profile',self.profiles['Bob'])
            assert resolved, 'Exact persisted operation was not resolved'
            self.cli('ResolveAgain','resolve','--profile',self.profiles['Bob'])
            assert not self.cli('OutboxResolved','outbox','--profile',self.profiles['Bob'])
            after = self.events('Alice',room,text)
            assert len(after)==1 and after[0]['event']==before[0]['event']
            self.record(dict(case='NativeUnknownSendResolvesExactlyOnce',passed=True,
                             event=after[0]['event'],fault=proxy.evidence,serviceRestart=True))
        finally:
            self.controls['end_ack_loss']('Bob',proxy)

    def authority_refusal(self, room):
        text = 'Preserved draft after HyperNet authority withdrawal'
        self.controls['revoke_principal']('Agent')
        self.send('Agent',room,text,failure=True)
        draft = self.cli('DraftAfterAuthorityRefusal','draft','get','--profile',self.profiles['Agent'],'--room',address(room))
        assert text in json.dumps(draft,ensure_ascii=False), 'Draft was lost during refused connection'
        assert not self.events('Alice',room,text)
        self.record(dict(case='NativeHyperNetAuthorityRefusalPreservesDraft',passed=True,
                         draftRetained=True,noPublication=True,noDirectFallback=True))


def run(configuration, controls, record):
    workflow = Conversation(configuration, controls, record)
    try:
        workflow.main()
    finally:
        workflow.stop()
