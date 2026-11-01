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
        started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000
        # Session setup has one 30 s budget; operation and durable I/O have their own bounds.
        result = subprocess.run([self.binary, *map(str, arguments)], capture_output=True,
                                timeout=min(55, remaining))
        assert len(result.stdout) <= 1024*1024 and len(result.stderr) <= 65536
        item = dict(case=name, exitCode=result.returncode, startedBootMs=started,
                    finishedBootMs=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000,
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

    def stop(self, require_clean=False):
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
            exit_code = self.server.returncode
            self.record(dict(case='HrcServiceStopped', exitCode=exit_code,
                             stdout=out.decode(errors='replace'), stderr=err.decode(errors='replace')))
            self.server = None
            if require_clean:
                assert exit_code == 0, 'HRC service did not complete orderly shutdown'
                assert json.loads(out) == dict(status='Stopped'), 'Missing orderly shutdown result'

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
        page = self.cli(name+'History' if term is None else name+'Search',*args)
        assert page['stale'] is False and isinstance(page['content'], dict), 'Expected current ConversationPage'
        return page['events']

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
        inspected = self.cli('AgentInspect','agent','inspect','--profile',self.profiles['Alice'],
                     '--grant',reference['id'],'--generation',reference['generation'],'--export',exported)
        assert inspected['inspection']['grant']['reference'] == reference and inspected['inspection']['pending'] == []
        return reference, exported

    def main(self):
        self.setup()
        room = self.room('Native room')
        only_local = self.config.get('localClientOnly', False)
        assert isinstance(only_local, bool), 'localClientOnly must be boolean'
        setting = os.environ.get('HYPERNET_HRC_LOCAL_CLIENT_ONLY', '0')
        assert setting in ('0', '1'), 'Invalid local-client workflow selection'
        only_local = only_local or setting == '1'
        only_confidential = self.config.get('confidentialClientOnly', False)
        assert isinstance(only_confidential, bool), 'confidentialClientOnly must be boolean'
        confidential_setting = os.environ.get('HRC_NATIVE_CONFIDENTIAL_ONLY', '0')
        assert confidential_setting in ('0', '1'), 'Invalid confidential workflow selection'
        only_confidential = only_confidential or confidential_setting == '1'
        assert not (only_local and only_confidential), 'Select one independent client workflow'
        if only_local or only_confidential:
            binary = self.confidential_client_binary() if only_confidential else self.local_client_binary()
            assert binary, 'Independent client workflow requires its executable'
            for name in ('Bob', 'Agent'):
                self.outcome(self.cli(name+'Joined','room','join','--profile',self.profiles[name],
                                      '--room',address(room)))
            if only_confidential:
                self.confidential_client(room)
                self.authority_refusal(room)
                self.record(dict(case='NativeConfidentialClientWorkflow',passed=True,protocol='hrc/1',
                                 realCliProvisioning=True,conversationBaselineIncluded=False,
                                 confidentialClientIncluded=True,noDirectFallback=True))
                return
            self.local_client(room)
            reference, _ = self.grant(room)
            revoked = self.outcome(self.cli('LocalBotGrantRevoked','agent','revoke',
                '--profile',self.profiles['Alice'],'--grant',reference['id'],
                '--generation',reference['generation']))
            self.bot(room, revoked)
            self.authority_refusal(room)
            self.record(dict(case='NativeLocalClientWorkflow',passed=True,protocol='hrc/1',
                             realCliProvisioning=True,conversationBaselineIncluded=False,
                             localControllerIncluded=True,botIncluded=True,noDirectFallback=True))
            return
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
        self.denied_send('Agent',other,'Out of scope',exported,'OperationDenied')
        def lifecycle(operation):
            nonlocal reference
            reference=self.outcome(self.cli('Agent'+operation.title(),'agent',operation,
                '--profile',self.profiles['Alice'],'--grant',reference['id'],'--generation',reference['generation']))
        lifecycle('pause')
        self.denied_send('Agent',room,'Paused effect',exported,'OperationDenied')
        lifecycle('resume')
        exported=self.exchange/'AgentResumedGrant.json'
        inspected = self.cli('AgentInspectResumed','agent','inspect','--profile',self.profiles['Alice'],
            '--grant',reference['id'],'--generation',reference['generation'],'--export',exported)
        assert inspected['inspection']['grant']['reference'] == reference and inspected['inspection']['pending'] == []
        self.outcome(self.send('Agent',room,'Resumed effect',exported))
        lifecycle('revoke')
        self.denied_send('Agent',room,'Revoked effect',exported,'OperationDenied')
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
        self.denied_send('Agent',room,'Expired permission effect',expiring,'OperationExpired')
        self.record(dict(case='NativeExpiredDelegationRefusesEffect',passed=True))
        self.filters(room)
        self.stop(require_clean=True); self.start()
        assert any(e['body'].get('text')==text for e in self.events('Alice',room,'café') if isinstance(e['body'],dict))
        self.acknowledgement_loss(room)
        self.local_client(room)
        if self.local_client_binary():
            self.bot(room, reference)
        self.confidential_client(room)
        self.authority_refusal(room)
        self.record(dict(case='NativeHrcConversation',passed=True,protocol='hrc/1',
                         allHrcOperationsThroughCli=not (self.local_client_binary() or self.confidential_client_binary()),
                         localControllerIncluded=bool(self.local_client_binary()),
                         confidentialClientIncluded=bool(self.confidential_client_binary()),noDirectFallback=True))

    def denied_send(self, name, room, text, grant, code):
        result = self.send(name, room, text, grant, failure=True)
        assert json.loads(result.stderr) == dict(status='Failed', code=code), 'Wrong permanent preflight refusal'
        assert not self.events('Alice', room, text), 'Refused message was published'

    def confidential_client_binary(self):
        return self.config.get('confidentialClientBinary') or os.environ.get('HRC_NATIVE_CONFIDENTIAL_CLIENT')

    def confidential_client(self, room):
        binary = self.confidential_client_binary()
        if not binary:
            return
        binary = Path(binary).resolve(strict=True)
        assert binary.is_file() and os.access(binary, os.X_OK), 'Native confidential executable unavailable'
        maximum = min(600, int(self.deadline - time.monotonic()) - 2)
        assert maximum >= 120, 'Insufficient remaining confidential conversation budget'
        request = self.json_file(dict(alice=str(self.profiles['Alice']), bob=str(self.profiles['Bob']),
                                     agent=str(self.profiles['Agent']), room=room,
                                     bobRecovery=str(self.recovery/'Bob.key')))
        result = subprocess.run([str(binary), '--request', str(request), '--maximum-seconds', str(maximum)],
                                capture_output=True, timeout=maximum+1)
        assert len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'Confidential helper output bound'
        self.record(dict(case='NativeConfidentialProcess', exitCode=result.returncode,
                         stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace')))
        assert result.returncode == 0, 'Native confidential workflow failed'
        evidence = json.loads(result.stdout)
        assert evidence['case'] == 'NativeConfidentialConversations' and evidence['passed'] is True
        self.record(evidence)

    def local_client_binary(self):
        return self.config.get('localClientBinary') or os.environ.get('HYPERNET_HRC_LOCAL_CLIENT')

    def local_client(self, room):
        binary = self.local_client_binary()
        if not binary:
            return
        binary = Path(binary).resolve(strict=True)
        assert binary.is_file() and os.access(binary, os.X_OK), 'Native Controller executable unavailable'
        maximum = min(240, int(self.deadline - time.monotonic()) - 2)
        assert maximum >= 30, 'Insufficient remaining native Controller budget'
        request = self.json_file(dict(alice=str(self.profiles['Alice']), bob=str(self.profiles['Bob']),
                                      agent=str(self.profiles['Agent']), room=room))
        result = subprocess.run([str(binary), '--request', str(request), '--maximum-seconds', str(maximum)],
                                capture_output=True, timeout=maximum+1)
        assert len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'Native Controller output bound'
        self.record(dict(case='NativeLocalControllerProcess',exitCode=result.returncode,
                         stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace')))
        assert result.returncode == 0, 'Native Controller workflow failed'
        evidence = json.loads(result.stdout)
        assert evidence['case'] == 'NativeLocalController' and evidence['passed'] is True
        self.record(evidence)

    def bot(self, room, revoked_grant):
        previous_deadline = self.deadline
        self.deadline = min(previous_deadline, time.monotonic()+180)
        process = None
        help_text = 'Native deterministic help ' + os.urandom(12).hex()
        arguments = ['bot','--profile',self.profiles['Agent'],'--room',address(room),
                     '--help-text',help_text,'--poll-interval-ms','1000']

        def replies():
            return [event for event in self.events('Alice',room,help_text)
                    if isinstance(event['body'],dict) and event['body'].get('text') == help_text]

        def start(label):
            nonlocal process
            assert process is None, 'A bot already owns the Agent profile'
            process = subprocess.Popen([self.binary,*map(str,arguments)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            until = min(self.deadline,time.monotonic()+55)
            line = bytearray()
            while b'\n' not in line:
                remaining = until-time.monotonic()
                assert remaining > 0, label+': BotReady deadline'
                readable = select.select([process.stdout],[],[],min(remaining,0.2))[0]
                if readable:
                    part = os.read(process.stdout.fileno(),4096)
                    assert part, label+': bot exited before readiness'
                    line.extend(part)
                    assert len(line) <= 4096, label+': readiness output bound'
                else:
                    assert process.poll() is None, label+': bot exited before readiness'
            message,extra = bytes(line).split(b'\n',1)
            assert not extra.strip(), label+': unexpected startup output'
            ready = json.loads(message)
            assert ready == dict(status='BotReady',meaning='InitialAuthorisedCatchUpComplete'), ready
            assert process.poll() is None, label+': bot stopped at readiness'
            self.record(dict(case=label,passed=True,readiness=ready))

        def stop(label, require_clean=False):
            nonlocal process
            if process is None:
                return
            active = process
            process = None
            if active.poll() is None:
                active.terminate()
            forced = False
            try:
                stdout,stderr = active.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                forced = True
                active.kill()
                stdout,stderr = active.communicate(timeout=5)
            assert len(stdout) <= 65536 and len(stderr) <= 65536, 'Bot process output bound'
            self.record(dict(case=label,exitCode=active.returncode,forcedKill=forced,
                             stdout=stdout.decode(errors='replace'),stderr=stderr.decode(errors='replace')))
            if require_clean:
                assert active.returncode == 0 and not forced, label+': bot did not stop cleanly'
                assert json.loads(stdout) == dict(status='BotStopped'), label+': missing stopped result'

        try:
            historical = self.send('Alice',room,'!help')
            self.outcome(historical)
            historical_id = historical['outcome']['event']
            start('NativeBotInitialReady')
            assert not replies(), 'Initial catch-up replayed a historical trigger'
            trigger = self.send('Alice',room,'!help')
            self.outcome(trigger)
            trigger_id = trigger['outcome']['event']
            assert trigger_id != historical_id
            human = [event for event in self.events('Alice',room,'!help') if event['event'] == trigger_id]
            assert len(human) == 1 and human[0]['actor']['mode'] == 'direct'
            assert human[0]['operationId'] == trigger['operationId']
            until = min(self.deadline,time.monotonic()+30)
            observed = []
            while not observed:
                assert process.poll() is None, 'Bot stopped before its reply'
                observed = replies()
                if not observed:
                    assert time.monotonic() < until, 'Bot reply deadline'
                    time.sleep(min(0.2,max(0,until-time.monotonic())))
            assert len(observed) == 1, 'A single human trigger created duplicate bot replies'
            response = observed[0]
            assert response['kind'] == 21
            assert response['actor']['mode'] == 'independentAgent'
            assert response['actor']['acting']['account'] == self.sessions['Agent']['acting']['account']
            assert response['actor']['operator'] == self.sessions['Alice']['acting']['account']
            assert response['body']['parent'] == trigger_id and response['body']['causation'] == trigger_id
            assert response['sequence'] > human[0]['sequence']
            response_observed = time.monotonic()
            stop('NativeBotFirstStop',require_clean=True)

            # The Agent profile is released before another shipped CLI accesses it.
            agent_trigger = self.send('Agent',room,'!help')
            self.outcome(agent_trigger)
            human_reply = self.cli('NativeHumanReplyDoesNotTriggerBot','send','--profile',self.profiles['Alice'],
                                   '--room',address(room),'--text','!help','--reply',trigger_id)
            self.outcome(human_reply)
            # Cross the documented five-second reply rate window before evaluating
            # actor/reply suppression, so the rate limit cannot mask a bad rule.
            until = min(self.deadline,response_observed+7)
            while time.monotonic() < until:
                time.sleep(min(0.2,max(0,until-time.monotonic())))
            assert self.deadline-time.monotonic() > 0, 'Bot restart budget expired'
            start('NativeBotRestartReady')
            after = replies()
            assert len(after) == 1 and after[0]['event'] == response['event'], 'Bot replay or trigger loop'
            assert process.poll() is None, 'Bot stopped after restart catch-up'
            stop('NativeBotRestartStop',require_clean=True)

            denied = self.cli('NativeBotRevokedGrant','bot','--profile',self.profiles['Agent'],
                              '--room',address(room),'--help-text',help_text,'--poll-interval-ms','1000',
                              '--grant',revoked_grant['id'],failure=True)
            assert any(code in denied.stderr.decode(errors='replace')
                       for code in ('BotPermissionDenied','BotGrantUnavailable')), 'Expected explicit grant refusal'
            assert b'BotReady' not in denied.stdout, 'Revoked grant reached bot readiness'
            final = replies()
            assert len(final) == 1 and final[0]['event'] == response['event']
            self.record(dict(case='NativeDeterministicBot',passed=True,initialCatchUpNoReplay=True,
                             humanTrigger=trigger_id,reply=response['event'],parentAndCausation=True,
                             independentAgentAttribution=True,agentTrigger=agent_trigger['outcome']['event'],
                             humanReplyTrigger=human_reply['outcome']['event'],agentAndReplySuppressed=True,
                             restartNoReplay=True,cleanStops=True,revokedGrantRefused=True))
        finally:
            try:
                stop('NativeBotCleanup')
            finally:
                self.deadline = previous_deadline

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
            self.stop(require_clean=True); self.start()
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

    def diagnostics(self):
        suite = self.config.get('suiteBinary') or os.environ.get('HYPERNET_HRC_SUITE_BINARY')
        if not suite:
            self.record(dict(case='NativeCompanionDiagnostics',available=False,reason='SuiteBinaryNotConfigured'))
            return
        until = min(self.deadline, time.monotonic()+6)
        for name, companion in self.config['companions'].items():
            remaining = until-time.monotonic()
            if remaining <= 0:
                break
            item = dict(case='NativeCompanionDiagnostics',principal=name,
                        observedBootMs=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000)
            try:
                result = subprocess.run([str(suite),'streams','status','--directory',companion['directory']],
                                        capture_output=True,timeout=min(2,remaining))
                item['exitCode'] = result.returncode
                assert len(result.stdout) <= 16384 and len(result.stderr) <= 16384
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    assert isinstance(status,dict)
                    errors = status.get('recentErrors',[])
                    assert isinstance(errors,list) and len(errors) <= 8
                    assert all(isinstance(e,dict) for e in errors)
                    item['recentErrors'] = [dict(bootMs=e.get('bootMs'),
                                                message=str(e.get('message',''))[:256]) for e in errors]
                    item['connections'] = len(status.get('connections',[]))
                    item['status'] = status.get('status')
                else:
                    item['available'] = False
            except (OSError, subprocess.TimeoutExpired, ValueError, AssertionError) as error:
                item.update(available=False,error=type(error).__name__)
            self.record(item)


def run(configuration, controls, record):
    workflow = Conversation(configuration, controls, record)
    try:
        workflow.main()
    except Exception:
        try:
            workflow.diagnostics()
        except Exception as error:
            record(dict(case='NativeCompanionDiagnostics',available=False,error=type(error).__name__))
        raise
    else:
        workflow.stop(require_clean=True)
    finally:
        workflow.stop()
