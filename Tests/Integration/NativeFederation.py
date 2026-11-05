# SPDX-License-Identifier: Apache-2.0
"""Two administered networks: shipped setup CLI plus the real client API helper.

Only initial, explicitly approved identity imports are performed here. Running
origin lifecycle propagation must establish every later encrypted-room barrier.
"""
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import stat
import sys
import threading
import time

_spec = importlib.util.spec_from_file_location('HrcNativeConversation', Path(__file__).with_name('NativeConversation.py'))
_conversation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_conversation)
Conversation, address = _conversation.Conversation, _conversation.address


def collect_helper(process, end, control, record, case):
    """Drain this owned child while controls run, retaining bounded failure evidence."""
    limit = 65536
    pipes = (process.stdout, process.stderr)
    captured = (bytearray(), bytearray())
    truncated, eof = [False, False], [False, False]
    stop, failed = threading.Event(), threading.Event()
    read_errors = []

    def drain():
        try:
            with selectors.DefaultSelector() as selector:
                for index, pipe in enumerate(pipes):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, index)
                while selector.get_map() and not stop.is_set():
                    for key, _ in selector.select(.05):
                        index = key.data
                        try:
                            data = os.read(key.fd, 4096)
                        except BlockingIOError:
                            continue
                        if not data:
                            eof[index] = True
                            selector.unregister(key.fileobj)
                            continue
                        left = limit - len(captured[index])
                        captured[index].extend(data[:left])
                        if len(data) > left:
                            truncated[index] = True
                            failed.set()
                            # Excess output is a terminal helper failure, including while
                            # a bounded control callback is still finishing its own work.
                            try:
                                process.kill()
                            except ProcessLookupError:
                                pass
        except BaseException as error:
            read_errors.append(error)
            failed.set()

    reader = threading.Thread(target=drain, name='hrc-federation-output', daemon=True)
    failure, traceback, cleanup_errors = None, None, []
    started = False
    try:
        reader.start()
        started = True
        while process.poll() is None:
            if failed.is_set():
                assert not any(truncated), 'Federation helper output limit'
                raise AssertionError('Federation helper output incomplete')
            assert time.monotonic() < end, 'Federation helper deadline'
            control(process)
            failed.wait(min(.1, max(0, end-time.monotonic())))
    except BaseException as error:
        failure, traceback = error, sys.exc_info()[2]
    finally:
        if process.poll() is None:
            try:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            except BaseException as error:
                cleanup_errors.append(error)
        if started:
            reader.join(timeout=5)
            stop.set()
            reader.join(timeout=1)
        for pipe in pipes:
            try:
                pipe.close()
            except BaseException as error:
                cleanup_errors.append(error)

    output, errors = map(bytes, captured)
    item = dict(case=case, exitCode=process.returncode,
        stdout=output.decode(errors='replace'), stderr=errors.decode(errors='replace'),
        stdoutTruncated=truncated[0] or not eof[0], stderrTruncated=truncated[1] or not eof[1],
        outputComplete=all(eof))
    try:
        record(item)
    except BaseException as error:
        cleanup_errors.append(error)
    # Preserve the original control/timeout exception even if draining or cleanup fails.
    if failure is not None:
        for error in [*read_errors, *cleanup_errors]:
            failure.add_note('Helper cleanup: '+type(error).__name__)
        raise failure.with_traceback(traceback)
    if cleanup_errors:
        raise cleanup_errors[0]
    assert not any(truncated), 'Federation helper output limit'
    assert not read_errors and all(eof), 'Federation helper output incomplete'
    assert time.monotonic() < end, 'Federation helper deadline'
    return output, errors


def run(configuration, controls, record):
    root = Path(configuration['directory'])
    root.mkdir(mode=0o700)
    end = time.monotonic() + configuration['maximumSeconds']
    helper = Path(os.environ['HRC_NATIVE_FEDERATION_CLIENT']).resolve(strict=True)
    assert os.access(helper, os.X_OK)
    # Reuse the maintained process/CLI owner; do not repeat the HyperNet fixture.
    def local(name, peer):
        return Conversation(dict(binary=configuration['binary'], directory=str(root/name),
            home=peer['home'], clock=configuration['clock'], maximumSeconds=configuration['maximumSeconds']), {}, record)
    home, origin = local('Home', configuration['home']), local('Origin', configuration['origin'])
    try:
        descriptors, accounts, actors = {}, {}, {}
        for name, flow, peer in (('Home', home, configuration['home']), ('Origin', origin, configuration['origin'])):
            service = peer['home']
            descriptors[name] = flow.cli(name+'ServiceCreated', 'service', 'init', '--directory', flow.service,
                '--network', service['network']['network'], '--incarnation', service['network']['incarnation'],
                '--service', service['service'], *flow.clock(peer['companion']))
            assert descriptors[name]['home'] == service
        peers = {'Alice':(home,configuration['home']), 'Bob':(origin,configuration['origin']), 'Agent':(origin,configuration['agent'])}
        assert len({peer['principal'] for _,peer in peers.values()}) == 3
        for name, (flow, peer) in peers.items():
            invitation, registration = flow.exchange/(name+'.json'), flow.exchange/(name+'.cbor')
            args = ['service','invite','--directory',flow.service,'--principal',peer['principal'],'--output',invitation]
            if name == 'Agent':
                args += ['--operator',address(accounts['Bob'])]
            flow.cli(name+'Invited', *args)
            profile = flow.root/name
            created = flow.cli(name+'ProfileCreated','profile','create','--directory',profile,
                '--invitation',invitation,'--recovery-key-file',flow.recovery/(name+'.key'),
                '--registration-output',registration,*flow.clock(peer['companion']))
            accounts[name] = created['account']
            flow.cli(name+'Enrolled','service','enrol','--directory',flow.service,'--registration',registration)
            flow.profiles[name] = profile
        home.start(); origin.start()
        for name,(flow,_) in peers.items():
            actors[name] = flow.session(name)['acting']
        origin.outcome(origin.api('Bob',1,{'kind':'account','id':accounts['Bob']},{'nickname':'OriginBob'}))
        home.stop(); origin.stop()
        home_descriptor, origin_descriptor = home.json_file(descriptors['Home']), home.json_file(descriptors['Origin'])
        keys = {}
        for name in ('HomeGateway','OriginGateway','Attestor'):
            path = home.recovery/(name+'.key')
            keys[name] = (path,home.cli(name+'KeyCreated','federation','key-create','--output',path)['publicKey'])
        def gateway(peer, receiving, key):
            return dict(network=receiving['home']['network'],destination=receiving['home'],
                principal=peer['principal'],serviceEndpoint=receiving['endpoint'],signingKey=key,protocol='hrc/1')
        # Consent covers the original whole fixture, including withdrawal checks;
        # this allowance never extends the process or operation deadlines.
        expiry = int(time.time()*1000) + int((end-time.monotonic())*1000) + 10000
        agreement = dict(profile=1,id=os.urandom(32).hex(),revision=1,home=home.home,origin=origin.home,
            homeGateway=gateway(configuration['toHome'],configuration['home'],keys['HomeGateway'][1]),
            originGateway=gateway(configuration['toOrigin'],configuration['origin'],keys['OriginGateway'][1]),
            homeServiceKey=descriptors['Home']['signingKey'],originServiceKey=descriptors['Origin']['signingKey'],
            originAttestorKey=keys['Attestor'][1],rooms=[],notBeforeMs=int(time.time()*1000)-3000,expiresMs=expiry)
        pins = home.json_file(dict(home=home.home,origin=origin.home,homeKey=agreement['homeServiceKey'],
            originKey=agreement['originServiceKey'],originAttestor=agreement['originAttestorKey']))
        admissions = {}
        def accept_and_import(rooms):
            proposal = home.json_file(agreement)
            signatures = [home.exchange/('Home'+str(agreement['revision'])+'.cbor'),home.exchange/('Origin'+str(agreement['revision'])+'.cbor')]
            references = []
            for flow,path in zip((home,origin),signatures):
                references.append(flow.cli('SignBilateralProposal','federation','sign','--directory',flow.service,
                    '--agreement',proposal,'--output',path)['agreement'])
            assert references[0] == references[1]
            reference = references[0]
            ref_file = home.json_file(reference)
            for flow in (home,origin):
                state = flow.cli('AcceptIndependentPins','federation','accept','--directory',flow.service,
                    '--home-signature',signatures[0],'--origin-signature',signatures[1],'--pins',pins)
                assert state['reference'] == reference and not state['withdrawn']
            for name in ('Bob','Agent'):
                cp_path = home.exchange/(name+'Checkpoint'+str(agreement['revision'])+'.cbor')
                cp = origin.cli('Export'+name+'Checkpoint','federation','checkpoint','--directory',origin.service,
                    '--agreement',ref_file,'--account',address(accounts[name]),'--output',cp_path)
                after = 0
                for page_number in range(256):
                    page_path = home.exchange/(name+'Page'+str(agreement['revision'])+'-'+str(page_number)+'.cbor')
                    page = origin.cli('ExportBoundedIdentityPage','federation','identity-page','--directory',origin.service,
                        '--agreement',ref_file,'--checkpoint',cp['checkpoint'],'--after',after,'--limit',4,'--output',page_path)
                    imported = home.cli('ImportExplicitOriginAnchor','federation','import-identity','--directory',home.service,
                        '--agreement',ref_file,'--checkpoint',cp_path,'--page',page_path,'--trust-anchor',cp['anchor'])
                    assert imported['complete'] == page['complete']
                    if page['complete']:
                        break
                    assert page['next'] > after
                    after = page['next']
                else:
                    raise AssertionError('Identity page bound')
                request = dict(agreement=reference,account=accounts[name],endpoint=actors[name]['endpoint'],
                    bindingDigest=actors[name]['bindingDigest'],checkpoint=cp['checkpoint'],rooms=rooms,
                    expiresMs=expiry,expectedRevision=admissions.get(name,{}).get('reference',{}).get('revision',0))
                admissions[name] = home.cli('AdmitExact'+name+'Endpoint','federation','admit','--directory',home.service,
                    '--request',home.json_file(request))
                assert admissions[name]['acting'] == actors[name] and not admissions[name]['withdrawn']
            return reference,ref_file,signatures
        # Setup-only consent admits identities but gives no conversation access.
        accept_and_import([])
        home.start()
        community = home.room('Federated community')
        private = home.outcome(home.cli('CreatePrivateGroup','room','create','--profile',home.profiles['Alice'],
            '--name','Federated private group','--private'))['room']
        direct = home.outcome(home.cli('CreateForeignDirect','room','direct','--profile',home.profiles['Alice'],
            '--recipient',address(accounts['Bob'])))['room']
        home.outcome(home.cli('InviteForeignHuman','room','invite','--profile',home.profiles['Alice'],
            '--room',address(private),'--account',address(accounts['Bob'])))
        home.stop()
        agreement['revision'] = 2
        agreement['rooms'] = [dict(room=room,historyFromMs=0,retentionMs=30*86400000,storage='homeOnly',
            confidentiality=mode,privacy='supportedHyperNetRoute',moderatorAccounts=[])
            for room,mode in ((community,'community'),(private,'privateGroup'),(direct,'confidentialDirect'))]
        reference,reference_file,signatures = accept_and_import([community,private,direct])
        routes = origin.json_file([dict(agreement=reference,companion=configuration['toHome']['companion'],
            gatewayKey=str(keys['HomeGateway'][0]),attestorKey=str(keys['Attestor'][0]))])
        origin.cli('InstallExplicitDestinationCompanion','federation','routes-install','--directory',origin.service,'--configuration',routes)
        for name,(flow,_) in peers.items():
            args = ['federation','client-select','--directory',flow.profiles[name],
                '--home-descriptor',home_descriptor,'--origin-descriptor',origin_descriptor,
                '--home-signature',signatures[0],'--origin-signature',signatures[1]]
            if name == 'Alice':
                args += ['--trust-only']
            flow.cli(name+'SelectBilateralService',*args)
        home.start(); origin.start()
        request = home.json_file(dict(alice=str(home.profiles['Alice']),bob=str(origin.profiles['Bob']),
            agent=str(origin.profiles['Agent']),community=community,private=private,direct=direct,
            originDescriptor=str(origin_descriptor),bobRecovery=str(origin.recovery/'Bob.key'),
            controls=str(root/'Controls')))
        controls_path = root/'Controls'; controls_path.mkdir(mode=0o700)
        remaining = min(900,int(end-time.monotonic())-120)
        assert remaining >= 180, 'Insufficient bounded client qualification time'
        handled = set()
        gateway_samples, sample_failures, next_sample = {}, 0, time.monotonic()
        def private_json(path, maximum):
            information = path.lstat()
            assert stat.S_ISREG(information.st_mode) and information.st_uid == os.geteuid()
            assert information.st_mode & 0o777 == 0o600 and information.st_size <= maximum
            return json.loads(path.read_bytes())
        def stop_for_admission():
            home.stop()
            origin.stop()
        def admit_recovered():
            assert home.server is None and origin.server is None
            actor = private_json(controls_path/'RecoveredEndpoint.json',8192)
            assert actor['account'] == accounts['Bob'] and actor['endpoint'] != actors['Bob']['endpoint']
            assert actor['securityGeneration'] == actors['Bob']['securityGeneration']+1
            # The running origin has already established the home recovery barrier.
            # Export only its exact checkpoint identifier; never import pages here.
            cp = origin.cli('ExportAutomaticallyPropagatedRecoveryCheckpoint','federation','checkpoint',
                '--directory',origin.service,'--agreement',reference_file,'--account',address(accounts['Bob']),
                '--output',home.exchange/'RecoveredCheckpoint.cbor')
            assert cp['checkpoint'] != admissions['Bob']['checkpoint']
            proposed = dict(agreement=reference,account=accounts['Bob'],endpoint=actor['endpoint'],
                bindingDigest=actor['bindingDigest'],checkpoint=cp['checkpoint'],rooms=[community,private,direct],
                expiresMs=expiry,expectedRevision=0)
            admitted = home.cli('ExplicitRecoveredForeignAdmission','federation','admit',
                '--directory',home.service,'--request',home.json_file(proposed))
            assert admitted['acting'] == actor and not admitted['withdrawn']
            assert admitted['checkpoint'] == cp['checkpoint'] and admitted['rooms'] == proposed['rooms']
            assert admitted['reference']['id'] != admissions['Bob']['reference']['id']
            assert admitted['reference']['revision'] == 1
            home.cli('SelectRecoveredBilateralProfile','federation','client-select',
                '--directory',controls_path/'RecoveredBob','--home-descriptor',home_descriptor,
                '--origin-descriptor',origin_descriptor,'--home-signature',signatures[0],
                '--origin-signature',signatures[1])
            receipt = controls_path/'RecoveredAdmission.json'
            with receipt.open('x') as output:
                receipt.chmod(0o600)
                json.dump(admitted,output)
            record(dict(case='RecoveredForeignEndpointExplicitlyAdmitted',passed=True,
                sameAccount=True,automaticallyImportedCheckpoint=True,manualIdentityImports=0))
        def resume_after_admission():
            home.start()
            origin.start()
        operations = {'PauseOrigin':origin.stop,'ResumeOrigin':origin.start,
            'StopForRecoveredAdmission':stop_for_admission,'AdmitRecoveredBob':admit_recovered,
            'ResumeAfterRecoveredAdmission':resume_after_admission}
        def poll_controls(process):
            nonlocal sample_failures, next_sample
            for name,action in operations.items():
                marker = controls_path/(name+'.request')
                if marker.exists() and name not in handled:
                    request_control = private_json(marker,256)
                    assert set(request_control) == {'version','deadlineBootMs'} and request_control['version'] == 1
                    boot_ms = lambda: time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000
                    remaining_ms = request_control['deadlineBootMs']-boot_ms()
                    assert 0 < remaining_ms <= 45000
                    # CLI mutations share the helper's original step deadline. No new
                    # request identity or authority interval is created by this control.
                    saved_deadlines = (home.deadline,origin.deadline)
                    for flow in (home,origin):
                        flow.deadline = min(flow.deadline,time.monotonic()+remaining_ms/1000)
                    try:
                        action()
                    finally:
                        home.deadline,origin.deadline = saved_deadlines
                    assert boot_ms() < request_control['deadlineBootMs'] and process.poll() is None
                    handled.add(name)
                    ack = controls_path/(name+'.done')
                    with ack.open('xb') as output:
                        ack.chmod(0o600); output.write(b'HRC/1\n')
            if time.monotonic() >= next_sample:
                try:
                    identifiers = controls['sample_gateway']()
                    assert len(identifiers) <= 16
                    for identifier in identifiers:
                        gateway_samples[identifier] = gateway_samples.get(identifier,0)+1
                except (OSError,RuntimeError,ValueError):
                    sample_failures += 1
                next_sample = time.monotonic()+2
        process = subprocess.Popen([str(helper),'--request',str(request),'--maximum-seconds',str(remaining)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output,_ = collect_helper(process,end,poll_controls,record,'NativeFederationClient')
        assert process.returncode == 0
        result = json.loads(output)
        assert result['status'] == 'Passed' and handled == set(operations)
        assert any(count >= 3 for count in gateway_samples.values()), 'No observed gateway connection reuse'
        record(dict(case='ObservedGatewayConnectionReuse',passed=True,
            distinctSampledConnections=len(gateway_samples),samplesPerConnection=sorted(gateway_samples.values()),
            unavailableSamples=sample_failures,completeConnectionCensus=False,concurrentLimit=16,voucherConnectionLimit=128))
        # The origin's local stop and actual destination acknowledgement are separate effects.
        origin.stop()
        withdrawal = origin.cli('WithdrawAndNotifyHome','federation','withdraw','--directory',origin.service,
            '--agreement',reference_file)
        assert withdrawal['status'] == 'HomeWithdrawalAcknowledged' and withdrawal['homeBarrier'] is not None
        origin.start()
        withdrawal_end = min(end,time.monotonic()+65)
        refused = subprocess.Popen([str(helper),'--request',str(request),'--maximum-seconds','60','--withdrawal'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output,_ = collect_helper(refused,withdrawal_end,lambda _: None,record,'NativeFederationWithdrawal')
        assert refused.returncode == 0 and json.loads(output)['agreementWithdrawn']
        home.stop()
        inspected = home.cli('InspectHomeWithdrawal','federation','inspect','--directory',home.service,'--agreement',reference_file)
        assert inspected['withdrawn'] and inspected['barrierPosition'] == withdrawal['homeBarrier']
        record(dict(case='ActualBilateralWithdrawal',passed=True,homeBarrier=withdrawal['homeBarrier']))
    finally:
        original_error = sys.exc_info()[1]
        failures = []
        for flow in (origin,home):
            try:
                flow.stop()
            except BaseException as error:
                failures.append(type(error).__name__+': '+str(error))
        if failures:
            message = 'HRC federation service cleanup: '+'; '.join(failures)
            if original_error is None:
                raise RuntimeError(message)
            original_error.add_note(message)
