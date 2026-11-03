# SPDX-License-Identifier: Apache-2.0
"""Provision actual pilot endpoints, sample service resources and retain bounded load results."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time


def _address(account):
    origin = account['origin']
    return ':'.join((origin['network'], origin['incarnation'], account['local']))


def _sample(pid):
    values = {}
    for line in Path('/proc', str(pid), 'status').read_text().splitlines():
        name, _, value = line.partition(':')
        if name == 'VmRSS':
            values['rssBytes'] = int(value.split()[0]) * 1024
        elif name == 'Threads':
            values['threads'] = int(value)
    assert set(values) == {'rssBytes', 'threads'}, 'Service resource sample unavailable'
    return values


def run(workflow, executable):
    binary = Path(executable).resolve(strict=True)
    companions = workflow.config['companions']
    assert len({v['principal'] for v in companions.values()}) == 3
    descriptor = workflow.cli('LoadServiceCreated', 'service', 'init', '--directory', workflow.service,
        '--network', workflow.home['network']['network'], '--incarnation', workflow.home['network']['incarnation'],
        '--service', workflow.home['service'], *workflow.clock(companions['Alice']['directory']))
    assert descriptor['home'] == workflow.home
    accounts = {}
    # The operators must exist before their independently identified agents are invited.
    names = ['O0', 'O1'] + ['U'+str(i) for i in range(8)] + ['A0', 'A1']
    for name in names:
        companion = companions['Agent' if name.startswith('A') else 'Bob']
        invitation = workflow.exchange / (name+'Invitation.json')
        registration = workflow.exchange / (name+'Registration.cbor')
        profile = workflow.root / name
        arguments = ['service', 'invite', '--directory', workflow.service,
                     '--principal', companion['principal'], '--output', invitation]
        if name.startswith('A'):
            arguments += ['--operator', _address(accounts['O'+name[1]])]
        workflow.cli(name+'LoadInvited', *arguments)
        created = workflow.cli(name+'LoadProfileCreated', 'profile', 'create', '--directory', profile,
            '--invitation', invitation, '--recovery-key-file', workflow.recovery/(name+'.key'),
            '--registration-output', registration, *workflow.clock(companion['directory']))
        enrolled = workflow.cli(name+'LoadEnrolled', 'service', 'enrol', '--directory', workflow.service,
                                '--registration', registration)
        assert enrolled['account'] == created['account']
        accounts[name] = created['account']
        workflow.profiles[name] = profile
    assert len({json.dumps(a, sort_keys=True) for a in accounts.values()}) == 12
    workflow.start()
    ordered = ['U'+str(i) for i in range(8)] + ['A0', 'A1', 'O0', 'O1']
    request = workflow.json_file({'profiles': [str(workflow.profiles[n]) for n in ordered]})
    remaining = workflow.deadline - time.monotonic()
    assert remaining > 390, 'Insufficient original workflow budget for bounded load helper and cleanup'
    workflow.record(dict(case='NativeLoadTopology', interactiveEndpoints=8, agentEndpoints=2,
        plannedProductionControllers=8, controllerBackgroundRefresh=True,
        interactiveSetupUsesProductionControllers=True, temporaryInteractiveStreams=0,
        readinessHealthBlocksObservation=False,
        operatorEndpoints=2, measuredModerators=1, distinctHrcAccounts=12,
        distinctClientHyperNetPrincipals=2, sharedClientApplications=True,
        receivingApplicationStreams=12, outgoingStreamsByApplication={'Bob': 10, 'Agent': 2},
        unoccupiedReservedSlots={'transition': 2, 'federation': 2},
        simultaneousFederationQualified=False, sourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        executableSha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
    process = subprocess.Popen([str(binary), '--request', str(request), '--maximum-seconds', '360'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    for name in buffers:
        pipe = getattr(process, name)
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    deadline = min(workflow.deadline-20, time.monotonic()+365)
    rss_peak = threads_peak = samples = 0
    totals = {'stdout': 0, 'stderr': 0}
    summary = None
    phase = 'startup'
    failure = None
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise AssertionError('Native load helper original deadline expired')
            sample = _sample(workflow.server.pid)
            samples += 1
            rss_peak = max(rss_peak, sample['rssBytes'])
            threads_peak = max(threads_peak, sample['threads'])
            for key, _ in selector.select(timeout=0.2):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                totals[name] += len(chunk)
                assert totals[name] <= (1024*1024 if name == 'stdout' else 65536), 'Load output bound'
                buffers[name].extend(chunk)
                if name == 'stdout':
                    while b'\n' in buffers[name]:
                        line, _, rest = buffers[name].partition(b'\n')
                        buffers[name] = bytearray(rest)
                        item = json.loads(line)
                        assert isinstance(item, dict) and 'case' in item
                        phase = item.get('phase', phase)
                        workflow.record(item)
                        if item['case'] == 'NativeLoadSummary':
                            summary = item
        process.wait(timeout=5)
    except Exception as error:
        failure = str(error)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        selector.close()
        workflow.record(dict(case='NativeLoadResources', servicePid=workflow.server.pid,
            sampleIntervalMs=200, samples=samples, peakRssBytes=rss_peak, peakThreads=threads_peak,
            rssLimitBytes=512*1024*1024, rssPassed=samples > 0 and rss_peak <= 512*1024*1024,
            lastPhase=phase, helperExitCode=process.returncode, failure=failure,
            stderr=buffers['stderr'].decode(errors='replace'),
            incompleteStdout=buffers['stdout'].decode(errors='replace'),
            excludesHyperNetProcesses=True, internalQueueOccupancyMeasured=False,
            linkBytesMeasured=False, deliveryModel='authenticated pull'))
    assert failure is None, failure
    assert summary is not None, 'Missing final load result; partial metrics retained'
    assert process.returncode == 0 and summary['passed'], 'Native load thresholds or contracts failed'
    assert samples > 0 and rss_peak <= 512*1024*1024, 'HRC service exceeded RSS budget'
