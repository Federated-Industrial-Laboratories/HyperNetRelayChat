# SPDX-License-Identifier: Apache-2.0
"""Protect the native driver's stopped switch and exact pending-outcome checks."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'NativeConversation', ROOT / 'Tests/Integration/NativeConversation.py')
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


class StoppedUpgrade(unittest.TestCase):
    def selector(self, old, **configuration):
        workflow = NATIVE.Conversation.__new__(NATIVE.Conversation)
        workflow.binary = str(old)
        workflow.config = configuration
        return workflow

    def test_explicit_selection_refuses_invalid_or_conflicting_targets(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            root = Path(temporary)
            old, new = root / 'old', root / 'new'
            old.write_bytes(b'old executable'); old.chmod(0o700)
            new.write_bytes(b'new executable'); new.chmod(0o700)
            workflow = self.selector(old, upgradeBinary=str(new))
            target, old_hash, new_hash = workflow.upgrade_selection()
            self.assertEqual(target, str(new))
            self.assertNotEqual(old_hash, new_hash)
            self.assertIsNone(self.selector(old).upgrade_selection())
            for invalid in ('', None, str(old), str(root / 'missing')):
                with self.subTest(target=invalid), self.assertRaises((AssertionError, FileNotFoundError)):
                    self.selector(old, upgradeBinary=invalid).upgrade_selection()
            new.chmod(0o600)
            with self.assertRaisesRegex(AssertionError, 'unavailable'):
                workflow.upgrade_selection()
            new.chmod(0o700)
            with patch.dict(os.environ, {'HRC_NATIVE_UPGRADE_BINARY': str(old)}):
                with self.assertRaisesRegex(AssertionError, 'Conflicting'):
                    workflow.upgrade_selection()
            for key in ('loadOnly', 'localClientOnly', 'confidentialClientOnly',
                        'localClientBinary', 'confidentialClientBinary'):
                with self.subTest(selector=key), self.assertRaisesRegex(AssertionError, 'independent'):
                    self.selector(old, upgradeBinary=str(new), **{key: True}).upgrade_selection()
            for key in ('HRC_NATIVE_LOAD_ONLY', 'HYPERNET_HRC_LOCAL_CLIENT_ONLY',
                        'HRC_NATIVE_CONFIDENTIAL_ONLY'):
                with self.subTest(selector=key), patch.dict(os.environ, {key: '1'}):
                    with self.assertRaisesRegex(AssertionError, 'independent'):
                        workflow.upgrade_selection()
            with patch.dict(os.environ, {'HRC_NATIVE_UPGRADE_BINARY': str(new)}):
                self.assertEqual(self.selector(old).upgrade_selection()[0], str(new))
            new.write_bytes(old.read_bytes())
            with self.assertRaisesRegex(AssertionError, 'different executable bytes'):
                workflow.upgrade_selection()

    def acknowledgement(self, clean=True):
        workflow = NATIVE.Conversation.__new__(NATIVE.Conversation)
        workflow.binary, workflow.home = 'old', {'service': 'home'}
        workflow.profiles = {'Bob': 'Bob'}
        pending = dict(operationId={'window': 'window', 'operation': 'original'}, actionDigest='digest',
                       held=False, abandoned=False)
        event = dict(event='committed-event', operationId=pending['operationId'], actionDigest='digest')
        result = dict(home=workflow.home, outcome=dict(status='result', body=dict(
            operationId=pending['operationId'], actionDigest='digest',
            outcome=dict(status='committed', event=event['event']))))
        values = dict(PendingAfterAckLoss=[pending], ResolveAfterRestart=[result], ResolveAgain=[], OutboxResolved=[])
        trace = []
        proxy = Mock(evidence={'dropped': True})
        proxy.dropped.wait.return_value = True
        workflow.controls = dict(begin_ack_loss=Mock(return_value=proxy), end_ack_loss=Mock())
        workflow.record = Mock()
        workflow.server = Mock(returncode=0 if clean else 1)
        workflow.server.poll.return_value = None
        workflow.server.communicate.return_value = (b'{"status":"Stopped"}', b'')
        workflow.server.terminate.side_effect = lambda: trace.append('stop')
        workflow.send = Mock()
        workflow.events = Mock(return_value=[event])
        workflow.start = Mock(side_effect=lambda: trace.append('start:' + workflow.binary))

        def cli(name, *_args):
            trace.append(name + ':' + workflow.binary)
            return copy.deepcopy(values[name])

        workflow.cli = cli

        def stopped(saved):
            self.assertIsNone(workflow.server)
            self.assertEqual(saved, pending)
            trace.append('switch')
            workflow.binary = 'new'

        return workflow, values, trace, stopped

    def test_unclean_stop_never_switches_or_resolves_and_restores_fault(self):
        workflow, _, trace, stopped = self.acknowledgement(clean=False)
        with self.assertRaisesRegex(AssertionError, 'orderly shutdown'):
            workflow.acknowledgement_loss('room', stopped=stopped)
        self.assertEqual(workflow.binary, 'old')
        self.assertNotIn('switch', trace)
        workflow.start.assert_not_called()
        self.assertFalse(any(item.startswith('Resolve') for item in trace))
        workflow.controls['end_ack_loss'].assert_called_once()

    def test_stopped_switch_precedes_restart_and_exact_resolution(self):
        workflow, _, trace, stopped = self.acknowledgement()
        workflow.acknowledgement_loss('room', stopped=stopped)
        self.assertEqual(trace, ['PendingAfterAckLoss:old', 'stop', 'switch', 'start:new',
                                'ResolveAfterRestart:new', 'ResolveAgain:new', 'OutboxResolved:new'])
        workflow.controls['end_ack_loss'].assert_called_once()

    def test_substituted_or_unresolved_outcome_cannot_qualify(self):
        for field in ('operationId', 'actionDigest', 'event', 'status', 'home', 'second', 'duplicate'):
            with self.subTest(field=field):
                workflow, values, _, stopped = self.acknowledgement()
                response = values['ResolveAfterRestart'][0]
                original = response['outcome']['body']
                if field in ('operationId', 'actionDigest'):
                    original[field] = 'substitution'
                elif field in ('event', 'status'):
                    original['outcome'][field] = 'substitution'
                elif field == 'home':
                    response['home'] = 'substitution'
                elif field == 'second':
                    values['ResolveAgain'] = [response]
                else:
                    before = workflow.events.return_value
                    workflow.events.side_effect = [before, before * 2]
                with self.assertRaises(AssertionError):
                    workflow.acknowledgement_loss('room', stopped=stopped)
                workflow.controls['end_ack_loss'].assert_called_once()


if __name__ == '__main__':
    unittest.main()
