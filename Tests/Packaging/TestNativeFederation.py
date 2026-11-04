# SPDX-License-Identifier: Apache-2.0
"""The native federation driver drains bounded evidence while servicing controls."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'NativeFederation', ROOT / 'Tests/Integration/NativeFederation.py')
federation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(federation)


class FederationOutput(unittest.TestCase):
    def child(self, source, *arguments):
        # Force each successful output below 64 KiB to exceed actual pipe capacity.
        process = subprocess.Popen([sys.executable, '-c', source, *map(str, arguments)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pipesize=4096)
        self.addCleanup(self.reap, process)
        return process

    @staticmethod
    def reap(process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for pipe in (process.stdout, process.stderr):
            pipe.close()

    def test_each_pipe_drains_beyond_capacity_while_controls_advance(self):
        for descriptors in ('1', '2', '1,2'):
            with self.subTest(descriptors=descriptors), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                process = self.child('''
import os,sys,time
from pathlib import Path
root=Path(sys.argv[1])
for descriptor in map(int,sys.argv[2].split(',')):
    data=bytes([64+descriptor])*60000
    while data:
        data=data[os.write(descriptor,data):]
(root/'ready').touch()
end=time.monotonic()+8
while not (root/'ack').exists():
    if time.monotonic()>=end: raise RuntimeError('control not serviced')
    time.sleep(.01)
''', root, descriptors)
                controls, records = [], []
                def control(child):
                    controls.append(child.pid)
                    if (root/'ready').exists():
                        (root/'ack').touch()
                output, errors = federation.collect_helper(
                    process, time.monotonic()+10, control, records.append, 'client')
                self.assertEqual(output, b'A'*60000 if '1' in descriptors else b'')
                self.assertEqual(errors, b'B'*60000 if '2' in descriptors else b'')
                self.assertTrue(controls)
                self.assertTrue((root/'ack').exists())
                self.assertEqual(process.returncode, 0)
                self.assertEqual(len(records), 1)
                self.assertTrue(records[0]['outputComplete'])
                self.assertFalse(records[0]['stdoutTruncated'])
                self.assertFalse(records[0]['stderrTruncated'])

    def test_independent_stream_overflow_is_bounded_and_reaped(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor):
                process = self.child('''
import os,sys,time
fd=int(sys.argv[1])
os.write(3-fd,b'other-stream-marker')
while True: os.write(fd,b'X'*4096)
''', descriptor)
                records = []
                with self.assertRaisesRegex(AssertionError, 'output limit'):
                    federation.collect_helper(process, time.monotonic()+10,
                        lambda _: None, records.append, 'client')
                self.assertIsNotNone(process.returncode)
                self.assertEqual(len(records), 1)
                selected, other = ('stdout','stderr') if descriptor == 1 else ('stderr','stdout')
                self.assertEqual(records[0][selected], 'X'*65536)
                self.assertTrue(records[0][selected+'Truncated'])
                self.assertEqual(records[0][other], 'other-stream-marker')
                self.assertFalse(records[0][other+'Truncated'])

    def test_timeout_retains_both_outputs_and_reaps_child(self):
        process = self.child('''
import os,time
os.write(1,b'partial result')
os.write(2,b'last completed step')
time.sleep(30)
''')
        records = []
        with self.assertRaisesRegex(AssertionError, 'Federation helper deadline'):
            federation.collect_helper(process, time.monotonic()+1,
                lambda _: None, records.append, 'client')
        self.assertIsNotNone(process.returncode)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['stdout'], 'partial result')
        self.assertEqual(records[0]['stderr'], 'last completed step')
        self.assertTrue(records[0]['outputComplete'])

    def test_control_error_is_preserved_with_its_output(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/'ready'
            process = self.child('''
import os,sys,time
from pathlib import Path
os.write(1,b'partial result')
os.write(2,b'control requested')
Path(sys.argv[1]).touch()
time.sleep(30)
''', marker)
            original = ValueError('original control refusal')
            def control(_):
                if marker.exists():
                    raise original
            records = []
            with self.assertRaises(ValueError) as raised:
                federation.collect_helper(process, time.monotonic()+10,
                    control, records.append, 'client')
            self.assertIs(raised.exception, original)
            self.assertIsNotNone(process.returncode)
            self.assertEqual(records[0]['stdout'], 'partial result')
            self.assertEqual(records[0]['stderr'], 'control requested')
            self.assertEqual(len(records), 1)


if __name__ == '__main__':
    unittest.main()
