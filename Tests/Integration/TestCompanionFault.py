# SPDX-License-Identifier: Apache-2.0
"""The fault injector preserves opaque metadata and drops exactly one response."""
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location('CompanionFault',Path(__file__).with_name('CompanionFault.py'))
fault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fault)


class FaultBoundary(unittest.TestCase):
    def test_exact_context_and_payload_then_one_lost_response(self):
        with tempfile.TemporaryDirectory(prefix='hrc-fault-') as root:
            root=Path(root)
            visible=root/'Visible';actual=root/'Actual'
            visible.mkdir(mode=0o700);actual.mkdir(mode=0o700)
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(actual/'Control.sock'));(actual/'Control.sock').chmod(0o600)
            listener.listen(1);listener.settimeout(3)
            request=b'{"version":2,"action":"connect","timeoutMs":1000,"service":"opaque"}'
            metadata=b'{"version":2,"ok":true,"id":"opaque","peer":{"unmodified":"context"}}'
            ready=(3).to_bytes(4,'big')+b'\x04\x81\x00'
            response=(3).to_bytes(4,'big')+b'\x06\x81\x01'
            observed=[]
            def upstream():
                with listener.accept()[0] as stream:
                    stream.settimeout(3)
                    observed.append(fault.exact(stream,4+len(request)))
                    stream.sendall(len(metadata).to_bytes(4,'big')+metadata)
                    observed.append(fault.exact(stream,9))
                    stream.sendall(ready+response)
            worker=threading.Thread(target=upstream)
            worker.start()
            proxy=fault.DropResponseProxy(visible,actual)
            try:
                proxy.arm()
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3);client.connect(str(visible/'Control.sock'))
                    client.sendall(len(request).to_bytes(4,'big')+request)
                    self.assertEqual(fault.exact(client,4+len(metadata)),len(metadata).to_bytes(4,'big')+metadata)
                    client.sendall(b'raw bytes')
                    self.assertEqual(fault.exact(client,len(ready)),ready)
                    self.assertEqual(client.recv(1),b'')
                self.assertTrue(proxy.dropped.wait(1))
                self.assertEqual(proxy.evidence['bytes'],len(response))
                self.assertEqual(proxy.errors,[])
            finally:
                proxy.close();listener.close();worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(observed,[len(request).to_bytes(4,'big')+request,b'raw bytes'])


if __name__=='__main__':
    unittest.main()
