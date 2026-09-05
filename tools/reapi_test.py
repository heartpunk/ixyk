"""Regression tests for the local REAPI launcher's execution boundaries."""

from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reapi import (
    bazel_command, configuration, coordinator_configuration, endpoint, main,
    process, state_directory, wait_ready, worker_configuration,
)
import argparse


class ReapiTest(unittest.TestCase):
    def test_configuration_keeps_namespaces_and_loopback(self):
        config = configuration(Path('/tmp/state'), 51001, 51002, 3, '/nix/store/action')
        worker = config['workers'][0]['local']
        self.assertEqual(worker['entrypoint'], '/nix/store/action')
        self.assertNotIn('ghot-nix-contract', worker['platform_properties'])
        self.assertTrue(worker['use_namespaces'])
        self.assertTrue(worker['use_mount_namespace'])
        self.assertEqual(worker['max_inflight_tasks'], 3)
        self.assertEqual(worker['worker_api_endpoint']['uri'], 'grpc://127.0.0.1:51002')
        self.assertEqual(
            [s['listener']['http']['socket_address'] for s in config['servers']],
            ['127.0.0.1:51001', '127.0.0.1:51002'],
        )

    def test_managed_options_override_rc_and_preserve_run_arguments(self):
        command = bazel_command('run', ['//extractor:tool', '--jobs=99', '--', '--help'], 51001, 2)
        self.assertEqual(command[-2:], ['--', '--help'])
        self.assertGreater(command.index('--jobs=2'), command.index('--jobs=99'))
        self.assertIn('--remote_local_fallback=false', command)
        self.assertIn('--remote_executor=grpc://127.0.0.1:51001', command)
        self.assertIn('--spawn_strategy=remote', command)
        with self.assertRaises(ValueError):
            bazel_command('test', [], 51001, 2)

    def test_coordinator_has_no_execution_worker(self):
        config = coordinator_configuration(Path('/tmp/state'), 50051, 50061, '0.0.0.0')
        self.assertNotIn('workers', config)
        self.assertEqual([s['name'] for s in config['stores']], ['CAS', 'AC'])
        self.assertEqual([s['listener']['http']['socket_address'] for s in config['servers']],
                         ['0.0.0.0:50051', '0.0.0.0:50061'])

    def test_worker_fetches_and_uploads_to_shared_coordinator(self):
        config = worker_configuration(Path('/tmp/worker'), 'grpc://hub:50051',
                                      'grpc://hub:50061', 3, '/nix/action')
        self.assertNotIn('schedulers', config)
        self.assertEqual(config['servers'], [])
        for store, kind in zip(config['stores'][:2], ('cas', 'ac')):
            self.assertEqual(store['grpc']['endpoints'], [{'address': 'grpc://hub:50051'}])
            self.assertEqual(store['grpc']['store_type'], kind)
        worker = config['workers'][0]['local']
        self.assertEqual(worker['worker_api_endpoint']['uri'], 'grpc://hub:50061')
        self.assertEqual(worker['max_inflight_tasks'], 3)
        self.assertTrue(worker['use_namespaces'])
        self.assertTrue(worker['use_mount_namespace'])
        self.assertEqual(worker['entrypoint'], '/nix/action')

    def test_remote_client_never_starts_worker_or_checks_namespaces(self):
        with patch('reapi.process') as launch, patch('reapi.check_namespaces') as namespaces:
            launch.return_value.__enter__.return_value.wait.return_value = 0
            self.assertEqual(main(['--nativelink', 'unused', '--entrypoint', 'unused',
                                   '--endpoint', 'grpc://hub:50051', 'test', '//:target']), 0)
            namespaces.assert_not_called()
            launch.assert_called_once()
            command = launch.call_args.args[0]
            self.assertEqual(command[:3], ['bazel', '--batch', 'test'])
            self.assertIn('--remote_executor=grpc://hub:50051', command)
            self.assertIn('--remote_local_fallback=false', command)
            self.assertIn('--jobs=48', command)

    def test_endpoint_rejects_ambiguous_or_unsupported_urls(self):
        for value in ('hub:50051', 'grpc://hub', 'grpc://hub:0', 'grpc://hub:65536',
                      'grpc://user@hub:1', 'grpc://hub:1/path', 'https://hub:1'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                endpoint(value)
        self.assertEqual(endpoint('grpc://[::1]:50051'), 'grpc://[::1]:50051')

    def test_state_rejects_unrelated_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'work').mkdir()
            with self.assertRaises(ValueError):
                with state_directory(root):
                    pass
            self.assertTrue((root / 'work').is_dir())

    def test_state_lock_prevents_concurrent_workers_and_allows_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with state_directory(root):
                with self.assertRaises(ValueError):
                    with state_directory(root):
                        pass
            with state_directory(root) as reopened:
                self.assertEqual(reopened, root.resolve())

    def test_temporary_state_is_removed(self):
        with state_directory(None) as root:
            (root / 'data').write_text('temporary')
        self.assertFalse(root.exists())

    def test_child_is_stopped_when_context_raises(self):
        with self.assertRaisesRegex(RuntimeError, 'test failure'):
            with process([sys.executable, '-c', 'import time; time.sleep(60)']) as child:
                raise RuntimeError('test failure')
        self.assertIsNotNone(child.poll())

    def test_cleanup_kills_group_even_when_leader_exits(self):
        with patch("reapi.os.killpg", wraps=os.killpg) as killpg:
            with process([sys.executable, "-c", "pass"]) as child:
                child.wait()
        self.assertEqual(
            [call.args for call in killpg.call_args_list],
            [(child.pid, signal.SIGTERM), (child.pid, signal.SIGKILL)],
        )

    def test_startup_detects_failed_worker_before_connecting(self):
        child = subprocess.Popen([sys.executable, '-c', 'raise SystemExit(7)'])
        child.wait()
        with self.assertRaisesRegex(RuntimeError, 'exit 7'):
            wait_ready(child, 51001, 51002)


if __name__ == '__main__':
    unittest.main()
