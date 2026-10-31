"""합성 자식 프로세스로 자원 승인과 소유 자원 정리를 검증합니다."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import gxw_analysis_service as service


CHILD_TIMEOUT = 10.0


def scratch_directory():
    root = Path(tempfile.gettempdir()).resolve(strict=True)
    protected = {(Path.home() / "OneDrive").resolve()}
    for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        configured = os.environ.get(name)
        if configured and Path(configured).is_absolute():
            protected.add(Path(configured).resolve())
    for anchor in (Path(__file__).resolve().parent, Path.cwd().resolve(strict=True)):
        for ancestor in (anchor, *anchor.parents):
            if (ancestor / ".git").exists() or (ancestor / "AGENTS.md").is_file():
                protected.add(ancestor)
    if any(root.is_relative_to(path) for path in protected):
        raise AssertionError("합성 입력의 Temp 경로는 저장소와 OneDrive 밖에 있어야 합니다.")
    path = Path(tempfile.mkdtemp(prefix="gxw-service-resources-", dir=root)).resolve(strict=True)
    if not path.is_relative_to(root) or path == root:
        raise AssertionError("합성 입력은 현재 사용자 Temp 하위에 있어야 합니다.")
    # Preserve the unique run, including failures, for operator inspection.
    return path


def owned_subject(proc, job):
    subject = service.ReadService.__new__(service.ReadService)
    subject._owned_proc = proc
    subject._owned_job = job
    subject._owned_waiter = None
    subject._poisoned = False
    subject.active = True
    return subject


def fake_process(returncode, returned):
    return SimpleNamespace(
        stdin=mock.Mock(), returncode=returncode, kill=mock.Mock(),
        wait=mock.AsyncMock(return_value=returned),
    )


async def reap_child(proc, job=None):
    try:
        if job is not None:
            job.close()
    finally:
        try:
            if proc.stdin is not None:
                proc.stdin.close()
            if proc.returncode is None:
                proc.kill()
        finally:
            await asyncio.wait_for(proc.wait(), CHILD_TIMEOUT)


async def run_child(command, environment, payload=None):
    proc = await asyncio.create_subprocess_exec(
        *command, env=environment, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        creationflags=0x08000000 if sys.platform == "win32" else 0,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(payload), CHILD_TIMEOUT)
        return proc.returncode, stdout, stderr
    finally:
        await reap_child(proc)


class ServiceResourceTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows 자원 격리 계약을 검증합니다.")
    async def test_real_child_pid_and_memory_limit_after_gate(self):
        scratch = scratch_directory()
        child = scratch / "bounded_child.py"
        child.write_text(
            "import os, sys\n"
            "print(os.getpid(), flush=True)\n"
            "if sys.stdin.buffer.readline(2) != b'G\\n' or sys.stdin.buffer.read(1):\n"
            "    raise SystemExit(3)\n"
            "try:\n"
            "    allocation = bytearray(256 * 1024 * 1024)\n"
            "except MemoryError:\n"
            "    print('MEMORY_LIMIT', flush=True)\n"
            "    raise SystemExit(0)\n"
            "print('ALLOCATION_ALLOWED', flush=True)\n"
            "raise SystemExit(4)\n",
            encoding="utf-8",
        )
        fixedworker = Path(service.__file__).resolve().with_name("gxw_analysis_worker.py")
        command, environment = service._worker_launch(fixedworker)
        self.assertEqual(["-I", "-S", "-B"], command[1:-1])
        self.assertEqual(str(fixedworker), command[-1])
        proc = await asyncio.create_subprocess_exec(
            *command[:-1], str(child), env=environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, creationflags=0x08000000,
        )
        job = None
        try:
            reported_pid = await asyncio.wait_for(proc.stdout.readline(), CHILD_TIMEOUT)
            self.assertEqual(proc.pid, int(reported_pid))
            job = service.WorkerJob(proc.pid, 32 * 1024 * 1024)
            proc.stdin.write(b"G\n")
            await asyncio.wait_for(proc.stdin.drain(), CHILD_TIMEOUT)
            proc.stdin.close()
            stdout, stderr = await asyncio.wait_for(proc.communicate(), CHILD_TIMEOUT)
            self.assertEqual(0, proc.returncode, stderr.decode("utf-8", errors="replace"))
            self.assertEqual(b"MEMORY_LIMIT\r\n" if os.linesep == "\r\n" else b"MEMORY_LIMIT\n", stdout)
        finally:
            await reap_child(proc, job)

    @unittest.skipUnless(sys.platform == "win32", "Windows 워커 시작 계약을 검증합니다.")
    async def test_invalid_worker_gate_does_not_run_site_hooks(self):
        scratch = scratch_directory()
        site_root = scratch / "site-packages"
        site_root.mkdir()
        (site_root / "resource_marker.pth").write_text(
            "import os, pathlib; pathlib.Path(os.environ['GXW_TEST_PTH_MARKER']).write_text('executed')\n",
            encoding="utf-8",
        )
        (site_root / "sitecustomize.py").write_text(
            "import os, pathlib\n"
            "pathlib.Path(os.environ['GXW_TEST_SITE_MARKER']).write_text('executed')\n",
            encoding="utf-8",
        )
        fixedworker = Path(service.__file__).resolve().with_name("gxw_analysis_worker.py")
        command, environment = service._worker_launch(fixedworker)
        pth_marker, site_marker = scratch / "invalid-pth.txt", scratch / "invalid-site.txt"
        environment.update({
            "GXW_TOOLKIT_WORKER_SITE": str(site_root),
            "GXW_TEST_PTH_MARKER": str(pth_marker),
            "GXW_TEST_SITE_MARKER": str(site_marker),
        })
        returncode, stdout, stderr = await run_child(command, environment, b"{}\n")
        self.assertEqual((2, b"", b""), (returncode, stdout, stderr))
        self.assertFalse(pth_marker.exists())
        self.assertFalse(site_marker.exists())

        # A separate owned child proves the synthetic hooks are executable.
        control_pth, control_site = scratch / "control-pth.txt", scratch / "control-site.txt"
        environment.update({
            "GXW_TEST_PTH_MARKER": str(control_pth),
            "GXW_TEST_SITE_MARKER": str(control_site),
        })
        control = command[:-1] + [
            "-c", "import site, sys; site.addsitedir(sys.argv[1]); import sitecustomize",
            str(site_root),
        ]
        returncode, stdout, stderr = await run_child(control, environment)
        self.assertEqual((0, b"", b""), (returncode, stdout, stderr))
        self.assertEqual("executed", control_pth.read_text(encoding="utf-8"))
        self.assertEqual("executed", control_site.read_text(encoding="utf-8"))

    async def test_confirmed_owned_cleanup_returns_true(self):
        proc = fake_process(None, 0)

        async def completed_wait():
            proc.returncode = 0
            return 0

        proc.wait.side_effect = completed_wait
        job = mock.Mock()
        subject = owned_subject(proc, job)
        self.assertTrue(await subject._cleanup_owned())
        job.close.assert_called_once_with()
        proc.stdin.close.assert_called_once_with()
        proc.kill.assert_called_once_with()
        proc.wait.assert_awaited_once_with()
        self.assertTrue(subject._owned_waiter.done())
        self.assertIs(proc, subject._owned_proc)
        self.assertIs(job, subject._owned_job)

    async def test_unconfirmed_exit_or_job_close_returns_false(self):
        cases = (
            ("mismatched_exit", 3, 0, False),
            ("missing_exit", None, 0, False),
            ("missing_wait_result", 0, None, False),
            ("boolean_exit", True, True, False),
            ("job_close_error", 0, 0, True),
        )
        for name, returncode, returned, close_error in cases:
            with self.subTest(case=name):
                proc = fake_process(returncode, returned)
                job = mock.Mock()
                if close_error:
                    job.close.side_effect = OSError("synthetic close failure")
                subject = owned_subject(proc, job)
                self.assertFalse(await subject._cleanup_owned())
                proc.wait.assert_awaited_once_with()
                self.assertTrue(subject.active)
                self.assertIs(proc, subject._owned_proc)
                self.assertIs(job, subject._owned_job)

    async def test_never_completing_owned_wait_has_bounded_cleanup(self):
        proc = fake_process(None, None)

        async def never_completes():
            await asyncio.Future()

        proc.wait.side_effect = never_completes
        subject = owned_subject(proc, mock.Mock())
        with mock.patch.object(service, "CLEANUP_TIMEOUT", 0.02):
            result = await asyncio.wait_for(subject._cleanup_owned(), 1.0)
        self.assertFalse(result)
        self.assertTrue(subject.active)
        proc.wait.assert_awaited_once_with()
        await asyncio.wait_for(asyncio.gather(subject._owned_waiter, return_exceptions=True), 1.0)
        self.assertTrue(subject._owned_waiter.cancelled())

    async def test_poisoned_service_rejects_reuse_and_close_without_releasing_slot(self):
        proc, job, waiter = object(), object(), object()
        subject = owned_subject(proc, job)
        subject._owned_waiter = waiter
        subject._poisoned = True
        subject.registry = SimpleNamespace(projects={})
        subject.audit = mock.Mock()
        subject.record = mock.Mock()
        subject._cleanup_owned = mock.AsyncMock()
        with mock.patch.object(service.asyncio, "create_subprocess_exec", new_callable=mock.AsyncMock) as spawn:
            with mock.patch.object(service, "WorkerJob") as new_job:
                with self.assertRaisesRegex(service.ServiceError, "^CLEANUP_UNCONFIRMED$"):
                    await subject.execute("inventory", "synthetic")
                with self.assertRaisesRegex(service.ServiceError, "^CLEANUP_UNCONFIRMED$"):
                    subject.close()
        spawn.assert_not_awaited()
        new_job.assert_not_called()
        subject._cleanup_owned.assert_not_awaited()
        subject.audit.close.assert_not_called()
        self.assertTrue(subject.active)
        self.assertTrue(subject._poisoned)
        self.assertIs(proc, subject._owned_proc)
        self.assertIs(job, subject._owned_job)
        self.assertIs(waiter, subject._owned_waiter)


if __name__ == "__main__":
    unittest.main()
