"""Failure diagnostics across the CLI boundary, with no external writes."""

from __future__ import annotations

import http.client
import io
import json
import socket
import ssl
import stat
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from arcbench_cli.cli import build_parser, log, main
from arcbench_cli.client import ApiError, OfficialClient, SubmitConfig
from arcbench_cli.diagnostics import Diagnostics, active
from test_platform import MODEL_KEY, SESSION_VALUE, Website


class DiagnosticTests(unittest.TestCase):
    def invoke(self, *args, env=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("arcbench_cli.cli.load_env", return_value=env or {}), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--json", *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_log_flag_works_before_or_after_command(self):
        for args in (["--log-file", "file.jsonl", "balance"],
                     ["balance", "--log-file", "file.jsonl"]):
            self.assertEqual(build_parser().parse_args(args).log_file, "file.jsonl")

    def test_missing_credentials_emit_json_on_stderr_with_original_exit_code(self):
        code, stdout, stderr = self.invoke("balance")
        self.assertEqual((code, stdout), (1, ""))
        error = json.loads(stderr)
        self.assertEqual(error["error_kind"], "local")
        self.assertIn("no metering credential", error["error"])
        self.assertEqual(error["exit_code"], 1)

    def test_progress_goes_to_stderr(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            log("queue full")
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("queue full", stderr.getvalue())

    def test_real_socket_balance_keeps_stdout_json_and_writes_private_metadata(self):
        with tempfile.TemporaryDirectory() as tmp, Website() as server:
            path = Path(tmp) / "requests.jsonl"
            code, stdout, stderr = self.invoke("balance", "--log-file", str(path), env={
                "ARC_BENCH_METER_BASE_URL": server.origin,
                "ARC_BENCH_API_KEY": MODEL_KEY,
            })
            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(json.loads(stdout)["available_balance"], "-1.353979")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            completed = [row for row in records if row["event"] == "request_finished"]
            self.assertEqual([row["path"] for row in completed],
                             ["/api/user/login", "/api/user/balance", "/api/user/freshness"])
            for row in completed:
                self.assertEqual(row["origin"], server.origin)
                self.assertEqual(row["http_status"], 200)
                self.assertGreaterEqual(row["elapsed_ms"], 0)
                self.assertEqual(row["timeout_seconds"], 60)
            rendered = path.read_text() + stdout + stderr
            self.assertNotIn(MODEL_KEY, rendered)
            for cookie in server.requests:
                if cookie["cookie"]:
                    for pair in cookie["cookie"].split(";"):
                        self.assertNotIn(pair.partition("=")[2].strip(), rendered)
            self.assertEqual(records[-1]["exit_code"], 0)

    def test_http_authentication_failure_is_attributed_to_meter_login(self):
        with tempfile.TemporaryDirectory() as tmp, Website() as server:
            path = Path(tmp) / "requests.jsonl"
            code, stdout, stderr = self.invoke("balance", "--log-file", str(path), env={
                "ARC_BENCH_METER_BASE_URL": server.origin,
                "ARC_BENCH_API_KEY": "wrong-synthetic-key",
            })
            self.assertEqual((code, stdout), (1, ""))
            error = json.loads(stderr)
            self.assertEqual(error["error_kind"], "authentication")
            self.assertEqual(error["http_status"], 401)
            self.assertEqual(error["method"], "POST")
            self.assertEqual(error["path"], "/user/login")
            self.assertEqual(error["origin"], server.origin)
            self.assertFalse(error["outcome_uncertain"])
            self.assertIn(error["request_id"], path.read_text())
            self.assertNotIn("wrong-synthetic-key", stderr + path.read_text())
            self.assertEqual(len(server.requests), 1)

    def test_transport_failures_keep_kind_cause_and_uncertain_write_without_retry(self):
        cases = [
            (urllib.error.URLError(socket.gaierror(-2, "name not known")), "dns", "gaierror"),
            (urllib.error.URLError(TimeoutError("timed out")), "timeout", "TimeoutError"),
            (TimeoutError("timed out"), "timeout", "TimeoutError"),
            (urllib.error.URLError(ssl.SSLError("certificate failed")), "tls", "SSLError"),
            (ConnectionRefusedError(61, "refused"), "connection", "ConnectionRefusedError"),
            (http.client.IncompleteRead(b"partial", 10), "incomplete_response", "IncompleteRead"),
        ]
        for error, kind, cause in cases:
            with self.subTest(kind=kind, cause=cause):
                client = OfficialClient(SubmitConfig(timeout_seconds=3))
                with patch.object(client.opener, "open", side_effect=error) as request:
                    with self.assertRaises(ApiError) as caught:
                        client.request("POST", "/runs?token=should-not-be-logged")
                detail = caught.exception.details
                self.assertEqual(detail["error_kind"], kind)
                self.assertEqual(detail["cause_type"], cause)
                self.assertEqual(detail["timeout_seconds"], 3)
                self.assertEqual(detail["path"], "/api/runs")
                self.assertTrue(detail["outcome_uncertain"])
                self.assertTrue(detail["transport_failure"])
                self.assertNotIn("should-not-be-logged", json.dumps(detail))
                request.assert_called_once()

    def test_http_error_body_read_failure_stays_structured(self):
        response = urllib.error.HTTPError("https://arc-bench.com/api/runs", 503, "busy", {}, io.BytesIO())
        with patch.object(response, "read", side_effect=http.client.IncompleteRead(b"", 4)):
            client = OfficialClient(SubmitConfig())
            with patch.object(client.opener, "open", side_effect=response):
                with self.assertRaises(ApiError) as caught:
                    client.request("GET", "/runs")
        self.assertEqual(caught.exception.details["error_kind"], "incomplete_response")
        self.assertEqual(caught.exception.status, 503)
        self.assertFalse(caught.exception.uncertain)

    def test_http_error_payload_and_free_text_credentials_are_redacted(self):
        client = OfficialClient(SubmitConfig(api_key=MODEL_KEY, session_cookie=f"arcbench_session={SESSION_VALUE}"))
        diagnostics = Diagnostics()
        token = active.set(diagnostics)
        try:
            with patch.object(client, "_request", return_value=(401, {
                "detail": {"api_key": "unknown-response-key", "message": f"{MODEL_KEY} {SESSION_VALUE} access_key=other-key"}
            })):
                with self.assertRaises(ApiError) as caught:
                    client.request("GET", "/auth/me?token=query-secret")
            rendered = json.dumps(caught.exception.details)
            for secret in (MODEL_KEY, SESSION_VALUE, "unknown-response-key", "other-key", "query-secret"):
                self.assertNotIn(secret, rendered)
        finally:
            active.reset(token)

    def test_log_open_error_prevents_request_and_stays_stderr_json(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(OfficialClient, "meter_login") as login:
            code, stdout, stderr = self.invoke("balance", "--log-file", str(Path(tmp) / "absent" / "x"))
            self.assertEqual((code, stdout), (1, ""))
            self.assertEqual(json.loads(stderr)["exception_type"], "FileNotFoundError")
            login.assert_not_called()

    def test_log_write_failure_does_not_change_command_exit(self):
        diagnostics = Diagnostics()
        stream = unittest.mock.Mock()
        stream.write.side_effect = OSError("disk full")
        diagnostics.stream = stream
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            diagnostics.record("command_finished", exit_code=0)
        self.assertIsNone(diagnostics.stream)
        self.assertIn("logging disabled", stderr.getvalue())

    def test_log_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("preserve")
            link = Path(tmp) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                Diagnostics(str(link)).open()
            self.assertEqual(target.read_text(), "preserve")

    def test_invalid_balance_payload_is_an_error_instead_of_null_balance(self):
        client = OfficialClient(SubmitConfig())
        with patch.object(client, "request", return_value=b"<html>login</html>") as request:
            with self.assertRaises(ApiError) as caught:
                client.balance()
        self.assertEqual(caught.exception.details["error_kind"], "invalid_response")
        request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
