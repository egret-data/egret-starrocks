"""Unit tests of probe_lib: python -I -m unittest discover -s tests/e2e -p test_probe_lib.py (no Docker needed)."""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import probe_lib  # noqa: E402
from probe_lib import Probe, ProbeCheck, Verdict, canary_hits, run_checks, skipped_probes  # noqa: E402

REFUSED = "DENIED"
LEAKED = [(1, "us", "a@x.io")]


def check(sight=lambda: True, actual=lambda: REFUSED, leaked=lambda r: r != REFUSED, na=lambda: None,
          probe=Probe.JDBC, id="C1", name="a check"):
    return ProbeCheck(id=id, probe=probe, name=name, sight=sight, actual=actual, leaked=leaked, na_reason=na)


def run(checks, skipped=frozenset()):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = run_checks(checks, set(skipped))
    return status, out.getvalue()


class SkippedProbes(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(skipped_probes(""), set())

    def test_two_names(self):
        self.assertEqual(skipped_probes("jdbc,hive"), {Probe.JDBC, Probe.HIVE})

    def test_whitespace(self):
        self.assertEqual(skipped_probes(" jdbc , paimon ,"), {Probe.JDBC, Probe.PAIMON})
        self.assertEqual(skipped_probes("   "), set())

    def test_unknown_name_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                skipped_probes("jdbc,nope")
        self.assertEqual(cm.exception.code, 2)

    def test_dropped_udf_probes_are_unknown(self):
        # The UDF probe left the package: its names must stop a run rather than be skipped silently.
        for name in ("udf", "python-udf"):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    skipped_probes(name)
            self.assertEqual(cm.exception.code, 2)


class RunChecks(unittest.TestCase):
    def verdict_line(self, checks, skipped=frozenset()):
        _, out = run(checks, skipped)
        return out.splitlines()[0]

    def test_enforced(self):
        self.assertTrue(self.verdict_line([check()]).startswith("ENFORCED  [probe:jdbc]  C1 a check  DENIED"))

    def test_leak(self):
        self.assertTrue(self.verdict_line([check(actual=lambda: LEAKED)]).startswith("LEAK  "))

    def test_blind_even_when_actual_is_a_refusal(self):
        status, out = run([check(sight=lambda: False, actual=lambda: REFUSED)])
        self.assertTrue(out.startswith("BLIND  "))
        self.assertEqual(status, 1)

    def test_blind_even_when_actual_leaks(self):
        self.assertTrue(self.verdict_line([check(sight=lambda: False, actual=lambda: LEAKED)]).startswith("BLIND"))

    def test_na_carries_the_reason_and_wins_over_the_rest(self):
        line = self.verdict_line([check(na=lambda: "no partition listing", sight=lambda: False)])
        self.assertTrue(line.startswith("N/A  "))
        self.assertIn("no partition listing", line)

    def test_skip_does_not_call_anything(self):
        def boom():
            raise AssertionError("called")
        line = self.verdict_line([check(sight=boom, actual=boom, na=boom)], {Probe.JDBC})
        self.assertTrue(line.startswith("SKIP  [probe:jdbc]"))

    def test_exception_in_actual_is_error_with_class_and_message(self):
        def boom():
            raise ValueError("kaput")
        status, out = run([check(actual=boom)])
        self.assertTrue(out.startswith("ERROR  "))
        self.assertIn("ValueError", out)
        self.assertIn("kaput", out)
        self.assertEqual(status, 1)

    def test_exception_in_sight_or_leaked_is_error(self):
        def boom(*_):
            raise RuntimeError("x")
        self.assertTrue(self.verdict_line([check(sight=boom)]).startswith("ERROR"))
        self.assertTrue(self.verdict_line([check(leaked=boom)]).startswith("ERROR"))

    def test_a_broken_check_does_not_stop_the_run(self):
        def boom():
            raise ValueError("x")
        _, out = run([check(actual=boom, id="A"), check(id="B")])
        self.assertEqual([l.split()[0] for l in out.splitlines()[:2]], ["ERROR", "ENFORCED"])

    def test_connection_failure_string_is_error_not_leak_or_enforced(self):
        # sqlpaths helpers never raise: a failure comes back as "ERROR <errno>: <msg>" or "ERROR <Class>: <msg>".
        for failure in ("ERROR 2003: Can't connect to MySQL server", "ERROR OSError: refused"):
            for leaked in (lambda r: True, lambda r: False):
                status, out = run([check(actual=lambda f=failure: f, leaked=leaked)])
                self.assertTrue(out.startswith("ERROR  "), out)
                self.assertIn(failure[:20], out)
                self.assertEqual(status, 1)

    def test_error_string_does_not_hide_behind_a_sight_failure(self):
        self.assertTrue(self.verdict_line([check(sight=lambda: False, actual=lambda: "ERROR 2003: x")]).startswith("BLIND"))

    def test_denied_refusal_takes_the_normal_path(self):
        # run() maps privilege errors (5203, 5204, 5210-5214, "Access denied") to the string DENIED ...
        self.assertTrue(self.verdict_line([check(actual=lambda: "DENIED")]).startswith("ENFORCED"))
        self.assertTrue(self.verdict_line([check(actual=lambda: "DENIED", leaked=lambda r: True)]).startswith("LEAK"))
        # ... and a refusal that arrives as an ERROR string with one of those codes is not a harness fault either.
        for code in (5203, 5204, 5210, 5211, 5212, 5213, 5214):
            line = self.verdict_line([check(actual=lambda c=code: f"ERROR {c}: Access denied", leaked=lambda r: False)])
            self.assertTrue(line.startswith("ENFORCED"), line)

    def test_other_non_error_strings_and_5xxx_errors(self):
        # Any other "ERROR ..." string (here a 5xxx storage error, not a DENIED code) is a failed request: ERROR.
        self.assertTrue(self.verdict_line([check(actual=lambda: "ERROR 5001: storage", leaked=lambda r: False)]).startswith("ERROR"))
        self.assertTrue(self.verdict_line([check(actual=lambda: "an ERROR inside", leaked=lambda r: False)]).startswith("ENFORCED"))

    def test_result_is_cut_at_110_characters(self):
        line = self.verdict_line([check(actual=lambda: "x" * 300)])
        self.assertTrue(line.endswith("x" * 107 + "..."))

    def test_na_reason_is_printed_whole_on_one_line(self):
        reason = "first: ERROR 1064: " + "y" * 200 + "\nsecond: ERROR 5502: Unknown table"
        _, out = run([check(na=lambda: reason)])
        line = out.splitlines()[0]
        self.assertTrue(line.startswith("N/A  [probe:jdbc]  C1 a check  "), line)
        self.assertTrue(line.endswith("second: ERROR 5502: Unknown table"), line)
        self.assertIn("y" * 200, line)
        self.assertIn("N/A 1", out.strip().splitlines()[-1])

    def test_exit_status_leak_is_zero_skip_and_na_are_zero(self):
        status, _ = run([check(actual=lambda: LEAKED), check(na=lambda: "r", id="N"), check(id="S", probe=Probe.HIVE)],
                        {Probe.HIVE})
        self.assertEqual(status, 0)

    def test_summary_counts_every_verdict(self):
        _, out = run([check(), check(actual=lambda: LEAKED), check(sight=lambda: False)])
        summary = out.strip().splitlines()[-1]
        for fragment in ("ENFORCED 1", "LEAK 1", "BLIND 1", "N/A 0", "SKIP 0", "ERROR 0"):
            self.assertIn(fragment, summary)


class CanaryHits(unittest.TestCase):
    def test_returns_only_lines_with_the_marker(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("/c16-1 172.17.0.2\n/other 172.17.0.2\n/c16-1/x 10.0.0.1\n")
        try:
            self.assertEqual(canary_hits(f.name, "c16-1"),
                             ["/c16-1 172.17.0.2", "/c16-1/x 10.0.0.1"])
        finally:
            os.unlink(f.name)

    def test_missing_log_is_no_hits(self):
        self.assertEqual(canary_hits("/nonexistent/canary.log", "x"), [])



class PaimonSystemLeak(unittest.TestCase):
    """C14-paimon's predicate, over rows shaped as the probe reads them: (partition, record count)."""

    # What bob read on both images in the 2026-11-12 runs.
    BOB_UNFILTERED = {"files": [("{eu}", 2), ("{us}", 2)], "snapshots": [(None, 4)],
                      "partitions": [("{eu}", 2), ("{us}", 2)]}

    def test_unfiltered_reads_leak(self):
        # Arrange / Act / Assert
        self.assertTrue(probe_lib.paimon_system_leak(self.BOB_UNFILTERED, allowed_rows=2))

    def test_rows_filtered_to_us_do_not_leak(self):
        # What a patch applying bob's row filter to the system tables would return (the "no eu" branch).
        filtered = {"files": [("{us}", 2)], "snapshots": [(None, 2)], "partitions": [("{us}", 2)]}
        self.assertFalse(probe_lib.paimon_system_leak(filtered, allowed_rows=2))

    def test_refusals_and_empty_results_do_not_leak(self):
        self.assertFalse(probe_lib.paimon_system_leak(
            {"files": "DENIED", "snapshots": "DENIED", "partitions": []}, allowed_rows=0))

    def test_eu_matches_the_partition_value_not_a_substring(self):
        self.assertFalse(probe_lib.paimon_system_leak({"files": [("{us-eu-x}", 1)]}, allowed_rows=2))
        self.assertTrue(probe_lib.paimon_system_leak({"partitions": [("{eu}", 0)]}, allowed_rows=2))

    def test_record_counts_beyond_the_allowed_rows_leak(self):
        self.assertTrue(probe_lib.paimon_system_leak({"snapshots": [(None, 4)]}, allowed_rows=2))
        self.assertTrue(probe_lib.paimon_system_leak({"files": [("{us}", 2), ("{us}", 1)]}, allowed_rows=2))
        self.assertTrue(probe_lib.paimon_system_leak({"files": [("{us}", 1)]}, allowed_rows=0))
        self.assertFalse(probe_lib.paimon_system_leak({"snapshots": [(None, 1), (None, 2)]}, allowed_rows=2))


if __name__ == "__main__":
    unittest.main()
