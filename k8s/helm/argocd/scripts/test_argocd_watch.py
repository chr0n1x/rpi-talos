#!/usr/bin/env python3
"""Unit tests for the ArgoCD watcher state machine (process_poll).

Run: python3 test_argocd_watch.py
Uses only the standard library (unittest, sys). No network calls.
"""

import sys
import os
import unittest

# Make the script importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import argocd_watch as aw


GOOD = ("Synced", "Healthy")
OUT_OF_SYNC = ("OutOfSync", "Healthy")  # NOT bad: drift, not an incident
BAD_HEALTH = ("Synced", "Degraded")
BOTH_BAD = ("OutOfSync", "Degraded")


def app(name, sync, health, ns="argocd"):
    return {
        "metadata": {"name": name, "namespace": ns},
        "status": {
            "sync": {"status": sync},
            "health": {"status": health},
        },
    }


def apps(*specs):
    """Build a list of app dicts from (name, sync, health) tuples."""
    return [app(n, s, h) for (n, s, h) in specs]


def bad_apps(name):
    """Degraded-health app variants (the alert-worthy ones)."""
    return [app(name, "Synced", "Degraded")]


class TestProcessPoll(unittest.TestCase):
    def setUp(self):
        self.settle = 3
        self.healthy_clear = 900
        self.rebad_refresh = 300
        self.t = 1000.0  # starting clock

    def poll(self, state, current_apps):
        return aw.process_poll(
            state, current_apps, self.t,
            self.settle, self.healthy_clear, self.rebad_refresh,
        )

    def advance(self, dt=60.0):
        self.t += dt

    def test_baseline_is_silent(self):
        state = aw.new_state()
        current = apps(("a", "Synced", "Healthy"), ("b", "Synced", "Healthy"))
        actions = self.poll(state, current)
        self.assertEqual(actions, [])
        self.assertTrue(state["started"])
        self.assertEqual(state["baseline"]["a"], GOOD)
        self.assertEqual(state["baseline"]["b"], GOOD)

    def test_no_action_when_stable(self):
        state = aw.new_state()
        current = apps(("a", "Synced", "Healthy"))
        self.poll(state, current)
        self.advance()
        actions = self.poll(state, current)
        self.assertEqual(actions, [])

    def test_flap_below_settle_is_absorbed(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)

        # One bad poll: not settled
        self.advance()
        actions = self.poll(state, bad)
        self.assertEqual(actions, [])
        self.assertEqual(state["baseline"]["a"], GOOD)  # still good

        # Flaps back to good before settle: no action
        self.advance()
        actions = self.poll(state, good)
        self.assertEqual(actions, [])
        self.assertEqual(state["baseline"]["a"], GOOD)

    def test_bad_settles_after_settle_polls(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)

        # settle-1 bad polls: no action
        for _ in range(self.settle - 1):
            self.advance()
            actions = self.poll(state, bad)
            self.assertEqual(actions, [])

        # settle-th bad poll: alert fires
        self.advance()
        actions = self.poll(state, bad)
        self.assertEqual(len(actions), 1)
        kind, name, old, new, app, send_kind = actions[0]
        self.assertEqual(kind, "send")
        self.assertEqual(name, "a")
        self.assertEqual(old, GOOD)
        self.assertEqual(new, BAD_HEALTH)
        self.assertEqual(send_kind, "alert")
        self.assertEqual(state["baseline"]["a"], BAD_HEALTH)
        self.assertIsNone(state["healthy_since"]["a"])
        self.assertIn("a", state["last_bad_msg_at"])

    def test_out_of_sync_healthy_does_not_alert(self):
        """OutOfSync + Healthy is drift, not an incident: no alert, even when settled."""
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        oos = apps(("a", "OutOfSync", "Healthy"))
        self.poll(state, good)

        for _ in range(self.settle * 2):
            self.advance()
            actions = self.poll(state, oos)
            self.assertEqual(actions, [])
        # Baseline tracks the new pair but nothing was ever reported
        self.assertEqual(state["baseline"]["a"], OUT_OF_SYNC)
        self.assertNotIn("a", state["message_ids"])
        self.assertNotIn("a", state["last_bad_msg_at"])

    def test_recovery_sends_message_and_starts_timer(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)

        # Drive to bad (settled) - alert fires
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        self.assertEqual(state["baseline"]["a"], BAD_HEALTH)
        self.assertIn("a", state["last_bad_msg_at"])

        # Simulate the alert message being sent and stored
        state["message_ids"]["a"] = 12345

        # Now recover to good for settle polls
        recovery_actions = []
        for i in range(self.settle):
            self.advance()
            actions = self.poll(state, good)
            recovery_actions.extend(actions)
        # Exactly one send action on the settle-th poll
        sends = [a for a in recovery_actions if a[0] == "send"]
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0][5], "recovery")
        self.assertEqual(sends[0][1], "a")
        self.assertEqual(state["baseline"]["a"], GOOD)
        self.assertIsNotNone(state["healthy_since"]["a"])
        self.assertNotIn("a", state["last_bad_msg_at"])

    def test_healthy_15m_deletes_message(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        # Simulate the alert message being sent and stored
        state["message_ids"]["a"] = 12345

        # Recover to good (settled) - recovery message sent
        for _ in range(self.settle):
            self.advance()
            self.poll(state, good)
        # Simulate the recovery message being stored
        state["message_ids"]["a"] = 99999

        # Advance past healthy_clear: delete action should be returned
        self.advance(dt=self.healthy_clear + 1)
        actions = self.poll(state, good)
        deletes = [a for a in actions if a[0] == "delete"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][1], "a")
        self.assertIsNone(state["healthy_since"]["a"])

    def test_no_delete_before_healthy_clear(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        state["message_ids"]["a"] = 12345

        # Recover to good (settled)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, good)
        state["message_ids"]["a"] = 99999

        # Advance less than healthy_clear: no delete
        self.advance(dt=self.healthy_clear - 1)
        actions = self.poll(state, good)
        self.assertEqual([a for a in actions if a[0] == "delete"], [])

    def test_stays_bad_refreshes_every_rebad_window(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        # Now stays bad; advance past rebad_refresh and expect a refresh
        baseline_bad = state["last_bad_msg_at"]["a"]
        self.advance(dt=self.rebad_refresh + 1)
        actions = self.poll(state, bad)
        refreshes = [a for a in actions if a[0] == "send" and a[5] == "refresh"]
        self.assertEqual(len(refreshes), 1)
        self.assertEqual(refreshes[0][1], "a")
        self.assertGreater(state["last_bad_msg_at"]["a"], baseline_bad)

    def test_no_refresh_within_rebad_window(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        # Advance less than rebad_refresh: no refresh
        self.advance(dt=self.rebad_refresh - 1)
        actions = self.poll(state, bad)
        self.assertEqual([a for a in actions if a[0] == "send"], [])

    def test_recovery_without_message_no_delete_second(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = bad_apps("a")
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        # No message stored (simulating a failed send)
        # Recover to good (settled), then advance past healthy_clear
        for _ in range(self.settle):
            self.advance()
            self.poll(state, good)
        self.advance(dt=self.healthy_clear + 1)
        actions = self.poll(state, good)
        # No delete since no message_id exists
        self.assertEqual([a for a in actions if a[0] == "delete"], [])



    def test_removed_app_sends_removal(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"), ("b", "Synced", "Healthy"))
        self.poll(state, good)
        # "b" disappears
        self.advance()
        actions = self.poll(state, apps(("a", "Synced", "Healthy")))
        sends = [a for a in actions if a[0] == "send"]
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0][1], "b")
        self.assertEqual(sends[0][2], GOOD)  # old
        self.assertEqual(sends[0][3], ("Removed", "Removed"))  # new
        self.assertEqual(sends[0][5], "alert")  # removal is not "good"
        self.assertNotIn("b", state["baseline"])

    def test_new_app_added_silently(self):
        state = aw.new_state()
        self.poll(state, apps(("a", "Synced", "Healthy")))
        self.advance()
        actions = self.poll(state, apps(("a", "Synced", "Healthy"), ("b", "Synced", "Healthy")))
        # New app "b" should not produce an action
        self.assertEqual([a for a in actions if a[1] == "b"], [])
        self.assertIn("b", state["baseline"])

    def test_independent_apps_do_not_clobber(self):
        state = aw.new_state()
        self.poll(state, apps(("a", "Synced", "Healthy"), ("b", "Synced", "Healthy")))
        # Only "a" goes bad
        for _ in range(self.settle):
            self.advance()
            self.poll(state, apps(("a", "Synced", "Degraded"), ("b", "Synced", "Healthy")))
        # "b" should be untouched
        self.assertEqual(state["baseline"]["b"], GOOD)
        self.assertNotIn("b", state["message_ids"])
        self.assertEqual(state["baseline"]["a"], BAD_HEALTH)

    def test_is_good(self):
        self.assertTrue(aw.is_good(GOOD))
        # OutOfSync + Healthy is drift, not an incident: treated as good
        self.assertTrue(aw.is_good(OUT_OF_SYNC))
        self.assertFalse(aw.is_good(BAD_HEALTH))
        self.assertFalse(aw.is_good(BOTH_BAD))
        self.assertFalse(aw.is_good(("Synced", "Progressing")))
        self.assertFalse(aw.is_good(("Unknown", "Degraded")))
        self.assertFalse(aw.is_good(("Removed", "Removed")))


class TestExecuteActions(unittest.TestCase):
    def setUp(self):
        self.state = aw.new_state()
        self.state["started"] = True
        self.calls = {"send": [], "delete": []}
        self._next_id = 100

    def mock_send(self, text):
        self._next_id += 1
        self.calls["send"].append(text)
        return {"ok": True, "result": {"message_id": self._next_id}}

    def mock_delete(self, message_id):
        self.calls["delete"].append(message_id)
        return {"ok": True}

    def exec(self, actions):
        aw.execute_actions(self.state, actions, 300, self.mock_send, self.mock_delete)

    def test_send_stores_message_id(self):
        actions = [("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")]
        self.exec(actions)
        self.assertEqual(len(self.calls["send"]), 1)
        self.assertEqual(self.calls["delete"], [])
        self.assertEqual(self.state["message_ids"]["a"], 101)

    def test_refresh_deletes_old_then_sends_new(self):
        # First: alert stores id=101
        self.exec([("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")])
        first_id = self.state["message_ids"]["a"]
        # Then: refresh should delete old and send new
        self.exec([("send", "a", BAD_HEALTH, BAD_HEALTH, {"metadata": {"name": "a"}}, "refresh", 900)])
        self.assertEqual(self.calls["delete"], [first_id])
        self.assertEqual(len(self.calls["send"]), 2)
        self.assertNotEqual(self.state["message_ids"]["a"], first_id)

    def test_recovery_deletes_alert(self):
        self.exec([("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")])
        first_id = self.state["message_ids"]["a"]
        self.exec([("delete", "a", None, None, None, "healthy for 15m")])
        self.assertEqual(self.calls["delete"], [first_id])
        self.assertEqual(len(self.calls["send"]), 1)
        self.assertNotIn("a", self.state["message_ids"])

    def test_delete_removes_message_id(self):
        self.exec([("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")])
        stored_id = self.state["message_ids"]["a"]
        self.exec([("delete", "a", None, None, None, "healthy for 30m")])
        self.assertEqual(self.calls["delete"], [stored_id])
        self.assertNotIn("a", self.state["message_ids"])

    def test_delete_without_message_is_noop(self):
        self.exec([("delete", "a", None, None, None, "healthy for 30m")])
        self.assertEqual(self.calls["delete"], [])
        self.assertEqual(self.calls["send"], [])
        self.assertNotIn("a", self.state["message_ids"])

    def test_send_failure_does_not_store_id(self):
        def failing_send(text):
            self.calls["send"].append(text)
            return {"ok": False, "description": "rate limited"}
        aw.execute_actions(self.state,
            [("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")],
            300, failing_send, self.mock_delete)
        self.assertNotIn("a", self.state["message_ids"])

    def test_delete_failure_still_removes_from_state(self):
        self.exec([("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")])
        stored_id = self.state["message_ids"]["a"]

        def failing_delete(message_id):
            self.calls["delete"].append(message_id)
            return {"ok": False, "description": "message not found"}
        aw.execute_actions(self.state,
            [("delete", "a", None, None, None, "healthy for 30m")],
            300, self.mock_send, failing_delete)
        self.assertEqual(self.calls["delete"], [stored_id])
        self.assertNotIn("a", self.state["message_ids"])

    def test_independent_apps_separate_messages(self):
        self.exec([("send", "a", GOOD, BAD_HEALTH, {"metadata": {"name": "a"}}, "alert")])
        self.exec([("send", "b", GOOD, BOTH_BAD, {"metadata": {"name": "b"}}, "alert")])
        self.assertIn("a", self.state["message_ids"])
        self.assertIn("b", self.state["message_ids"])
        self.assertNotEqual(self.state["message_ids"]["a"], self.state["message_ids"]["b"])
        self.assertEqual(self.calls["delete"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
