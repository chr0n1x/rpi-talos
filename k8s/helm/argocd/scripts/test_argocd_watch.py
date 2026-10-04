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
BAD_SYNC = ("OutOfSync", "Healthy")
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


class TestProcessPoll(unittest.TestCase):
    def setUp(self):
        self.settle = 3
        self.healthy_clear = 1800
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
        bad = apps(("a", "OutOfSync", "Healthy"))
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
        bad = apps(("a", "OutOfSync", "Healthy"))
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
        self.assertEqual(new, BAD_SYNC)
        self.assertEqual(send_kind, "alert")
        self.assertEqual(state["baseline"]["a"], BAD_SYNC)
        self.assertIsNone(state["healthy_since"]["a"])
        self.assertIn("a", state["last_bad_msg_at"])

    def test_recovery_sends_recovery_and_starts_healthy_timer(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = apps(("a", "OutOfSync", "Healthy"))
        self.poll(state, good)

        # Drive to bad (settled)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        self.assertEqual(state["baseline"]["a"], BAD_SYNC)
        self.assertIn("a", state["last_bad_msg_at"])

        # Now recover to good for settle polls
        recovery_actions = []
        for i in range(self.settle):
            self.advance()
            actions = self.poll(state, good)
            recovery_actions.extend(actions)
        # Exactly one recovery action on the settle-th poll
        sends = [a for a in recovery_actions if a[0] == "send"]
        self.assertEqual(len(sends), 1)
        kind, name, old, new, app, send_kind = sends[0]
        self.assertEqual(name, "a")
        self.assertEqual(old, BAD_SYNC)
        self.assertEqual(new, GOOD)
        self.assertEqual(send_kind, "recovery")
        self.assertEqual(state["baseline"]["a"], GOOD)
        self.assertIsNotNone(state["healthy_since"]["a"])
        self.assertNotIn("a", state["last_bad_msg_at"])

    def test_stays_bad_refreshes_every_rebad_window(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = apps(("a", "OutOfSync", "Healthy"))
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
        bad = apps(("a", "OutOfSync", "Healthy"))
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        # Advance less than rebad_refresh: no refresh
        self.advance(dt=self.rebad_refresh - 1)
        actions = self.poll(state, bad)
        self.assertEqual([a for a in actions if a[0] == "send"], [])

    def test_good_30m_with_visible_message_deletes(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        bad = apps(("a", "OutOfSync", "Healthy"))
        self.poll(state, good)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, bad)
        # Simulate a visible message for "a"
        state["message_ids"]["a"] = 12345

        # Recover to good (settled)
        for _ in range(self.settle):
            self.advance()
            self.poll(state, good)
        self.assertIn("a", state["message_ids"])  # still visible after recovery

        # Advance past healthy_clear: delete action should be returned
        self.advance(dt=self.healthy_clear + 1)
        actions = self.poll(state, good)
        deletes = [a for a in actions if a[0] == "delete"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][1], "a")
        # healthy_since is cleared so the delete won't re-fire on next poll
        self.assertIsNone(state["healthy_since"]["a"])
        # Simulate the caller executing the delete
        state["message_ids"].pop("a", None)
        self.advance()
        actions = self.poll(state, good)
        self.assertEqual([a for a in actions if a[0] == "delete"], [])

    def test_no_delete_without_visible_message(self):
        state = aw.new_state()
        good = apps(("a", "Synced", "Healthy"))
        self.poll(state, good)
        # No message was ever sent; advance past healthy_clear
        self.advance(dt=self.healthy_clear + 1)
        actions = self.poll(state, good)
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
            self.poll(state, apps(("a", "OutOfSync", "Healthy"), ("b", "Synced", "Healthy")))
        # "b" should be untouched
        self.assertEqual(state["baseline"]["b"], GOOD)
        self.assertNotIn("b", state["message_ids"])
        self.assertEqual(state["baseline"]["a"], BAD_SYNC)

    def test_is_good(self):
        self.assertTrue(aw.is_good(GOOD))
        self.assertFalse(aw.is_good(BAD_SYNC))
        self.assertFalse(aw.is_good(BAD_HEALTH))
        self.assertFalse(aw.is_good(BOTH_BAD))
        self.assertFalse(aw.is_good(("Synced", "Progressing")))
        self.assertFalse(aw.is_good(("Unknown", "Healthy")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
