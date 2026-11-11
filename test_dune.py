import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("dune", Path(__file__).with_name("main.py"))
dune = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = dune
spec.loader.exec_module(dune)


class DuneTests(unittest.TestCase):
    def sample(self, t, rx, tx=0):
        return dune.InterfaceSample(t, t, dune.InterfaceIdentity("eth0"), dune.InterfaceCounters(rx_bytes=rx, tx_bytes=tx))

    def test_reset_not_a_drop(self):
        rates = dune.RateCalculator.calculate(self.sample(1, 1000), self.sample(2, 10))
        self.assertTrue(rates.counter_reset)
        self.assertEqual(rates.rx_bps, 0)

    def test_normal_rate(self):
        rates = dune.RateCalculator.calculate(self.sample(1, 100), self.sample(3, 300))
        self.assertEqual(rates.rx_bps, 100)
        self.assertFalse(rates.counter_reset)

    def test_rolling_window(self):
        baseline = dune.InterfaceBaseline()
        for n in range(10):
            baseline.push(dune.InterfaceRates(rx_bps=float(n)), 4)
        self.assertEqual(baseline.rx_bps.count, 4)
        self.assertAlmostEqual(baseline.rx_bps.mean, 7.5)

    def test_selftest_identity_stable(self):
        reader = dune.SelfTestReader(2, 12)
        first = reader.collect()["sim1"].identity
        second = reader.collect()["sim1"].identity
        self.assertEqual((first.mac, first.ipv4), (second.mac, second.ipv4))

    def test_state_reset_event(self):
        class Reader(dune.SampleProvider):
            def __init__(self):
                self.n = 0
            def collect(self, selected=None):
                self.n += 1
                return {"eth0": dune.InterfaceSample(float(self.n), float(self.n), dune.InterfaceIdentity("eth0"), dune.InterfaceCounters(rx_bytes=1000 if self.n == 1 else 1))}
        cfg = dune.MonitorConfig(include=["eth0"])
        state = dune.MonitorState(cfg, Reader())
        state.update()
        state.update()
        self.assertEqual(state.interfaces["eth0"].counter_resets, 1)
        self.assertEqual(state.interfaces["eth0"].baseline.rx_bps.count, 0)
        self.assertTrue(any(e.category == "counter_reset" for e in state.global_events))
        state.store.close()


if __name__ == "__main__":
    unittest.main()
