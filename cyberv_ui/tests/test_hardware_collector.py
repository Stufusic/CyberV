"""
Unit Tests for Local Hardware Collector
Verifies that the application can query real host machine hardware without mocks.
"""

import unittest
from cyberv_ui.hardware.collector import LocalHardwareCollector


class TestHardwareCollector(unittest.TestCase):

    def test_cpu_detection(self):
        cpu_info = LocalHardwareCollector.get_cpu_info()
        self.assertIsInstance(cpu_info, str)
        self.assertTrue(len(cpu_info) > 0)
        self.assertIn("Luồng", cpu_info)

    def test_motherboard_detection(self):
        mb_info = LocalHardwareCollector.get_motherboard_info()
        self.assertIsInstance(mb_info, str)
        self.assertTrue(len(mb_info) > 0)

    def test_ram_detection(self):
        ram_info = LocalHardwareCollector.get_ram_info()
        self.assertIsInstance(ram_info, str)
        self.assertTrue(len(ram_info) > 0)
        self.assertIn("GB", ram_info)

    def test_observed_hardware_structure(self):
        hardware_list = LocalHardwareCollector.get_observed_hardware()
        self.assertIsInstance(hardware_list, list)
        self.assertGreaterEqual(len(hardware_list), 5)

        for item in hardware_list:
            self.assertIn("component", item)
            self.assertIn("model", item)
            self.assertIn("status", item)
            self.assertTrue(len(item["model"]) > 0)


if __name__ == "__main__":
    unittest.main()
