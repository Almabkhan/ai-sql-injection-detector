import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqli_detector import SQLInjectionDetector

class TestSQLInjectionDetector(unittest.TestCase):
    
    def setUp(self):
        self.detector = SQLInjectionDetector()
    
    def test_import(self):
        """Test module imports correctly"""
        self.assertIsNotNone(self.detector)
    
    def test_safe_select(self):
        """Test safe SELECT query"""
        result = self.detector.analyze("SELECT * FROM users WHERE id = 1")
        self.assertFalse(result['is_malicious'])
    
    def test_malicious_or(self):
        """Test OR 1=1 injection"""
        result = self.detector.analyze("SELECT * FROM users WHERE id = 1 OR 1=1")
        self.assertTrue(result['is_malicious'])

if __name__ == '__main__':
    unittest.main()
