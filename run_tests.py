#!/usr/bin/env python3
"""Test runner for the Socket Chat Application."""
import unittest
import sys
import os

if __name__ == "__main__":
    # Add project root to path
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    
    print("Discovering tests...")
    test_suite = unittest.defaultTestLoader.discover('tests')
    test_runner = unittest.TextTestRunner(verbosity=2)
    
    print("\nRunning tests...")
    result = test_runner.run(test_suite)
    
    # Report summary
    print(f"\nSummary: {result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors")
    
    # Exit with appropriate status code
    sys.exit(not result.wasSuccessful())
