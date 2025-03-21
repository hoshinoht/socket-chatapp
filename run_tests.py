#!/usr/bin/env python3
"""
Test runner for the Socket Chat Application
"""
import unittest
import sys
import os

if __name__ == "__main__":
    # Add the project root to the path
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    
    # Discover and run all tests
    test_suite = unittest.defaultTestLoader.discover('tests')
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    
    # Return non-zero exit code if tests failed
    sys.exit(not result.wasSuccessful())
