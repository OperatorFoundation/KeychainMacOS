import XCTest

import KeychainMacOSTests

var tests = [XCTestCaseEntry]()
tests += KeychainMacOSTests.allTests()
XCTMain(tests)
