//
//  PasswordManagerOSXTests.swift
//  PasswordManagerOSXTests
//
//  Created by Gints Murans on 09.08.16.
//  Copyright © 2016. g. 4Apps. All rights reserved.
//

import XCTest
import Foundation
@testable import PasswordManager

class PasswordManagerOSXTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // HASH
        print("\nHashes:")
        let testData = "SECURE ME !!!".data(using: String.Encoding.utf8, allowLossyConversion: false)
        XCTAssertNotNil(testData)
        guard let data = testData else {
            return
        }

        let hashData1 = PasswordManager.hashWhirlpool(data)
        XCTAssertNotNil(hashData1)
        if let hashData1 = hashData1 {
            print("Whirlpool: Data Length: \(hashData1.count); Data: \(PasswordManager.hexadecimalEncodedStringWithData(hashData1))")
        }

        let hashData2 = PasswordManager.hashSHA256(data)
        XCTAssertNotNil(hashData2)
        if let hashData2 = hashData2 {
            print("SHA256: Data Length: \(hashData2.count); Data: \(PasswordManager.hexadecimalEncodedStringWithData(hashData2))")
        }


        // ENCRYPTION
        print("\nEncryption:")
        var error: NSError?

        let encData3 = PasswordManager.encryptData(data, withPassword: "AAAAA", error: &error)
        XCTAssertNil(error, "Encryption failed")

        if let encData3 = encData3 {
            print("Encrypt: Data Length: \(encData3.count); Data: \(PasswordManager.hexadecimalEncodedStringWithData(encData3))")
        }

        let path = Bundle(for: PasswordManagerOSXTests.self).path(forResource: "encrypted_test_file", ofType: nil)
        XCTAssertNotNil(path, "Couldn't find encoded data file in apps resources")

        if let path = path {
            var encodedData = Data()
            do {
                encodedData = try Data(contentsOf: URL(fileURLWithPath: path), options: Data.ReadingOptions.mappedIfSafe)
            } catch {
                XCTAssert(true, "Couldn't open encoded data file for testing")
                return
            }
            let decData4 = PasswordManager.decryptData(encodedData, withPassword: "AAAAA", error: &error)
            XCTAssertNil(error, "Decryption failed")

            if let decData4 = decData4 {
                print("Decrypt: Data Length: \(decData4.count); Data: \(decData4); String: \(String(data: decData4, encoding: String.Encoding.utf8))")
            }
        }


        // HELPERS
        print("\nHelpers:")
        print("Random data: \(PasswordManager.randomDataOfLength(30))")
        print("HEX Random data: \(PasswordManager.hexadecimalEncodedStringWithData("35".data(using: String.Encoding.utf8)!))")
        print("\n")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}
