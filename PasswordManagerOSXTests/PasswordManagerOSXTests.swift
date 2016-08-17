//
//  PasswordManagerOSXTests.swift
//  PasswordManagerOSXTests
//
//  Created by Gints Murans on 09.08.16.
//  Copyright © 2016. g. 4Apps. All rights reserved.
//

import XCTest
@testable import PasswordManagerOSX

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
        var error: NSError?

        // HASH
        print("\n")
        let data = "SECURE ME !!!".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)

        let encData1 = PasswordManager.hashWhirlpool(data!)
        print("Whirlpool: Data Length: \(encData1?.length); Data: \(encData1)")

        let encData2 = PasswordManager.hashSHA256(data!)
        print("SHA256: Data Length: \(encData2?.length); Data: \(encData2)")


        // ENCRYPTION
        print("\n")
        let encData3 = PasswordManager.encryptData(data!, withPassword: "AAAAA", error: &error)
        print("Encrypted: Data Length: \(encData3?.length); Data: \(encData3)")

        let decData4 = PasswordManager.decryptData(encData3!, withPassword: "AAAAA", error: &error)
        if decData4 == nil {
            print("Decrypted: Error: \(error)")
        } else {
            print("Decrypted: Data Length: \(decData4?.length); Data: \(decData4); String: \(String(data: decData4!, encoding: NSUTF8StringEncoding))")
        }

        // HELPERS
        print("\n")
        print("Random data: \(PasswordManager.randomDataOfLength(30))")
        print("HEX Random data: \(PasswordManager.hexadecimalEncodedStringWithData("35".dataUsingEncoding(NSUTF8StringEncoding)!))")


        print("\n")
        XCTAssertNil(error, "Pass")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }
    
}
