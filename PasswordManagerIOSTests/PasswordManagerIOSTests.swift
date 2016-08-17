//
//  PasswordManagerIOSTests.swift
//  PasswordManagerIOSTests
//
//  Created by Gints Murans on 09.08.16.
//  Copyright © 2016. g. 4Apps. All rights reserved.
//

import XCTest
@testable import PasswordManagerIOS

class PasswordManagerIOSTests: XCTestCase {
    
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

        print("\n")

        let data = "SECURE ME !!!".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)

        let encData1 = PasswordManager.hashWhirlpool(data!)
        print("Whirlpool: Data Length: \(encData1?.length); Data: \(encData1)")

        let encData2 = PasswordManager.hashSHA256(data!)
        print("SHA256: Data Length: \(encData2?.length); Data: \(encData2)")

        print("\n")

//        var encData: NSData = PasswordManager.v1_encryptData(data, withPassword: "parole mana", error: &error) as NSData
//        NSLog("Encrypted data: (%d) %@", encData.length, encData);

        //        var decryptedData = PasswordManager.decryptData(encData, withPassword: "parole mana", error: &error)
        //        if (error != nil)
        //        {
        //            NSLog("%@", error!);
        //        }
        //        else
        //        {
        //            NSLog("Decrypted data: %@ %@", decryptedData, NSString(data: decryptedData, encoding: NSUTF8StringEncoding))
        //        }

        XCTAssertNil(error, "Pass")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }
    
}
