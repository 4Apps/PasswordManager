//
//  PasswordManager_iOS_Tests.swift
//  PasswordManager iOS Tests
//
//  Created by Gints Murans on 25/10/14.
//  Copyright (c) 2014 Early Bird. All rights reserved.
//

import UIKit
import XCTest
import PasswordManager

class PasswordManager_iOS_Tests: XCTestCase {
    
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
        
        var data = "SECURE ME !!!".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        var encData: NSData = PasswordManager.v1_encryptData(data, withPassword: "parole mana", error: &error) as NSData
        
        NSLog("Encrypted data: (%d) %@", encData.length, encData);
        
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
    
//    func testPerformanceExample() {
//        // This is an example of a performance test case.
//        self.measureBlock() {
//
//    for (var i = 0; i <= 5000; i++)
//    {
//    var a = PasswordManager.hash1WithString("man ir loti gara parole kadai tai jabut butu")
//    var b = PasswordManager.hash2WithData(a)
//    }
    
//        }
//    }
    
}
