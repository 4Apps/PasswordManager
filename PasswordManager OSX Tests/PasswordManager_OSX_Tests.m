//
//  PasswordManager_OSX_Tests.m
//  PasswordManager OSX Tests
//
//  Created by Gints Murans on 25/10/14.
//  Copyright (c) 2014 Early Bird. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <XCTest/XCTest.h>
#import <PasswordManager/PasswordManager.h>

@interface PasswordManager_OSX_Tests : XCTestCase

@end

@implementation PasswordManager_OSX_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    NSError *error;
    
    NSData *data = [@"SECURE ME !!!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encData = [PasswordManager encryptData:data withPassword:@"parole mana" error:&error];
    
    NSLog(@"Encrypted data: (%d) %@", (int)encData.length, encData);
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
