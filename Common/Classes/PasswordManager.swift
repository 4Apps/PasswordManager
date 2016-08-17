//
//  PasswordManager.swift
//  PasswordManager
//
//  Created by Gints Murans on 09.08.16.
//  Copyright © 2016. g. 4Apps. All rights reserved.
//

import Foundation
import Twofish
import Whirlpool
import CommonCrypto


let VERSION: String = "v001"
let kCommonCryptoErrorDomain: String = "CommonCryptoErrorDomain";

func getSlicedArray(bytes: UnsafePointer<Int8>, start: Int, length: Int) -> UnsafeMutablePointer<Int8> {
    let targetArray = UnsafeMutablePointer<Int8>.alloc(length * sizeof(Int))
    var targetIndex = 0;
    for i in start..<start+length {
        targetArray[targetIndex] = bytes[i]
        targetIndex += 1
    }

    return targetArray
}


@objc public class PasswordManager: NSObject {

    // MARK: - Hashes

    public class func hashWhirlpool(let data: NSData) -> NSData? {
        var w = NESSIEstruct()
        let hash: UnsafeMutablePointer<u8> = UnsafeMutablePointer<u8>.alloc(Int(DIGESTBYTES))

        NESSIEinit(&w)
        NESSIEadd(UnsafePointer<u8>(data.bytes), UInt(data.length * 8), &w)
        NESSIEfinalize(&w, hash)

        return NSData(bytes: UnsafePointer<Void>(hash), length: Int(DIGESTBYTES))
    }


    public class func hashSHA256(let data: NSData) -> NSData? {
        let hash: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.alloc(Int(CC_SHA256_DIGEST_LENGTH))

        if CC_SHA256(data.bytes, CC_LONG(data.length), hash) != nil {
            return NSData(bytes: UnsafePointer<Void>(hash), length: Int(CC_SHA256_DIGEST_LENGTH));
        }

        return nil;
    }


    // MARK: - Encrypt

    class func errorWithCCCryptorStatus(let status: CCCryptorStatus) -> NSError {
        var description: String = ""
        var reason: String? = nil

        switch (Int(status)) {
            case kCCSuccess:
                description = NSLocalizedString("Success", comment: "Error description");
            break;

            case kCCParamError:
                description = NSLocalizedString("Parameter Error", comment: "Error description");
                reason = NSLocalizedString("Illegal parameter supplied to encryption/decryption algorithm", comment: "Error reason");
            break;

            case kCCBufferTooSmall:
                description = NSLocalizedString("Buffer Too Small", comment: "Error description");
                reason = NSLocalizedString("Insufficient buffer provided for specified operation", comment: "Error reason");
            break;

            case kCCMemoryFailure:
                description = NSLocalizedString("Memory Failure", comment: "Error description");
                reason = NSLocalizedString("Failed to allocate memory", comment: "Error reason");
            break;

            case kCCAlignmentError:
                description = NSLocalizedString("Alignment Error", comment: "Error description");
                reason = NSLocalizedString("Input size to encryption algorithm was not aligned correctly", comment: "Error reason");
            break;

            case kCCDecodeError:
                description = NSLocalizedString("Decode Error", comment: "Error description");
                reason = NSLocalizedString("Input data did not decode or decrypt correctly", comment: "Error reason");
            break;

            case kCCUnimplemented:
                description = NSLocalizedString("Unimplemented Function", comment: "Error description");
                reason = NSLocalizedString("Function not implemented for the current algorithm", comment: "Error reason");
            break;

            default:
                description = NSLocalizedString("Unknown Error", comment: "Error description");
            break;
        }

        let userInfo = NSMutableDictionary()
        userInfo.setObject(description, forKey: NSLocalizedDescriptionKey)

        if reason != nil {
            userInfo.setObject(reason!, forKey: NSLocalizedFailureReasonErrorKey)
        }

        return NSError(domain: kCommonCryptoErrorDomain, code: Int(status), userInfo: userInfo as [NSObject : AnyObject])
    }


    public class func encryptAES128(data: NSData, key: NSData, iv: NSData, error: UnsafeMutablePointer<CCCryptorStatus>) -> NSData? {
        var outLength = Int()
        let cipherData = NSMutableData(length: data.length + kCCBlockSizeAES128)

        let result = CCCrypt(
            CCOperation(kCCEncrypt), // operation
            CCAlgorithm(kCCAlgorithmAES128), // Algorithm
            CCOptions(kCCOptionPKCS7Padding), // options
            key.bytes, // key
            key.length, // keylength
            iv.bytes,// iv
            data.bytes, // dataIn
            data.length, // dataInLength,
            cipherData!.mutableBytes, // dataOut
            cipherData!.length, // dataOutAvailable
            &outLength
        ); // dataOutMoved

        if (result == CCCryptorStatus(kCCSuccess)) {
            cipherData!.length = outLength;
        } else {
            if error != nil {
                error.memory = result
            }

            return nil;
        }

        return cipherData;
    }


    public class func decryptAES128(data: NSData, key: NSData, iv: NSData, error: UnsafeMutablePointer<CCCryptorStatus>) -> NSData? {
        var outLength = Int()
        let cipherData = NSMutableData(length: data.length + kCCBlockSizeAES128)

        let result = CCCrypt(
            CCOperation(kCCDecrypt), // operation
            CCAlgorithm(kCCAlgorithmAES128), // Algorithm
            CCOptions(kCCOptionPKCS7Padding), // options
            key.bytes, // key
            key.length, // keylength
            iv.bytes, // iv
            data.bytes, // dataIn
            data.length, // dataInLength,
            cipherData!.mutableBytes, // dataOut
            cipherData!.length, // dataOutAvailable
            &outLength //dataOutMoved
        )

        if (result == CCCryptorStatus(kCCSuccess)) {
            cipherData!.length = outLength
        } else {
            if error != nil {
                error.memory = result
            }

            return nil
        }

        return cipherData
    }


    public class func encryptTwofish(data: NSData, key: NSData, iv: NSData, error: UnsafeMutablePointer<CCCryptorStatus>) -> NSData? {
        let length = Int(data.length) + TwoFish_BLOCK_SIZE
        var cipheredData = UnsafeMutablePointer<UInt8>.alloc(length + TwoFish_BLOCK_SIZE)

        let tf = TwoFishInit(UnsafePointer<UInt8>(key.bytes), UInt32(key.length))
        let encryptedLength = TwoFishEncrypt(UnsafeMutablePointer<UInt8>(data.bytes), &cipheredData, data.length, 0, tf)
        TwoFishDestroy(tf)

        if (encryptedLength == 0) {
            if error != nil {
                error.memory = CCCryptorStatus(kCCParamError)
            }

            return nil
        }

        let encryptedData = NSData(bytes: cipheredData, length:Int(encryptedLength))
        free(cipheredData)

        return encryptedData
    }


    public class func decryptTwofish(data: NSData, key: NSData, iv:NSData, error: UnsafeMutablePointer<CCCryptorStatus>) -> NSData? {
        let length = Int(data.length) - TwoFish_BLOCK_SIZE
        var decipheredData = UnsafeMutablePointer<UInt8>.alloc(length + TwoFish_BLOCK_SIZE)

        let tf = TwoFishInit(UnsafePointer<UInt8>(key.bytes), UInt32(key.length))
        let decryptedLength = TwoFishDecrypt(UnsafeMutablePointer<UInt8>(data.bytes), &decipheredData, data.length, 0, tf)
        TwoFishDestroy(tf)

        if (decryptedLength == 0) {
            if error != nil {
                error.memory = CCCryptorStatus(kCCDecodeError);
            }

            return nil;
        }

        let decryptedData = NSData(bytes: decipheredData, length:Int(decryptedLength))
        free(decipheredData);

        return decryptedData;
    }


    // MARK: - Data encryption

    public class func generatePasswordHashWithString(password: String, salt: NSData) -> NSData? {
        // Append salt to password
        let passwordData = password.dataUsingEncoding(NSUTF8StringEncoding)?.mutableCopy() as? NSMutableData
        if passwordData == nil {
            return nil;
        }
        passwordData!.appendData(salt)

        // Generate hash
        var passwordHash =  NSData(data: passwordData!)
        for _ in 0..<4999 {
            let tmp1 = self.hashWhirlpool(passwordHash)
            if (tmp1 == nil) {
                return nil;
            }
            passwordHash = tmp1!

            let tmp2 = self.hashSHA256(passwordHash)
            if (tmp2 == nil) {
                return nil;
            }
            passwordHash = tmp2!
        }

        return passwordHash;
    }


    public class func encryptData(data: NSData, withPassword password: String, error: UnsafeMutablePointer<NSError?>) -> NSData? {
        // Generate salt and iv
        let iv = self.randomDataOfLength(kCCBlockSizeAES128)
        let salt = self.randomDataOfLength(16)

        if iv == nil || salt == nil {
            let userInfo = NSMutableDictionary()
            userInfo.setObject("Could not create iv or salt. Memory issues?", forKey: NSLocalizedDescriptionKey)
            if error != nil {
                error.memory = NSError(domain: kCommonCryptoErrorDomain, code: -100, userInfo: userInfo as [NSObject : AnyObject])
            }

            return nil
        }

        // Generate hash
        let passwordHash = self.generatePasswordHashWithString(password, salt: salt!)

        // Pass 1
        var status = CCCryptorStatus(kCCSuccess)
        var result = self.encryptAES128(data, key: passwordHash!, iv: iv!, error: &status)
        if result == nil {
            if error != nil {
                error.memory = self.errorWithCCCryptorStatus(status)
            }

            return nil;
        }

        // Pass 2
        result = self.encryptTwofish(result!, key: passwordHash!, iv: iv!, error: &status)
        if result == nil {
            if error != nil {
                error.memory = self.errorWithCCCryptorStatus(status)
            }

            return nil;
        }

        // Return data
        let mutableResult = result!.mutableCopy() as! NSMutableData
        mutableResult.appendData(salt!)
        mutableResult.appendData(iv!)
        mutableResult.appendData(VERSION.dataUsingEncoding(NSUTF8StringEncoding)!)

        return mutableResult.copy() as? NSData
    }


    public class func decryptData(data: NSData, withPassword password: String, error: UnsafeMutablePointer<NSError?>) -> NSData? {
        // Check data
        if data.length < kCCBlockSizeAES128 + 16 + 4 {
            if error != nil {
                error.memory = self.errorWithCCCryptorStatus(CCCryptorStatus(kCCDecodeError))
            }

            return nil
        }

        // Parse data
        let bytes = UnsafePointer<Int8>(data.bytes)
        let length = data.length
        // **int** should be good for 2GB, way to much for passwords anyway

        let versionBytes = getSlicedArray(bytes, start: length - 4, length: 4)
        _ = NSData(bytes: versionBytes, length: 4)
        free(versionBytes)

        let ivBytes = getSlicedArray(bytes, start: length - 4 - kCCBlockSizeAES128, length: kCCBlockSizeAES128);
        let iv = NSData(bytes: ivBytes, length: kCCBlockSizeAES128)
        free(ivBytes)

        let saltBytes = getSlicedArray(bytes, start: length - 4 - kCCBlockSizeAES128 - 16, length: kCCBlockSizeAES128);
        let salt = NSData(bytes: saltBytes, length: 16)
        free(saltBytes)

        let encryptedDataLength = length - (4 + kCCBlockSizeAES128 + 16)
        let encryptedBytes = getSlicedArray(bytes, start: 0, length: encryptedDataLength)
        let encryptedData = NSData(bytes: encryptedBytes, length: encryptedDataLength)
        free(encryptedBytes)

        // Generate hash
        let passwordHash = self.generatePasswordHashWithString(password, salt: salt)

        // Decrypt pass 1
        var status = CCCryptorStatus(kCCSuccess)
        var result = self.decryptTwofish(encryptedData, key: passwordHash!, iv: iv, error:&status)
        if result == nil {
            if error != nil {
                error.memory = self.errorWithCCCryptorStatus(status)
            }

            return nil;
        }

        // Decrypt pass 2
        result = self.decryptAES128(result!, key: passwordHash!, iv: iv, error:&status)
        if result == nil {
            if error != nil {
                error.memory = self.errorWithCCCryptorStatus(status)
            }

            return nil;
        }

        return result!.copy() as? NSData
    }


    // MARK: - Helpers

    class func randomDataOfLength(length: size_t) -> NSData? {
        let data = NSMutableData(length: length)
        if data == nil {
            return nil
        }

        let result = SecRandomCopyBytes(kSecRandomDefault, length, UnsafeMutablePointer<UInt8>(data!.mutableBytes));
        if result == 0 {
            return data
        }

        return nil
    }


    class func hexadecimalEncodedStringWithData(data: NSData) -> NSString? {
        let hexChars = ("0123456789ABCDEF" as NSString).UTF8String
        let slen = data.length
        let dlen = slen * 2
        let src = UnsafePointer<Int8>(data.bytes)
        let dst = UnsafeMutablePointer<Int8>.alloc(dlen)
        var spos = 0
        var dpos = 0
        var c: Int
        while (spos < slen) {
            c = Int(src[spos])
            spos += 1

            dst[dpos] = hexChars[(c >> 4) & 0x0f]
            dpos += 1

            dst[dpos] = hexChars[c & 0x0f]
            dpos += 1
        }

        let return_data = NSData(bytesNoCopy: dst, length:dlen)
        return String(data: return_data, encoding:NSASCIIStringEncoding)
    }

}
