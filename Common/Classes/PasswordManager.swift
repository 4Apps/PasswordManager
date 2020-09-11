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
let kCommonCryptoErrorDomain: String = "CommonCryptoErrorDomain"

func getSlicedArray(_ bytes: UnsafePointer<Int8>, start: Int, length: Int) -> UnsafeMutablePointer<Int8> {
    let targetArray = UnsafeMutablePointer<Int8>.allocate(capacity: length * MemoryLayout<Int>.size)
    var targetIndex = 0
    for i in start..<start+length {
        targetArray[targetIndex] = bytes[i]
        targetIndex += 1
    }

    return targetArray
}


open class PasswordManager: NSObject {

    // MARK: - Hashes

    open class func hashWhirlpool(_ data: Data) -> Data? {
        var w = NESSIEstruct()
        let hash: UnsafeMutablePointer<u8> = UnsafeMutablePointer<u8>.allocate(capacity: Int(DIGESTBYTES))

        NESSIEinit(&w)
        guard let bytes = (
            data.withUnsafeBytes { body -> UnsafePointer<u8>? in
                guard let rawBytes = body.bindMemory(to: u8.self).baseAddress else {
                    return nil
                }
                return rawBytes
            }
        ) else {
            return nil
        }
        NESSIEadd(bytes, UInt(data.count * 8), &w)
        NESSIEfinalize(&w, hash)

        let returnData = Data(bytes: UnsafeRawPointer(hash), count: Int(DIGESTBYTES))
        free(hash)

        return returnData
    }


    open class func hashSHA256(_ data: Data) -> Data? {
        let hash: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))

        let returnData = data.withUnsafeBytes { body -> Data? in
            guard let rawBytes = body.bindMemory(to: u8.self).baseAddress else {
                return nil
            }

            if CC_SHA256(rawBytes, CC_LONG(data.count), hash) != nil {
                return Data(bytes: UnsafeRawPointer(hash), count: Int(CC_SHA256_DIGEST_LENGTH))
            }

            return nil
        }

        free(hash)
        return returnData
    }


    // MARK: - Encrypt

    class func errorWithCCCryptorStatus(_ status: CCCryptorStatus) -> NSError {
        var description: String = ""
        var reason: String? = nil

        switch (Int(status)) {
            case kCCSuccess:
                description = NSLocalizedString("Success", comment: "Error description")
            break

            case kCCParamError:
                description = NSLocalizedString("Parameter Error", comment: "Error description")
                reason = NSLocalizedString("Illegal parameter supplied to encryption/decryption algorithm", comment: "Error reason")
            break

            case kCCBufferTooSmall:
                description = NSLocalizedString("Buffer Too Small", comment: "Error description")
                reason = NSLocalizedString("Insufficient buffer provided for specified operation", comment: "Error reason")
            break

            case kCCMemoryFailure:
                description = NSLocalizedString("Memory Failure", comment: "Error description")
                reason = NSLocalizedString("Failed to allocate memory", comment: "Error reason")
            break

            case kCCAlignmentError:
                description = NSLocalizedString("Alignment Error", comment: "Error description")
                reason = NSLocalizedString("Input size to encryption algorithm was not aligned correctly", comment: "Error reason")
            break

            case kCCDecodeError:
                description = NSLocalizedString("Decode Error", comment: "Error description")
                reason = NSLocalizedString("Input data did not decode or decrypt correctly", comment: "Error reason")
            break

            case kCCUnimplemented:
                description = NSLocalizedString("Unimplemented Function", comment: "Error description")
                reason = NSLocalizedString("Function not implemented for the current algorithm", comment: "Error reason")
            break

            default:
                description = NSLocalizedString("Unknown Error", comment: "Error description")
            break
        }

        var userInfo = [AnyHashable: Any]()
        userInfo[NSLocalizedDescriptionKey] = description

        if reason != nil {
            userInfo[NSLocalizedFailureReasonErrorKey] = reason!
        }

        return NSError(domain: kCommonCryptoErrorDomain, code: Int(status), userInfo: userInfo as? [String : Any])
    }


    open class func encryptAES128(_ data: Data, key: Data, iv: Data, error: inout CCCryptorStatus?) -> Data? {
        var outLength = Int()
        let bufferLength = data.count + kCCBlockSizeAES128
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)

        // Interesting stuff, but I guess this is the safe way
        let result = key.withUnsafeBytes({ (keyBody: UnsafePointer<UInt8>) -> CCCryptorStatus in
            return iv.withUnsafeBytes({ (ivBody: UnsafePointer<UInt8>) -> CCCryptorStatus in
                return data.withUnsafeBytes({ (dataBody: UnsafePointer<UInt8>) -> CCCryptorStatus in
                    return CCCrypt(
                        CCOperation(kCCEncrypt), // operation
                        CCAlgorithm(kCCAlgorithmAES128), // Algorithm
                        CCOptions(kCCOptionPKCS7Padding), // options
                        keyBody, // key
                        key.count, // keylength
                        ivBody, // iv
                        dataBody, // dataIn
                        data.count, // dataInLength,
                        buffer, // dataOut
                        bufferLength, // dataOutAvailable
                        &outLength
                    )
                })
            })
        })

        if (result == CCCryptorStatus(kCCSuccess)) {
            let returnData = Data(bytes: buffer, count: outLength)
            free(buffer)

            return returnData
        } else {
            error = result

            free(buffer)
            return nil
        }
    }


    open class func decryptAES128(_ data: Data, key: Data, iv: Data, error: inout CCCryptorStatus?) -> Data? {
        var outLength = Int()
        let bufferLength = data.count + kCCBlockSizeAES128
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)

        // Interesting stuff, but I guess this is the safe way
        let result = key.withUnsafeBytes({ (keyBody: UnsafePointer<UInt8>) -> CCCryptorStatus in
            return iv.withUnsafeBytes({ (ivBody: UnsafePointer<UInt8>) -> CCCryptorStatus in
                return data.withUnsafeBytes({ (dataBody: UnsafePointer<UInt8>) -> CCCryptorStatus in
                    return CCCrypt(
                        CCOperation(kCCDecrypt), // operation
                        CCAlgorithm(kCCAlgorithmAES128), // Algorithm
                        CCOptions(kCCOptionPKCS7Padding), // options
                        keyBody, // key
                        key.count, // keylength
                        ivBody, // iv
                        dataBody, // dataIn
                        data.count, // dataInLength,
                        buffer, // dataOut
                        bufferLength, // dataOutAvailable
                        &outLength //dataOutMoved
                    )
                })
            })
        })

        if (result == CCCryptorStatus(kCCSuccess)) {
            let returnData = Data(bytes: buffer, count: outLength)
            free(buffer)

            return returnData
        } else {
            error = result
            free(buffer)

            return nil
        }
    }


    open class func encryptTwofish(_ data: Data, key: Data, iv: Data, error: inout CCCryptorStatus?) -> Data? {
        let bufferLength = data.count + TwoFish_BLOCK_SIZE
        let buffer = UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>.allocate(capacity: bufferLength + TwoFish_BLOCK_SIZE)

        let tf = key.withUnsafeBytes({ (keyBody: UnsafePointer<UInt8>) -> UnsafeMutablePointer<TWOFISH>? in
            return TwoFishInit(
                keyBody, // key
                UInt32(key.count)
            )
        })

        var data = data
        let outLength = data.withUnsafeMutableBytes({ (dataBody: UnsafeMutablePointer<UInt8>) -> Int in
            return Int(TwoFishEncrypt(
                dataBody, // dataIn
                buffer,
                bufferLength,
                0,
                tf
            ))
        })

        TwoFishDestroy(tf)

        if (outLength == 0) {
            error = CCCryptorStatus(kCCParamError)
            return nil
        }

        let encryptedData = Data(bytes: buffer.pointee!, count: outLength)
        free(buffer)

        return encryptedData
    }


    open class func decryptTwofish(_ data: Data, key: Data, iv:Data, error: inout CCCryptorStatus?) -> Data? {
        let bufferLength = Int(data.count) - TwoFish_BLOCK_SIZE
        let buffer = UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>.allocate(capacity: bufferLength + TwoFish_BLOCK_SIZE)

        let tf = key.withUnsafeBytes({ (keyBody: UnsafePointer<UInt8>) -> UnsafeMutablePointer<TWOFISH>? in
            return TwoFishInit(
                keyBody, // key
                UInt32(key.count)
            )
        })

        var data = data
        let outLength = data.withUnsafeMutableBytes({ (dataBody: UnsafeMutablePointer<UInt8>) -> Int in
            return Int(TwoFishDecrypt(
                dataBody, // dataIn
                buffer,
                bufferLength,
                0,
                tf
            ))
        })
        TwoFishDestroy(tf)

        if (outLength == 0) {
            error = CCCryptorStatus(kCCDecodeError)
            return nil
        }

        let decryptedData = Data(bytes: buffer.pointee!, count:outLength)
        free(buffer)

        return decryptedData
    }


    // MARK: - Data encryption

    open class func generatePasswordHashWithString(_ password: String, salt: Data) -> Data? {
        // Append salt to password
        let passwordData = (password.data(using: String.Encoding.utf8) as NSData?)?.mutableCopy() as? NSMutableData
        if passwordData == nil {
            return nil
        }
        passwordData!.append(salt)

        // Generate hash
        var passwordHash =  NSData(data: passwordData! as Data) as Data
        for _ in 0..<4999 {
            let tmp1 = self.hashWhirlpool(passwordHash)
            if (tmp1 == nil) {
                return nil
            }
            passwordHash = tmp1!

            let tmp2 = self.hashSHA256(passwordHash)
            if (tmp2 == nil) {
                return nil
            }
            passwordHash = tmp2!
        }

        return passwordHash
    }


    open class func encryptData(_ data: Data, withPassword password: String, error: inout NSError?) -> Data? {
        // Generate salt and iv
        guard let iv = self.randomDataOfLength(kCCBlockSizeAES128) else {
            var userInfo = [AnyHashable: Any]()
            userInfo[NSLocalizedDescriptionKey] = "Could not create iv. Memory issues?"
            error = NSError(domain: kCommonCryptoErrorDomain, code: -100, userInfo: userInfo as? [String : Any])

            return nil
        }

        guard let salt = self.randomDataOfLength(16) else {
            var userInfo = [AnyHashable: Any]()
            userInfo[NSLocalizedDescriptionKey] = "Could not create salt. Memory issues?"
            error = NSError(domain: kCommonCryptoErrorDomain, code: -100, userInfo: userInfo as? [String : Any])

            return nil
        }

        // Generate hash
        guard let passwordHash = self.generatePasswordHashWithString(password, salt: salt) else {
            var userInfo = [AnyHashable: Any]()
            userInfo[NSLocalizedDescriptionKey] = "Could not create password hash. Memory issues?"
            error = NSError(domain: kCommonCryptoErrorDomain, code: -100, userInfo: userInfo as? [String : Any])

            return nil
        }

        // Pass 1
        var status: CCCryptorStatus?
        var result = self.encryptAES128(data, key: passwordHash, iv: iv, error: &status)
        if result == nil {
            error = self.errorWithCCCryptorStatus(status!)

            return nil
        }

        // Pass 2
        result = self.encryptTwofish(result!, key: passwordHash, iv: iv, error: &status)
        if result == nil {
            error = self.errorWithCCCryptorStatus(status!)

            return nil
        }

        // Return data
        var mutableResult = result
        mutableResult!.append(salt)
        mutableResult!.append(iv)
        mutableResult!.append(VERSION.data(using: String.Encoding.utf8)!)

        return mutableResult
    }


    open class func decryptData(_ data: Data, withPassword password: String, error: inout NSError?) -> Data? {
        // Check data
        if data.count < kCCBlockSizeAES128 + 16 + 4 {
            error = self.errorWithCCCryptorStatus(CCCryptorStatus(kCCDecodeError))

            return nil
        }

        // Parse data
        let bytes = (data as NSData).bytes.bindMemory(to: Int8.self, capacity: data.count)
        let length = data.count
        // **int** should be good for 2GB, way to much for passwords anyway

        // For now this is not used as there is only one version as of yet
//        let versionBytes = getSlicedArray(bytes, start: length - 4, length: 4)
//        _ = Data(bytes: versionBytes, count: 4)
//        free(versionBytes)

        let ivBytes = getSlicedArray(bytes, start: length - 4 - kCCBlockSizeAES128, length: kCCBlockSizeAES128)
        let iv = Data(bytes: ivBytes, count: kCCBlockSizeAES128)
        free(ivBytes)

        let saltBytes = getSlicedArray(bytes, start: length - 4 - kCCBlockSizeAES128 - 16, length: kCCBlockSizeAES128)
        let salt = Data(bytes: saltBytes, count: 16)
        free(saltBytes)

        let encryptedDataLength = length - (4 + kCCBlockSizeAES128 + 16)
        let encryptedBytes = getSlicedArray(bytes, start: 0, length: encryptedDataLength)
        let encryptedData = Data(bytes: encryptedBytes, count: encryptedDataLength)
        free(encryptedBytes)

        // Generate hash
        let passwordHash = self.generatePasswordHashWithString(password, salt: salt)

        // Decrypt pass 1
        var status: CCCryptorStatus?
        var result = self.decryptTwofish(encryptedData, key: passwordHash!, iv: iv, error:&status)
        if result == nil {
            error = self.errorWithCCCryptorStatus(status!)

            return nil
        }

        // Decrypt pass 2
        result = self.decryptAES128(result!, key: passwordHash!, iv: iv, error:&status)
        if result == nil {
            error = self.errorWithCCCryptorStatus(status!)

            return nil
        }

        return result
    }


    // MARK: - Helpers

    class func randomDataOfLength(_ length: size_t) -> Data? {
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: length)

        let result = SecRandomCopyBytes(kSecRandomDefault, length, buffer)
        if result == 0 {
            let returnData = Data(bytes: buffer, count: length)
            free(buffer)

            return returnData
        }

        free(buffer)
        return nil
    }


    class func hexadecimalEncodedStringWithData(_ data: Data) -> String? {
        guard let hexChars = ("0123456789ABCDEF" as NSString).utf8String else {
            return nil
        }

        let returnData = data.withUnsafeBytes({ (srcBody: UnsafePointer<UInt8>) -> Data in
            let slen = data.count
            let dlen = slen * 2
            let dst = UnsafeMutablePointer<Int8>.allocate(capacity: dlen)
            var spos = 0
            var dpos = 0
            var c: Int
            while (spos < slen) {
                c = Int(srcBody[spos])
                spos += 1

                dst[dpos] = (hexChars[(c >> 4) & 0x0f])
                dpos += 1

                dst[dpos] = (hexChars[c & 0x0f])
                dpos += 1
            }

            let returnData = Data(bytes: dst, count:dlen)
            free(dst)

            return returnData
        })

        return String(data: returnData, encoding:String.Encoding.utf8)
    }

}
