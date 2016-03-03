//
//  PasswordManager.m
//  PasswordManager
//
//  Created by Gints Murans on 24/06/14.
//  Copyright (c) 2014 Early Bird. All rights reserved.
//


#import "aes.h"
#import "Twofish.h"
#import "Whirlpool.h"
#import "PasswordManager.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>


#define VERSION @"v001"


NSString *const kCommonCryptoErrorDomain = @"CommonCryptoErrorDomain";

char *getSlicedArray(const char *bytes, int start, int length)
{
    char *targetArray = (char *) malloc(length * sizeof(char));
    int targetIndex = 0;
    for (int i=start; i < start + length; i++)
    {
        targetArray[targetIndex++] = bytes[i];
    }
    return targetArray;
}


@implementation PasswordManager

#pragma mark - Hashes

+ (NSData *)hashWhirlpool:(NSData *)data
{
    struct NESSIEstruct w;
    u8 hash[DIGESTBYTES];

    NESSIEinit(&w);
    NESSIEadd([data bytes], [data length] * 8, &w);
    NESSIEfinalize(&w, hash);

    NSData *hashData = [NSData dataWithBytes:hash length:DIGESTBYTES];
    return hashData;
}


+ (NSData *)hashSHA256:(NSData *)data
{
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    if (CC_SHA256(data.bytes, (unsigned int)data.length, hash))
    {
        NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
        return hashData;
    }
    return nil;
}



#pragma mark - Encrypt

+ (NSError *)errorWithCCCryptorStatus:(CCCryptorStatus)status
{
    NSString *description = nil, *reason = nil;

    switch ( status )
    {
        case kCCSuccess:
            description = NSLocalizedString(@"Success", @"Error description");
            break;

        case kCCParamError:
            description = NSLocalizedString(@"Parameter Error", @"Error description");
            reason = NSLocalizedString(@"Illegal parameter supplied to encryption/decryption algorithm", @"Error reason");
            break;

        case kCCBufferTooSmall:
            description = NSLocalizedString(@"Buffer Too Small", @"Error description");
            reason = NSLocalizedString(@"Insufficient buffer provided for specified operation", @"Error reason");
            break;

        case kCCMemoryFailure:
            description = NSLocalizedString(@"Memory Failure", @"Error description");
            reason = NSLocalizedString(@"Failed to allocate memory", @"Error reason");
            break;

        case kCCAlignmentError:
            description = NSLocalizedString(@"Alignment Error", @"Error description");
            reason = NSLocalizedString(@"Input size to encryption algorithm was not aligned correctly", @"Error reason");
            break;

        case kCCDecodeError:
            description = NSLocalizedString(@"Decode Error", @"Error description");
            reason = NSLocalizedString(@"Input data did not decode or decrypt correctly", @"Error reason");
            break;

        case kCCUnimplemented:
            description = NSLocalizedString(@"Unimplemented Function", @"Error description");
            reason = NSLocalizedString(@"Function not implemented for the current algorithm", @"Error reason");
            break;

        default:
            description = NSLocalizedString(@"Unknown Error", @"Error description");
            break;
    }

    NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] init];
    [userInfo setObject: description forKey: NSLocalizedDescriptionKey];
    
    if (reason != nil)
    {
        [userInfo setObject: reason forKey: NSLocalizedFailureReasonErrorKey];
    }
    
    NSError *result = [NSError errorWithDomain:kCommonCryptoErrorDomain code:status userInfo:userInfo];
    return result;
}


+ (NSData *)encryptAES128:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(CCCryptorStatus *)error
{
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     kCCAlgorithmAES128, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     iv.bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            *error = result;
        }
        return nil;
    }
    return cipherData;
}


+ (NSData *)decryptAES128:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(CCCryptorStatus *)error
{
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt, // operation
                     kCCAlgorithmAES128, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     iv.bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            *error = result;
        }
        return nil;
    }
    
    return cipherData;
}


+ (NSData *)encryptTwofish:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(CCCryptorStatus *)error
{
    int length = (int)data.length + TwoFish_BLOCK_SIZE;
    uint8_t *cipheredData = (uint8_t *)malloc(length + TwoFish_BLOCK_SIZE);
    
    TWOFISH *tf = TwoFishInit(key.bytes, (unsigned int)key.length);
    uint32_t encryptedLength = TwoFishEncrypt((uint8_t *)data.bytes, &cipheredData, data.length, false, tf);
    TwoFishDestroy(tf);
    
    if (encryptedLength == 0)
    {
        if (error)
        {
            *error = kCCParamError;
        }
        return nil;
    }
    
    NSData *encryptedData = [NSData dataWithBytes:cipheredData length:encryptedLength];
    free(cipheredData);
    
    return encryptedData;
}

+ (NSData *)decryptTwofish:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(CCCryptorStatus *)error
{
    int length = (int)data.length - TwoFish_BLOCK_SIZE;
    uint8_t *decipheredData = (uint8_t *)malloc(length + TwoFish_BLOCK_SIZE);
    
    TWOFISH *tf = TwoFishInit(key.bytes, (unsigned int)key.length);
    uint32_t decryptedLength = TwoFishDecrypt((uint8_t *)data.bytes, &decipheredData, data.length, false, tf);
    TwoFishDestroy(tf);
    
    if (decryptedLength == 0)
    {
        if (error)
        {
            *error = kCCDecodeError;
        }
        return nil;
    }
    
    NSData *decryptedData = [NSData dataWithBytes:decipheredData length:length];
    free(decipheredData);
    
    return decryptedData;
}




#pragma mark - Compilation methods


+ (NSData *)generatePasswordHashWithString:(NSString *)password andSalt:(NSData *)salt
{
    // Append salt to password
    NSMutableData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    [passwordData appendData:salt];
    NSData *passwordHash = [NSData dataWithData:passwordData];
    
    // Generate hash
    for (int i = 0; i < 4999; ++i)
    {
        passwordHash = [self hashWhirlpool:passwordHash];
        passwordHash = [self hashSHA256:passwordHash];
    }
    
    return passwordHash;
}


+ (NSData *)encryptData:(NSData *)data withPassword:(NSString *)password error:(NSError *__autoreleasing *)error
{
    // Generate salt and iv
    NSData *iv = [self randomDataOfLength:kCCBlockSizeAES128];
    NSData *salt = [self randomDataOfLength:16];

    // Generate hash
    NSData *passwordHash = [self generatePasswordHashWithString:password andSalt:salt];

    // Pass 1
    CCCryptorStatus status = kCCSuccess;
    NSData *result = [self encryptAES128:data key:passwordHash iv:iv error:&status];
    if (result == nil)
    {
        if (error)
        {
            *error = [self errorWithCCCryptorStatus:status];
        }
        return nil;
    }

    // Pass 2
    result = [self encryptTwofish:result key:passwordHash iv:iv error:&status];
    if (result == nil)
    {
        if (error)
        {
            *error = [self errorWithCCCryptorStatus:status];
        }
        return nil;
    }

    // Return data
    NSMutableData *mutableResult = [result mutableCopy];
    [mutableResult appendData:salt];
    [mutableResult appendData:iv];
    [mutableResult appendData:[VERSION dataUsingEncoding:NSUTF8StringEncoding]];

    return [mutableResult copy];
}


+ (NSData *)decryptData:(NSData *)data withPassword:(NSString *)password error:(NSError *__autoreleasing *)error
{
    // Check data
    if (data.length < kCCBlockSizeAES128 + 16 + 4)
    {
        if (error)
        {
            *error = [self errorWithCCCryptorStatus:kCCDecodeError];
        }
        return nil;
    }

    // Parse data
    const char *bytes = [data bytes];
    int length = (int)[data length];
    // **int** should be good for 2GB, way to much for passwords anyway

    char *versionBytes = getSlicedArray(bytes, length - 4, 4);
    NSData *version = [NSData dataWithBytes:versionBytes length:4];
    free(versionBytes);

    char *ivBytes = getSlicedArray(bytes, length - 4 - kCCBlockSizeAES128, kCCBlockSizeAES128);
    NSData *iv = [NSData dataWithBytes:ivBytes length:kCCBlockSizeAES128];
    free(ivBytes);

    char *saltBytes = getSlicedArray(bytes, length - 4 - kCCBlockSizeAES128 - 16, kCCBlockSizeAES128);
    NSData *salt = [NSData dataWithBytes:saltBytes length:16];
    free(saltBytes);

    int encryptedDataLength = length - (4 + kCCBlockSizeAES128 + 16);
    char *encryptedBytes = getSlicedArray(bytes, 0, encryptedDataLength);
    NSData *encryptedData = [NSData dataWithBytes:encryptedBytes length:encryptedDataLength];
    free(encryptedBytes);

    // Generate hash
    NSData *passwordHash = [self generatePasswordHashWithString:password andSalt:salt];

    // Decrypt pass 1
    CCCryptorStatus status = kCCSuccess;
    NSData *result = [self decryptTwofish:encryptedData key:passwordHash iv:iv error:&status];
    if (result == nil)
    {
        if (error)
        {
            *error = [self errorWithCCCryptorStatus:status];
        }
        return nil;
    }

    // Decrypt pass 2
    status = kCCSuccess;
    result = [self decryptAES128:result key:passwordHash iv:iv error:&status];
    if (result == nil)
    {
        if (error)
        {
            *error = [self errorWithCCCryptorStatus:status];
        }
        return nil;
    }

    return [result copy];
}




#pragma mark - Helpers

+ (NSData *)randomDataOfLength:(size_t)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result == 0)
    {
        return data;
    }
    return nil;
}


+ (NSString *)hexadecimalEncodedStringWithData:(NSData *)data
{
    static const char *hexChars = "0123456789ABCDEF";
    NSUInteger slen = [data length];
    NSUInteger dlen = slen * 2;
    const unsigned char	*src = (const unsigned char *)[data bytes];
    char *dst = (char *)NSZoneMalloc(NSDefaultMallocZone(), dlen);
    NSUInteger spos = 0;
    NSUInteger dpos = 0;
    unsigned char	c;
    while (spos < slen) {
        c = src[spos++];
        dst[dpos++] = hexChars[(c >> 4) & 0x0f];
        dst[dpos++] = hexChars[c & 0x0f];
    }
    NSData *return_data = [[NSData alloc] initWithBytesNoCopy:dst length:dlen];
    return [[NSString alloc] initWithData:return_data encoding:NSASCIIStringEncoding];
}



#pragma mark - Tests

//
////+ (NSData *)encryptTwofishTest:(NSData *)data key:(NSData *)key iv:(NSData *)iv
////{
////    int length = (int)data.length + TwoFish_BLOCK_SIZE;
////    uint8_t *cipheredData = (uint8_t *)malloc(length + TwoFish_BLOCK_SIZE);
////    
////    TWOFISH *tf = TwoFishInit(key.bytes, (unsigned int)key.length);
////    uint32_t encryptedLength = TwoFishEncrypt((uint8_t *)data.bytes, &cipheredData, data.length, false, tf);
////    TwoFishDestroy(tf);
////    
////    if (encryptedLength == 0)
////    {
////        return nil;
////    }
////    
////    NSData *encryptedData = [NSData dataWithBytes:cipheredData length:encryptedLength];
////    free(cipheredData);
////    
////    return encryptedData;
////}
//
//
//+ (NSData *)v1_encryptDataPass2:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(CCCryptorStatus *)error
//{
//    keyInstance    ki;			/* key information, including tables */
//    cipherInstance ci;			/* keeps mode (ECB, CBC) and IV */
//
//    int length = (int)data.length + BLOCK_SIZE;
//    BYTE *cipheredData = (BYTE *)malloc(length + BLOCK_SIZE);
//    NSLog(@"key: %@", key);
//    NSLog(@"key size: %d", (int)key.length * 8);
//
//    static const char *hexChars = "0123456789ABCDEF";
//    NSUInteger slen = [key length];
//    NSUInteger dlen = slen * 2;
//    const unsigned char	*src = (const unsigned char *)[key bytes];
//    char *dst = (char *)NSZoneMalloc(NSDefaultMallocZone(), dlen);
//    NSUInteger spos = 0;
//    NSUInteger dpos = 0;
//    unsigned char	c;
//    while (spos < slen) {
//        c = src[spos++];
//        dst[dpos++] = hexChars[(c >> 4) & 0x0f];
//        dst[dpos++] = hexChars[c & 0x0f];
//    }
//
//
//    if (makeKey(&ki, DIR_ENCRYPT, (int)key.length * 8, dst) != TRUE)
//    {
//        *error = kCCParamError;
//        return nil;
//    }
//    NSLog(@"2: %d", (int)ki.keyLen);
//
//    if (cipherInit(&ci, MODE_CBC, NULL) != TRUE)
//    {
//        *error = kCCParamError;
//        return nil;
//    }
//    NSLog(@"3");
//
////    memcpy(ki.key32, key.bytes, key.length);
//
//    int keySize = 256;
//    for (int i = 0; i < keySize / 32; i++)	/* select key bits */
//    {
//        ki.key32[i]=0x10003 * rand();
//        NSLog(@"%lu", ki.key32[i]);
//    }
//
//    NSLog(@"3.5");
//    reKey(&ki);					/* run the key schedule */
//    NSLog(@"4");
//
//    // copy the IV to ci
//    memcpy(ci.iv32, iv.bytes, iv.length);
//    NSLog(@"5");
//
//    // encrypt the bytes
//    int encryptCode = blockEncrypt(&ci, &ki, (BYTE *)data.bytes, (int)data.length * 8, cipheredData);
//    if (encryptCode < 0)
//    {
//        *error = kCCParamError;
//        return nil;
//    }
//    NSLog(@"6");
//    
//    NSData *encryptedData = [NSData dataWithBytes:cipheredData length:sizeof(cipheredData)];
//    free(cipheredData);
//    NSLog(@"7");
//
//    return encryptedData;
//}
//
//
////+ (NSData *)v1_decryptDataPass2:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(CCCryptorStatus *)error
////{
////    int length = (int)data.length - TwoFish_BLOCK_SIZE;
////    uint8_t *decipheredData = (uint8_t *)malloc(length + TwoFish_BLOCK_SIZE);
////    
////    TWOFISH *tf = TwoFishInit(key.bytes, (unsigned int)key.length);
////    uint32_t decryptedLength = TwoFishDecrypt((uint8_t *)data.bytes, &decipheredData, data.length, false, tf);
////    TwoFishDestroy(tf);
////    
////    if (decryptedLength == 0)
////    {
////        *error = kCCDecodeError;
////        return nil;
////    }
////    
////    NSData *decryptedData = [NSData dataWithBytes:decipheredData length:length];
////    free(decipheredData);
////    
////    return decryptedData;
////}
//
//
//
//+ (NSData *)v1_encryptData:(NSData *)data withPassword:(NSString *)password error:(NSError *__autoreleasing *)error
//{
//
//    
//    // Generate salt and iv
//    NSData *iv = [self randomDataOfLength:kCCBlockSizeAES128];
//    NSData *salt = [self randomDataOfLength:16];
//    
//    // Generate hash
//    NSData *passwordHash = [self generatePasswordHashWithString:password andSalt:salt];
//
//
////
////    //    // Pass 1
//    CCCryptorStatus status = kCCSuccess;
////    //    NSData *result = [self encryptedData1WithData:data key:passwordHash iv:iv error:&status];
////    //    if (result == nil)
////    //    {
////    //        if (error != NULL)
////    //        {
////    //            *error = [self errorWithCCCryptorStatus:status];
////    //        }
////    //        return nil;
////    //    }
//    
//    // Pass 2
//    NSData *result = result = [self v1_encryptDataPass2:data key:passwordHash iv:iv error:&status];
//    if (result == nil)
//    {
//        if (error != NULL)
//        {
//            *error = [self errorWithCCCryptorStatus:status];
//        }
//        return nil;
//    }
//
//    // Return data
//    NSMutableData *mutableResult = [result mutableCopy];
//    [mutableResult appendData:salt];
//    [mutableResult appendData:iv];
//    [mutableResult appendData:[VERSION dataUsingEncoding:NSUTF8StringEncoding]];
//
//
////    NSData *test = [PasswordManager v1_decryptDataPass2:[mutableResult copy] key:passwordHash iv:iv error:nil];
////    NSLog(@"Decrypted: %@", [[NSString alloc] initWithData:test encoding:NSUTF8StringEncoding]);
//
//    return [mutableResult copy];
//}


@end