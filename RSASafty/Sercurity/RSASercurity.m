//
//  RSASercurity.m
//  ZPBuluoge
//
//  Created by zhangpan on 16/4/28.
//  Copyright © 2016年 pan zhang. All rights reserved.
//

#import "RSASercurity.h"
#import <Security/Security.h>

@interface RSASercurity ()

@end

@implementation RSASercurity

@end

NSData *_stripPrivateKeyHeader(NSData *d_key);

SecKeyRef RSAPublicKey()
{
    NSString *certPath = [[NSBundle mainBundle] pathForResource:@"xinan_public_key" ofType:@"der"];
    NSData *publicKeyFileContent = [NSData dataWithContentsOfFile:certPath];
    SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault,
                                                                 ( __bridge CFDataRef)publicKeyFileContent);
    if (!certificate) {return nil;}
    
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust;
    OSStatus returnCode = SecTrustCreateWithCertificates(certificate, policy, &trust);
    if (returnCode != noErr) { return nil;}
    
    SecTrustResultType trustResultType;
    returnCode = SecTrustEvaluate(trust, &trustResultType);
    if (returnCode != noErr) { return nil;}
    
    SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
    
    CFRelease(trust);
    CFRelease(policy);
    CFRelease(certificate);
    
    return publicKey;
}


SecKeyRef RSAPrivateKey(){
    NSString *certPath = [[NSBundle mainBundle] pathForResource:@"xinan_private" ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:certPath];
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: @"pd123" forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data,
                                             (__bridge CFDictionaryRef)options,
                                             &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    
    CFRelease(items);
    return privateKeyRef;
}

NSString * RSAEncrypt(NSString *string)
{
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    SecKeyRef publicKey = RSAPublicKey();
    if (publicKey == nil) {
        NSLog(@"Get public key fail");
        return nil;
    }
    
    size_t plainLen = [string length];
    size_t keyLength = SecKeyGetBlockSize(publicKey);
    if (plainLen > keyLength - 12) {
        NSLog(@"Encrypt string  is too long");
        return nil;
    }
    
    void *plain = malloc(plainLen);
    [data getBytes:plain length:plainLen];
    void *cipher = malloc(keyLength);
    
    OSStatus returnCode = SecKeyEncrypt(publicKey,
                                        kSecPaddingPKCS1,
                                        plain,
                                        plainLen,
                                        cipher,
                                        &keyLength);
    if (returnCode != noErr) {
        NSLog(@"Encrypt error %d", (int)returnCode);
        return nil;
    }
    
    NSData * result = [NSData dataWithBytes:cipher
                                     length:keyLength];
    
    free(plain);
    free(cipher);
    CFRelease(publicKey);
    
    return [result base64EncodedStringWithOptions:0];
}

NSString * RSADecryptBase64String(NSString *base64String)
{
    NSData *data = [[NSData alloc]initWithBase64EncodedString:base64String options:0];
    SecKeyRef privateKey = RSAPrivateKey();
    if (privateKey == nil) {
        NSLog(@"Get private key fail");
        return nil;
    }
    
    size_t cipherLen = [data length];
    size_t plainLen = SecKeyGetBlockSize(privateKey)-12;
    
    void *plain = malloc(plainLen);
    void *cipher = malloc(cipherLen);
    [data getBytes:cipher length:cipherLen];
    
    OSStatus returnCode = SecKeyDecrypt(privateKey,
                                        kSecPaddingPKCS1,
                                        cipher,
                                        cipherLen,
                                        plain,
                                        &plainLen);
    
    if (returnCode != noErr) {
        NSLog(@"Encrypt error %d", (int)returnCode);
        return nil;
    }
    
    NSData * result = [NSData dataWithBytes:plain
                                     length:plainLen];
    
    free(plain);
    free(cipher);
    CFRelease(privateKey);
    
    return [[NSString alloc]initWithData:result encoding:NSUTF8StringEncoding];
}









