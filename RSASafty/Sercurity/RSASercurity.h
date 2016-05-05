//
//  RSASercurity.h
//  ZPBuluoge
//
//  Created by zhangpan on 16/4/28.
//  Copyright © 2016年 pan zhang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSASercurity : NSObject

@end

NSString * RSAEncrypt(NSString *string);
NSString * RSADecryptBase64String(NSString *base64String);