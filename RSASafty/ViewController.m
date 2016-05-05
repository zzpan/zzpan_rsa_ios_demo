//
//  ViewController.m
//  RSASafty
//
//  Created by panda zhang on 16/4/29.
//  Copyright © 2016年 pan zhang. All rights reserved.
//

#import "ViewController.h"
#import "RSASercurity.h"
#import <Security/Security.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *encnryt = RSAEncrypt(@"hello world");
    NSLog(@"encnryt : %@",encnryt);
    NSLog(@"%@",RSADecryptBase64String(encnryt));
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}

@end
