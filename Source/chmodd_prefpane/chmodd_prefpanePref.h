//
//  chmodd_prefpanePref.h
//  chmodd_prefpane
//
//  Created by Frank Fleschner on 6/7/2010.
//  Copyright (c) 2010 Backlight Software. All rights reserved.
//

#import <PreferencePanes/PreferencePanes.h>
#import <SecurityInterface/SFAuthorizationView.h>


@interface chmodd_prefpanePref : NSPreferencePane 
{
	NSArrayController *dataController;
	
	NSButton *enableButton;
	
	NSButton *addRowButton;
	
	NSButton *removeRowButton;
	
	NSButton *commitButton;
	
	NSTableView *mainTableView;
	
	SFAuthorizationView *lock;
	
}


@property (assign, nonatomic) IBOutlet NSArrayController *dataController;
@property (assign, nonatomic) IBOutlet NSButton *enableButton;
@property (assign, nonatomic) IBOutlet NSButton *addRowButton;
@property (assign, nonatomic) IBOutlet NSButton *removeRowButton;
@property (assign, nonatomic) IBOutlet NSButton *commitButton;
@property (assign, nonatomic) IBOutlet NSTableView *mainTableView;
@property (assign, nonatomic) IBOutlet SFAuthorizationView *lock;

- (void) mainViewDidLoad;
- (IBAction)commitButtonAction:(id)sender;
- (IBAction)enableButtonAction:(id)sender;
@end
