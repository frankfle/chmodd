//
//  chmodd_prefpanePref.m
//  chmodd_prefpane
//
//  Created by Frank Fleschner on 6/7/2010.
//  Copyright (c) 2010 Backlight Software. All rights reserved.
//

#import "chmodd_prefpanePref.h"
#import <unistd.h>
#import <grp.h>
#import <pwd.h>

#define RIGHT "com.backlight.chmodd.admin"
#define CONFIG_FILE_PATH @"/etc/chmodd.conf"
#define LAUNCHD_JOB_PATH @"/Library/LaunchDaemons/com.backlight.chmodd.plist"
#define HELPER_TOOL @"chmodd_prefpane_helper"

@implementation chmodd_prefpanePref

@synthesize dataController;
@synthesize enableButton;
@synthesize addRowButton;
@synthesize removeRowButton;
@synthesize commitButton;
@synthesize mainTableView;
@synthesize lock;


- (NSTask *)createTask
{
	NSPipe *inPipe;
	NSTask *task;
	
	task = [[NSTask alloc] init];
	
	[task setLaunchPath:[[NSBundle bundleForClass:[self class]] pathForResource:HELPER_TOOL ofType:@""]];
	[task setEnvironment:[NSDictionary dictionary]];
	
	inPipe = [[NSPipe alloc] init];
	
	[task setStandardInput:inPipe];
	
	[inPipe release];
	
	return [task autorelease];
}

- (NSData *)authorizationAsData
{
	AuthorizationRef auth = [[lock authorization] authorizationRef];
	AuthorizationExternalForm extAuth;
	
	// If error, just return nil.
	if (AuthorizationMakeExternalForm(auth, &extAuth))
		return nil;
	
	return [NSData dataWithBytes:&extAuth length:sizeof(extAuth)];
}

- (void)updateUI
{
	[commitButton setEnabled:([lock authorizationState] == SFAuthorizationViewUnlockedState)];
	[enableButton setEnabled:([lock authorizationState] == SFAuthorizationViewUnlockedState)];
	[addRowButton setEnabled:([lock authorizationState] == SFAuthorizationViewUnlockedState)];
	[removeRowButton setEnabled:([lock authorizationState] == SFAuthorizationViewUnlockedState)];
	[mainTableView setEnabled:([lock authorizationState] == SFAuthorizationViewUnlockedState)];
	
	
	if ([lock authorizationState] == SFAuthorizationViewUnlockedState)
	{
		NSTask *checkTask = [self createTask];
		NSData *authData = [self authorizationAsData];
		NSFileHandle *inFile = [[checkTask standardInput] fileHandleForWriting];

		[checkTask setArguments:[NSArray arrayWithObject:@"-C"]];
		
		[checkTask launch];
		
		[inFile writeData:authData];
		[inFile closeFile];

		[checkTask waitUntilExit];
		
		int term = [checkTask terminationStatus];
		
		NSLog(@"checkTask reports %d as terminationStatus.", term);
		
		[enableButton setState:(term == 5) ? NSOnState : NSOffState];
	}
	else
	{
		[enableButton setState:NSOffState];
	}

}

- (void)installLaunchdItemIfNeeded
{
	BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:LAUNCHD_JOB_PATH];
	
	if (!exists)
	{
		NSLog(@"Attempting to move file");
		
		NSString *filePath = @"/tmp/chmodd_launchd.plist";
		
		NSString *templateFilePath = [[NSBundle bundleForClass:[self class]] pathForResource:@"com.backlight.chmodd" ofType:@"plist"];
		
		[[NSFileManager defaultManager] copyItemAtPath:templateFilePath toPath:filePath error:nil];
		
		NSTask *myTask = [self createTask];
		NSData *authData = [self authorizationAsData];
		NSFileHandle *inFile = [[myTask standardInput] fileHandleForWriting];
		
		[myTask setArguments:[NSArray arrayWithObjects:@"-L", filePath, nil]];
		
		NSLog(@"Launching task to move file.\nfilePath=%@\ntemplateFilePath=%@", filePath, templateFilePath);
		[myTask launch];
		[inFile writeData:authData];
		[inFile closeFile];
		[myTask waitUntilExit];
	}
}


- (void)authorizationViewDidAuthorize:(SFAuthorizationView *)view
{
	[self updateUI];
	
	// At this point, run our helper with -c force it to check it's permissions
	NSTask *checkTask = [self createTask];
	
	[checkTask setArguments:[NSArray arrayWithObject:@"-c"]];
	
	[checkTask launch];
	[checkTask waitUntilExit];

	[self installLaunchdItemIfNeeded];
}

- (void)authorizationViewDidDeauthorize:(SFAuthorizationView *)view
{
	[self updateUI];
}

- (BOOL)displayError:(NSString *)errorMessage andInput:(NSString *)input recoverable:(BOOL)recover
{
	NSInteger userReturnedValue;
	userReturnedValue = NSRunAlertPanel(@"Configuration Error!",
										[NSString stringWithFormat:@"Error on input %@.  Error Message: %@", input, errorMessage],
										(recover) ? @"Go Back" : @"Okay",
										(recover) ? @"Ignore" : nil,
										nil,
										nil);
	
	return ((userReturnedValue == NSAlertAlternateReturn) && recover);
}

- (BOOL)evaluateData
{
	int i = 0;	
	NSString *path;
	NSString *permissionsString;
	NSString *ownerString;
	NSString *groupString;
	const char	*permissions;
	mode_t *AuthPermissions;
	
	// Loop through the objects, validating data as we go.
	for (i = 0; i < [[dataController arrangedObjects] count]; i++)
	{
		// Current object:
		NSDictionary *currentDictionary = [[dataController arrangedObjects] objectAtIndex:i];
		NSLog(@"Evaluating data: %@" , currentDictionary);
		
		// Get path for current object:
		path = [currentDictionary objectForKey:@"_path"];
		NSLog(@"Path = %@", path);
		
		BOOL createChecked = [[currentDictionary objectForKey:@"_create"] boolValue];
		
		if (path == @" " || path == nil || path == @"") 
		{
			// TODO: Update to use NSAlert
			NSLog(@"Path is empty");
			[self displayError:@"Must input path!" andInput:@"" recoverable:NO];
			return NO;
		}
		else if (![[NSFileManager defaultManager] fileExistsAtPath:path] && !createChecked)
		{
			NSLog(@"Unsuccesful Path");
			[self displayError:@"Invalid Path" andInput:@"" recoverable:NO];
			return NO;
		}
		else 
		{
			NSLog(@"Path succesful");
		}
		
		// Check permissions:
		permissionsString = [currentDictionary objectForKey:@"_permissions"];
		permissions = [permissionsString cStringUsingEncoding:NSUTF8StringEncoding];
		
		NSLog(@"permissions = %s", permissions);

		if ((AuthPermissions = setmode(permissions)) == NULL) 
		{
			NSLog(@"Permissions is invalid");
			[self displayError:@"Invalid permissions string, consult chmod(1) man page for more info!"
					  andInput:permissionsString
				   recoverable:NO];
			return NO;
		}
		else 
		{
			NSLog(@"Permissions is valid");
		}

		// Check Owner:
		ownerString = [currentDictionary objectForKey:@"_owner"];
		NSCharacterSet *nonNumericCharacterSet = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
		
		if (ownerString == nil)
		{
			// Not specifying owner.  That's fine.
		}
		else if ([ownerString isEqualToString:@"0"])
		{
			// Root case:
			// We're good.
		}
		else if ([ownerString rangeOfCharacterFromSet:nonNumericCharacterSet].location == NSNotFound)
		{
			// Integer case:
			struct passwd *password_entry = NULL;
			password_entry = getpwuid([ownerString intValue]);
			
			if (!password_entry)
			{
				if (![self displayError:@"Invalid user id" andInput:ownerString recoverable:YES]) {
					return NO;
				}
				
			}
			
		}
		else
		{
			// username case (typed in username, ie, root)
			const char *cName = [ownerString UTF8String];
			
			struct passwd *password_entry = NULL;
			
			password_entry = getpwnam(cName);
			
			if (!password_entry)
			{
				[self displayError:@"Invalid username" andInput:ownerString recoverable:NO];
				return NO;
			}
		}

		// Check Group:
		groupString = [currentDictionary objectForKey:@"_group"];
		NSCharacterSet *nonDigitCharacterSet = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
		
		if (groupString == nil)
		{
			// Not specifying group.  That's fine.
		}
		else if ([groupString isEqualToString:@"0"])
		{
			// Root case:
			// We're good.
		}
		else if ([groupString rangeOfCharacterFromSet:nonDigitCharacterSet].location == NSNotFound)
		{
			// Integer case:
			struct group *group_entry = NULL;
			group_entry = getgrgid([groupString intValue]);
			
			if (!group_entry)
			{
				if (![self displayError:@"Invalid user id" andInput:groupString recoverable:YES]) {
					return NO;
				}
				
			}
			
		}
		else
		{
			// username case (typed in username, ie, root)
			const char *cName = [groupString UTF8String];
			
			struct group *group_entry = NULL;
			
			group_entry = getgrnam(cName);
			
			if (!group_entry)
			{
				[self displayError:@"Invalid username" andInput:groupString recoverable:NO];
				return NO;
			}
		}
		
		
	}
	
	return YES;
}

- (IBAction)commitButtonAction:(id)sender
{
	BOOL status = [self evaluateData];
	
	if (!status)
	{
		// Display Error
		return;
	}
	
	NSString *filePath = @"/tmp/chmodd_temp_file.plist";
	
	// Writes the objects held within datacontroller to a temp file on the desktop
	[[dataController arrangedObjects] writeToURL:[NSURL fileURLWithPath:filePath] atomically:YES];
	
	// At this point, run our helper with -m force it to check it's permissions
	NSTask *moveTask = [self createTask];
	
	[moveTask setArguments:[NSArray arrayWithObjects:@"-m", filePath, nil]];

	NSData *authData = [self authorizationAsData];
	NSFileHandle *inFile = [[moveTask standardInput] fileHandleForWriting];

	[moveTask launch];
	
	[inFile writeData:authData];
	[inFile closeFile];

	[moveTask waitUntilExit];
	
	int returnStatus = [moveTask terminationStatus];
	
	NSLog(@"helper_tool return code = %d", returnStatus);
}

- (IBAction)enableButtonAction:(id)sender
{
	if ([sender state] == NSOnState)
	{
		NSTask *moveTask = [self createTask];
		
		[moveTask setArguments:[NSArray arrayWithObjects:@"-l", nil]];
		
		NSData *authData = [self authorizationAsData];
		NSFileHandle *inFile = [[moveTask standardInput] fileHandleForWriting];
		
		[moveTask launch];
		
		[inFile writeData:authData];
		[inFile closeFile];
		
		[moveTask waitUntilExit];
		
		int returnStatus = [moveTask terminationStatus];
		
		NSLog(@"helper_tool return code = %d", returnStatus);
	}
	else
	{
		NSTask *moveTask = [self createTask];
		
		[moveTask setArguments:[NSArray arrayWithObjects:@"-u", nil]];
		
		NSData *authData = [self authorizationAsData];
		NSFileHandle *inFile = [[moveTask standardInput] fileHandleForWriting];
		
		[moveTask launch];
		
		[inFile writeData:authData];
		[inFile closeFile];
		
		[moveTask waitUntilExit];
		
		int returnStatus = [moveTask terminationStatus];
		
		NSLog(@"helper_tool return code = %d", returnStatus);		
	}
}

- (void) mainViewDidLoad
{
	// Set up the authorization view
	AuthorizationItem right = {RIGHT, 0, NULL, 0};
	AuthorizationRights rights = {1, &right};
	AuthorizationFlags flags = kAuthorizationFlagDefaults |
	kAuthorizationFlagExtendRights;
	[lock setDelegate:self];
	[lock setString:RIGHT];
	[lock setAuthorizationRights:&rights];
	[lock setFlags:flags];
	[lock updateStatus:self];
	[lock setAutoupdate:YES];
	
	[self updateUI];
	
	if ([lock authorizationState] == SFAuthorizationViewUnlockedState)
	{
		[self installLaunchdItemIfNeeded];
	}
	
	if ([[NSFileManager defaultManager] fileExistsAtPath:CONFIG_FILE_PATH])
	{
		NSArray *tempArray = [NSArray arrayWithContentsOfURL:[NSURL fileURLWithPath:CONFIG_FILE_PATH]];
		[dataController addObjects:tempArray];
	}
}

@end
