/* 
 *	chmodd -- ownership and permissions enforcing daemon for Mac OS X 10.5+
 *
 *	© 2009, Backlight Software
 *
 *	Created by Frank Fleschner
 *
 *
 */

#import <sys/types.h>
#import <sys/acl.h>
#import <sys/dirent.h>
#import <sys/stat.h>
#import <dirent.h>
#import <membership.h>
#import <unistd.h>
#import <uuid/uuid.h>
#import <sys/param.h>
#import <fts.h>
#import <sys/time.h>
#import <signal.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CoreServices/CoreServices.h>
#import <pwd.h>
#import <grp.h>

#ifdef __APPLE__
#define PROGNAME getprogname()
#else
#define PROGNAME "chmodd"
#endif

#define VERSION	"0.9"

#pragma mark -
#pragma mark Dictionary Keys
#define kCHMODDPathKey				(CFSTR("_path"))
#define kCHMODDPermKey				(CFSTR("_permissions"))
#define kCHMODDForceKey				(CFSTR("_force"))
#define kCHMODDCreateKey			(CFSTR("_create"))
#define kCHMODDFollowLinkKey		(CFSTR("_followLinks"))
#define kCHMODDACLKey				(CFSTR("_acl"))
#define kCHMODDOwnerKey				(CFSTR("_owner"))
#define kCHMODDGroupKey				(CFSTR("_group"))
#define kCHMODDDebugKey				(CFSTR("_debug"))
#define kCHMODDPreScanKey			(CFSTR("_prescan"))
#define kCHMODDDescriptorKey		(CFSTR("_descriptor"))

// Global variables.
struct globals_t {
	// Control verbosity/output
	Boolean					verbose;
	Boolean					megaVerbose;
	Boolean					quiet;
	
	// For signal handling
	Boolean					rescanSignal;
	Boolean					quitSignal;
	
	// Plist file path (if provided)
	char					plistPath[PATH_MAX];
	
	// Setup for one entry (command line style)
	char					*mode;
	uid_t					owner; //unsigned int 32
	gid_t					group;
	char					directoryPath[PATH_MAX];
	int						acl; // -1 for not set, 0 for false, and 1 for set.
	Boolean					followSymbolicLinks;
	Boolean					create;
	Boolean					force;
	Boolean					prescan;
    CFAbsoluteTime          latency; // CFAbsoluteTime = typedef double
	
	// Array for FSEventStreamRef storage:
	CFMutableArrayRef		streamArray;
	
	// Time the program launched.  This is used to keep track of when the daemon
	// is launched, so we can be smart and skip over some items after we've
	// prescanned.
	time_t					launch_time;
	
	// If we're on an OS later than Leopard, we can ignore ourself by sending
	// a flag to the FSEventStreamCreate() call.  We can do it a slightly sneaky
	// way to avoid having to have a compiled version for Leopard and one for
	// later OS's.
	Boolean					ignoreSelf;
	
	CFMutableDictionaryRef	descriptorDict;
} _globals;

struct globals_t *globals = &_globals;

#pragma mark -
#pragma mark Function Prototypes

// Logs errors to stderr.
static void LogError(const char *format, ...)
__attribute__((format(printf, 1, 2)));

// For verbose (-v) output, goes to stderr.
static void LogV(const char *format, ...)
__attribute__((format(printf, 1, 2)));

// For mega-verbose (-V) output, goes to stderr.
static void LogMV(const char *format, ...)
__attribute__((format(printf, 1, 2)));

// Returns a CFPropertyList (could be CFDictionary, CFArray, etc....) from a
// path.  Returns NULL if something goes wrong.
CFPropertyListRef CreatePropertyListFromFile(const char *path);

// Returns an FSEventStreamRef configured with a given CFDictionary Object.
FSEventStreamRef EventStreamFromDictionary(CFDictionaryRef config);

// Stream Array callbacks:
void MyCFArrayReleaseCallback(CFAllocatorRef allocator,
							  const void *value);
Boolean MyCFArrayEqualCallBack(const void *value1,
							   const void *value2);
const void *MyCFArrayRetainCallBack(CFAllocatorRef allocator,
									const void *value);

// Heavy lifting.  Call back that occurs when a change is made.
void FSCallback(ConstFSEventStreamRef streamRef,
				void *clientCallBackInfo,
				size_t numEvents,
				void *eventPaths,
				const FSEventStreamEventFlags eventFlags[],
				const FSEventStreamEventId eventIds[]);

// No, this is the actual heavy lifting.  Applies what's in the config passed
// down through the tree.  Forcing recursion if necessary.
int applyPermissionsToFolder(const char *path,
							 CFDictionaryRef config,
							 Boolean force_recursion);

// Returns the UID specified in the CFString (whether the string is a username
// or a UID itself.
uid_t getUIDfromCFString(CFStringRef myString);

// Returns the GID specified in the CFString (whether the string is a username
// or a GID itself.
gid_t getGIDfromCFString(CFStringRef myString);

// Returns TRUE if the file at path does NOT have the acl specified.
Boolean fileNeedsACLApplied(const char *path, acl_t acl);

// Prints the usage to stderr
void usage(void);

// Signal related functions
void setup_signals(void);
void handle(int signal);

#pragma mark -
#pragma mark Implementation

int main (int argc, char * argv[]) {
    // insert code here...
	
	// Some defaults (see above for more info):
	globals->verbose					=	false;
	globals->megaVerbose				=	false;
	globals->quiet						=	false;
	globals->rescanSignal				=	false;
	globals->quitSignal					=	false;
	globals->mode						=	NULL;
	globals->owner						=	-1;
	globals->group						=	-1;
	globals->acl						=	-1;
	globals->force						=	false;
	globals->create						=	false;
	globals->followSymbolicLinks		=	false;
	globals->ignoreSelf					=	false;
	globals->prescan					=	false;
    globals->latency                    =   5.0;

	bzero(globals->plistPath, PATH_MAX);
	bzero(globals->directoryPath, PATH_MAX);
		
	globals->launch_time = time(NULL);
	
	CFArrayCallBacks streamArrayCallbacks;
	streamArrayCallbacks.version = 0;
	streamArrayCallbacks.retain = &MyCFArrayRetainCallBack;
	streamArrayCallbacks.release = &MyCFArrayReleaseCallback;
	streamArrayCallbacks.equal = &MyCFArrayEqualCallBack;
	globals->streamArray = CFArrayCreateMutable(kCFAllocatorDefault,
												0,
												&streamArrayCallbacks);
	
	// Determine if we can send the ignore self flag to FSEventStreamCreate()
	SInt32 minorVersion, majorVersion;
	
	if ((Gestalt(gestaltSystemVersionMajor, &majorVersion) != noErr) ||
		(Gestalt(gestaltSystemVersionMinor, &minorVersion) != noErr))
	{		
		LogError("Warning, could not determine OS Version!  (Assuming 10.5)\n");
	}
	else
	{
		globals->ignoreSelf = (majorVersion == 10 && minorVersion > 5);
	}
	
	
	// GET PARAMETERS
	char absolutePath[PATH_MAX];
   	int c; opterr = 0;
	while ((c = getopt(argc, argv, "vVPqaLHfCp:c:d:l:")) != -1)
	{
		switch (c) {
			case 'V':
				globals->megaVerbose = true;
				/* FALLTHROUGH: V implies v*/
			case 'v':
				globals->verbose = true;
				break;
			case 'q':
				globals->quiet = true;
				break;
			case 'c':
				// Get full path, or exit if we can't find the file.
				if (realpath(optarg, absolutePath) == NULL)
				{
					LogError("Cannot find file %s\n", optarg);
					exit(1);
				}
				snprintf(globals->plistPath, PATH_MAX-1, "%s", absolutePath);
				break;
			case 'd':
				if (realpath(optarg, absolutePath) == NULL)
				{
					LogError("Cannot find file %s\n", optarg);
					exit(1);
				}
				snprintf(globals->directoryPath, PATH_MAX-1, "%s", absolutePath);
				break;
            case 'l':
                globals->latency = strtod(optarg, (char **)NULL);
			case 'p':
				globals->mode = strdup(optarg);
				break;
			case 'a':
				globals->acl = true;
				break;
			case 'L':
				globals->followSymbolicLinks = true;
				break;
			case 'f':
				globals->force = true;
				break;
			case 'C':
				globals->create = true;
				break;
			case 'P':
				globals->prescan = true;
				break;
			case '?':
			default:
				if (optopt == 'p' || optopt == 'd' || optopt == 'c') {
					LogError("Option %c requires an argument.\n", optopt);
				}
				else {
					LogError("Unknown option: %c\n", 
							 isprint(optopt) ? optopt: '?');
				}
				break;
		}
	}
	
	// Print out some info in verbose mode:
	LogV("%s v%s, %s2009 Backlight, LLC.\n", PROGNAME, VERSION, "©");
	
	// Setup signal handling:
	setup_signals();
	
	// If we aren't root, display a warning.  (But keep going!!)
	if (geteuid() != 0)
	{
		LogError("WARNING: %s is much more effective (and deadly) when run as "
				 "root!\n",
				 PROGNAME);
	}
	
	// Configuring everything here.

	if (*(globals->plistPath))
	{
		CFPropertyListRef configFile = CreatePropertyListFromFile(globals->plistPath);
		if (!configFile)
		{
			LogError("Couldn't get property list from file %s.  "
					 "It could be corrupt!\n", globals->plistPath);
			exit(1);
		}
		
		CFTypeID plistType = CFGetTypeID(configFile);
		
		// Only one dictionary.  Use it as the sole configuration
		if (plistType == CFDictionaryGetTypeID())
		{
			FSEventStreamRef newStream = EventStreamFromDictionary((CFDictionaryRef)configFile);
			
			if (!newStream)
			{
				// Stream creation failed on the only config object, bail!
				LogError("Could not get a valid stream from config!\n");
				exit(1);
			}
			
			FSEventStreamScheduleWithRunLoop(newStream,
											 CFRunLoopGetCurrent(),
											 kCFRunLoopDefaultMode);
			FSEventStreamStart(newStream);
			CFArrayAppendValue(globals->streamArray, newStream);
			FSEventStreamRelease(newStream);

		}
		// If it's an array, get the dictionaries therein and use them as all
		// the configs
		else if (plistType == CFArrayGetTypeID())
		{
			int i;
			for (i = 0; i < CFArrayGetCount(configFile); i++)
			{
				CFTypeRef currObject;
				currObject = CFArrayGetValueAtIndex(configFile, i);
				CFTypeID currObjectType = CFGetTypeID(currObject);
				
				if (currObjectType == CFDictionaryGetTypeID())
				{
					FSEventStreamRef
					newStream =
						EventStreamFromDictionary((CFDictionaryRef)currObject);
					
					if (!newStream)
					{
						// Stream creation failed on the only config object, bail!
						LogError("Could not get a valid stream from config!\n");
						exit(1);
					}
					
					FSEventStreamScheduleWithRunLoop(newStream,
													 CFRunLoopGetCurrent(),
													 kCFRunLoopDefaultMode);
					FSEventStreamStart(newStream);
					CFArrayAppendValue(globals->streamArray, newStream);
					FSEventStreamRelease(newStream);
				}
				else
				{
					LogError("Plist Config File error: Expecting an array of "
							 "dictionaries!\n");
				}
			}
		}
		// If it's somthing else, then we have a problem with the plist and bail
		else
		{
			LogError("CFType at root of plist %s was not a dictionary or an "
					 "array!\n", globals->plistPath);
			exit(1);
		}
		
		CFRelease(configFile);
	 }
	else if (*(globals->directoryPath))
	{
		// Create a CFDictionary to hold our config info passed in through
		// parameters.
		
		CFMutableDictionaryRef 
		config = CFDictionaryCreateMutable(kCFAllocatorDefault,
										   0,
										   &kCFTypeDictionaryKeyCallBacks,
										   &kCFTypeDictionaryValueCallBacks);
		
		// Create CFString path and add it to config.
		CFStringRef path = CFStringCreateWithCString(kCFAllocatorDefault,
													 globals->directoryPath,
													 kCFStringEncodingUTF8);
		CFDictionarySetValue(config, kCHMODDPathKey, path);
		
		if (*(globals->mode))
		{
			CFStringRef
			perms = CFStringCreateWithCString(kCFAllocatorDefault,
											  globals->mode,
											  kCFStringEncodingUTF8);
			CFDictionarySetValue(config, kCHMODDPermKey, perms);
		}
		
		if (globals->owner != -1)
		{
			CFNumberRef owner = CFNumberCreate(kCFAllocatorDefault,
											   kCFNumberSInt32Type,
											   &(globals->owner));
			CFDictionarySetValue(config, kCHMODDOwnerKey, owner);
		}

		if (globals->group != -1)
		{
			CFNumberRef group = CFNumberCreate(kCFAllocatorDefault,
											   kCFNumberSInt32Type,
											   &(globals->group));
			CFDictionarySetValue(config, kCHMODDGroupKey, group);
		}
		if (globals->acl == true)
		{
			CFBooleanRef myBool = kCFBooleanTrue;
			CFDictionarySetValue(config, kCHMODDACLKey, myBool);
		}
		if (globals->followSymbolicLinks == true)
		{
			CFBooleanRef myBool = kCFBooleanTrue;
			CFDictionarySetValue(config, kCHMODDFollowLinkKey, myBool);
		}
		if (globals->force == true)
		{
			CFBooleanRef myBool = kCFBooleanTrue;
			CFDictionarySetValue(config, kCHMODDForceKey, myBool);
		}
		if (globals->create == true)
		{
			CFBooleanRef myBool = kCFBooleanTrue;
			CFDictionarySetValue(config, kCHMODDCreateKey, myBool);
		}
		if (globals->prescan == true)
		{
			CFBooleanRef myBool = kCFBooleanTrue;
			CFDictionarySetValue(config, kCHMODDPreScanKey, myBool);
		}
		
		FSEventStreamRef newStream = EventStreamFromDictionary((CFDictionaryRef)config);
		
		if (!newStream)
		{
			// Stream creation failed on the only config object, bail!
			LogError("Could not get a valid stream from config!\n");
			exit(1);
		}
		
		FSEventStreamScheduleWithRunLoop(newStream,
										 CFRunLoopGetCurrent(),
										 kCFRunLoopDefaultMode);
		FSEventStreamStart(newStream);
		CFArrayAppendValue(globals->streamArray, newStream);
		FSEventStreamRelease(newStream);
		CFRelease(config);
	}
	else
	{
		// Nothing to work with, we're done!
		LogError("No plist config file path or directory path specified!\n");
		exit(1);
	}
	
	// Main loop (only if we have something in the array):
	if (CFArrayGetCount(globals->streamArray) > 0)
	{
		Boolean done = false;
		do {
			// Start the run loop with a time out of 2 seconds:
			CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2, true);
			
			if (globals->rescanSignal)
			{
				//LogV("Got signal to rescan, rescanning %s\n", globals->path);
				globals->rescanSignal = false;
			}
			if (globals->quitSignal)
			{
				LogV("Got SIGINT or SIGTERM, cleaning and quiting.\n");
				done = true;
			}
		}
		while (!done);
	}
	
	CFIndex arrayCount = CFArrayGetCount(globals->streamArray);
	CFIndex i;
	for (i = 0; i < arrayCount; i++)
	{
		const FSEventStreamRef 
		aStream = (FSEventStreamRef)CFArrayGetValueAtIndex(globals->streamArray,
														   i);
		
		FSEventStreamStop(aStream);
		FSEventStreamInvalidate(aStream);
	}
	
	CFRelease(globals->streamArray);
	
    return 0;
}

// Load a property list from a path.
CFPropertyListRef CreatePropertyListFromFile(const char *path)
{
	CFURLRef myURL;
	CFPropertyListRef propertyList;
	CFStringRef errorString;
	CFStringRef myString = CFStringCreateWithCString(kCFAllocatorDefault,
													 path,
													 kCFStringEncodingUTF8);
	CFDataRef resourceData;
	Boolean status;
	SInt32 errorCode;
	
	/* Create CFURL from CFString */
	myURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
										  myString,
										  kCFURLPOSIXPathStyle,
										  FALSE);
	
	status = CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault,
													  myURL,
													  &resourceData,
													  NULL,
													  NULL,
													  &errorCode);
	
	propertyList = CFPropertyListCreateFromXMLData(kCFAllocatorDefault,
												   resourceData,
												   kCFPropertyListImmutable,
												   &errorString);
	
	CFRelease(resourceData);
	CFRelease(myString);
	
	if (globals->mode)
	{
		free(globals->mode);
	}
	
	return propertyList;
}


// Logs errors to stderr.
static void LogError(const char *format, ...)
{
	va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

// For verbose output, goes to stderr.
static void LogV(const char *format, ...)
{
	if (!globals->verbose) {
        return;
    }
    
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

// For mega-verbose output, goes to stderr.
static void LogMV(const char *format, ...)
{
	if (!globals->megaVerbose) {
        return;
    }
    
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

FSEventStreamRef EventStreamFromDictionary(CFDictionaryRef config)
{
	CFStringRef path;
	CFArrayRef pathArray;
	FSEventStreamRef stream;
	Boolean status;
	Boolean present;
	CFBooleanRef booleanValue;
	CFAbsoluteTime latency = globals->latency; // Latency (in seconds).
	FSEventStreamContext streamContext;
	char cPath[PATH_MAX], absoluteCPath[PATH_MAX];
	bzero(cPath, PATH_MAX);
	bzero(absoluteCPath, PATH_MAX);
	FSEventStreamCreateFlags myFlags = 0;
    
    // If we have a (relatively) low latencly, let's assume they want them as they come:
    if (latency < 2.5)
    {
        myFlags |= kFSEventStreamCreateFlagNoDefer; // If it's been more than (latency) seconds, we get the notificiation right away!
    }
    
	status = CFDictionaryGetValueIfPresent(config,
										   kCHMODDPathKey,
										   (const void **) (&path));
	// Make sure we have a string in the config
	if (! status)
	{
		LogError("Config with no path key!\n");
		return NULL;
	}
	
	// Convert the CFStringRef into a cString so we can use it for the following
	// calls.  (We shouldn't need it again after that!).
	status = CFStringGetCString(path,
								cPath,
								PATH_MAX,
								kCFStringEncodingUTF8);
	if (!status)
	{
		LogError("ERROR: Internal error converting path string!\n");
		return NULL;
	}
	
	// Make sure it's an absolute path:
	if (realpath(cPath, absoluteCPath) == NULL)
	{
		present = CFDictionaryGetValueIfPresent(config,
												kCHMODDCreateKey,
												(const void **)&booleanValue);
		
		if (present && CFBooleanGetValue(booleanValue))
		{
			if (mkdir(absoluteCPath, 0755) == -1) {
				LogError("ERROR: Could not find/create file: %s: %s\n",
						 cPath, strerror(errno));
				return NULL;
			}
			
		}
	}
	
    // If we're forcing the root to be there, let's open a file descriptor to it,
    // so we can detect where it's gone.  We'll also make sure that the root itself
    // is watched by the FSEvents API.
    present = CFDictionaryGetValueIfPresent(config,
                                            kCHMODDForceKey,
                                            (const void **)&booleanValue);
    if (present && CFBooleanGetValue(booleanValue))
    {
        myFlags |= kFSEventStreamCreateFlagWatchRoot;
        
        int descriptor = open(absoluteCPath, O_NONBLOCK);
        CFNumberRef descRef = CFNumberCreate(kCFAllocatorDefault,
                                             kCFNumberIntType,
                                             &descriptor);
        
        CFDictionarySetValue(globals->descriptorDict,
                             path,
                             descRef);
        
        CFRelease(descRef);
    }
	
	
	present = CFDictionaryGetValueIfPresent(config,
											kCHMODDPreScanKey,
											(const void **)&booleanValue);
	
	if (present && CFBooleanGetValue(booleanValue))
	{
		applyPermissionsToFolder(absoluteCPath, config, true);
	}
	
	pathArray = CFArrayCreate(kCFAllocatorDefault,
							  (const void **) &path,
							  1,
							  &kCFTypeArrayCallBacks);
	
	// Fill out the context so we can send the info along with it.
	streamContext.version			=	0;
	streamContext.info				=	(void *)config;
	streamContext.retain			=	&CFRetain;
	streamContext.release			=	&CFRelease;
	streamContext.copyDescription	=	NULL;
	
	// Magic.  This should work on Leopard and Snow Leopard.
	if (globals->ignoreSelf)
	{
		myFlags |= 0x00000008;
	}
	
	stream = FSEventStreamCreate(kCFAllocatorDefault,
								 &FSCallback,
								 &streamContext,
								 pathArray,
								 kFSEventStreamEventIdSinceNow,
								 latency,
								 myFlags);
	
	CFRelease(pathArray);
	
	return stream;
}

void FSCallback(ConstFSEventStreamRef streamRef,
				void *clientCallBackInfo,
				size_t numEvents,
				void *eventPaths,
				const FSEventStreamEventFlags eventFlags[],
				const FSEventStreamEventId eventIds[])
{
	CFDictionaryRef config = (CFDictionaryRef)clientCallBackInfo;
	int i;
	char **pathArray = eventPaths;
	Boolean status;
	
	for (i = 0; i < numEvents; i++)
	{
		if (eventFlags[i] == kFSEventStreamEventFlagNone)
		{
			// Base case:
			applyPermissionsToFolder(pathArray[i], config, false);
		}
		else if (eventFlags[i] & kFSEventStreamEventFlagRootChanged)
		{
			// Our root moved:
			char newPath[MAXPATHLEN];
			const char *string_to_use = NULL;
			const char *original_root_ptr = NULL;
			char path_string[MAXPATHLEN];
			
			CFStringRef	CFStringPath = CFDictionaryGetValue(config,
															kCHMODDPathKey);
			
			original_root_ptr = CFStringGetCStringPtr(CFStringPath,
													  kCFStringEncodingUTF8);
			
			if (original_root_ptr && *original_root_ptr)
			{
				string_to_use = original_root_ptr;
			}
			else
			{
				status = CFStringGetCString(CFStringPath,
											path_string,
											MAXPATHLEN-1,
											kCFStringEncodingUTF8);
				
				if (status)
				{
					string_to_use = path_string;
				}
			}
			
			CFStringRef path = CFDictionaryGetValue(config, kCHMODDPathKey);
			
			CFNumberRef descRef;
			status = CFDictionaryGetValueIfPresent(globals->descriptorDict,
												   path,
												   (void *)&descRef);
			
			if (status) {
				int descriptor;
				Boolean err = CFNumberGetValue(descRef,
											   kCFNumberIntType,
											   &descriptor);
				
				if (!err)
				{
					fcntl(descriptor, F_GETPATH, newPath);
					rename(string_to_use, newPath);
				}

			}

		}
		else if (eventFlags[i] & kFSEventStreamEventFlagMustScanSubDirs)
		{
			// Must rescan:
			applyPermissionsToFolder(pathArray[i], config, true);
		}
		else
		{
			// Unaccounted for flags, treat like base case:
			applyPermissionsToFolder(pathArray[i], config, false);
		}
	}
	
}

int applyPermissionsToFolder(const char *path,
							 CFDictionaryRef config,
							 Boolean force_recursion)
{
	FTS *ftsp;
	FTSENT *p;
	int filesChanged = 0, filesTouched = 0, filesVisited = 0, fts_options = 0;
	char *pathargv[] = {(char*)path, NULL};
	acl_t acl = NULL;
		
	if ((ftsp = fts_open(pathargv, fts_options, NULL)) == NULL)
	{
		LogError("fts_open: %s\n", strerror(errno));
		return(-1);
	}
	
	while ((p = fts_read(ftsp)) != NULL)
	{
		Boolean changed = false;
		Boolean isFolder = false;
		
		switch (p->fts_info) {
			case FTS_D:
				isFolder = true;
				break;
			case FTS_DNR:
				LogError("%s: %s\n", p->fts_path, strerror(p->fts_errno));
				break;
			case FTS_DP:
				isFolder = true;
				continue;
			case FTS_ERR:
			case FTS_NS:
				LogError("%s: %s\n", p->fts_path, strerror(p->fts_errno));
				continue;
			case FTS_SL:
			case FTS_SLNONE:
			default:
				break;
		}
		
		LogMV("MV: Visiting file: %s\n", p->fts_path);
		
		filesVisited++;

		CFTypeRef returnedValue = NULL;
		returnedValue = CFDictionaryGetValue(config,
											 kCHMODDPermKey);
		
		if (returnedValue != NULL)
		{
			if (CFGetTypeID(returnedValue) == CFStringGetTypeID())
			{
#define MODE_STRING_LENGTH 21
				const char *mode_string_ptr = NULL;
				char mode_string[MODE_STRING_LENGTH];
				const char *string_to_use = NULL;
				bzero(mode_string, MODE_STRING_LENGTH);
				
				mode_string_ptr = CFStringGetCStringPtr((CFStringRef) returnedValue,
														kCFStringEncodingUTF8);
				
				if (mode_string_ptr && *mode_string_ptr)
				{
					string_to_use = mode_string_ptr;
				}
				else
				{
					Boolean status = CFStringGetCString((CFStringRef) returnedValue,
														mode_string,
														MODE_STRING_LENGTH-1,
														kCFStringEncodingUTF8);
					
					if (status)
					{
						string_to_use = mode_string;
					}
				}

				if (string_to_use)
				{
					mode_t *modeChange;
					
					if ((modeChange = setmode(string_to_use)) == NULL)
					{
						LogError("Internal error setting file mode: %s\n",
								 string_to_use);
						LogError("This is probably an invalide mode!\n");
					}
					else {
						mode_t computedMode = getmode(modeChange,
													  p->fts_statp->st_mode);
						
						if (computedMode != p->fts_statp->st_mode)
						{
							// If the computed mode is not the same as the current
							// mode, we have work to do!
							changed = TRUE;
							LogMV("Applying new permissions %s to file %s\n",
								  string_to_use, p->fts_path);
							if (lchmod(p->fts_path, computedMode) != 0)
							{
								LogError("%s: %s\n", p->fts_path, strerror(errno));
							}
							else {
								filesChanged++;
							}
						}
						
						free(modeChange);
						
					}

				}
				else {
					LogError("Unspecified internal error in config structure!\n");
				}

#undef MODE_STRING_LENGTH
			}
			else {
				LogError("Unspecified internal error in config structure!\n");
			}
		}
		
		returnedValue = NULL;
		returnedValue = CFDictionaryGetValue(config,
											 kCHMODDACLKey);

		if (returnedValue != NULL)
		{
			if (CFGetTypeID(returnedValue) == CFBooleanGetTypeID())
			{
				if (CFBooleanGetValue((CFBooleanRef)returnedValue))
				{
					acl = acl_get_file(path, ACL_TYPE_EXTENDED);
					
					if (acl)
					{
						if (fileNeedsACLApplied(p->fts_path, acl))
						{
							filesChanged++;
							acl_set_link_np(p->fts_path,
											ACL_TYPE_EXTENDED,
											acl);
						}
					}
					else
					{
						LogError("Root folder (%s) doesn't have ACL set!\n",
								 path);
					}
				}
			}
			else {
				LogError("Internal error in config structure!\n");
			}
		}
		
		returnedValue = NULL;
		returnedValue = CFDictionaryGetValue(config, kCHMODDOwnerKey);
		
		if (returnedValue != NULL)
		{
			uid_t ownerID = -1;
			
			if (CFGetTypeID(returnedValue) == CFStringGetTypeID())
			{
				ownerID = getUIDfromCFString(returnedValue);
			}
			else if (CFGetTypeID(returnedValue) == CFNumberGetTypeID())
			{
				
				Boolean status = CFNumberGetValue(returnedValue,
												  kCFNumberSInt32Type,
												  &ownerID);
				if (!status)
				{
					LogError("Couldn't get number from plist for owner of "
							 "config %s\n", path);
					ownerID = -1;
				}
			}
			else
			{
				LogError("Internal error in config structure!\n");
			}
			
			if (p->fts_statp->st_uid != ownerID && ownerID != -1)
			{
				if (lchown(p->fts_path, ownerID, -1) != 0)
				{
					LogError("chown %s: %s\n", p->fts_path,strerror(errno));
				}
				else
				{
					filesChanged++;
				}
			}
		}

		returnedValue = NULL;
		returnedValue = CFDictionaryGetValue(config,
											 kCHMODDGroupKey);
		
		if (returnedValue != NULL)
		{
			gid_t groupID = -1;
			
			if (CFGetTypeID(returnedValue) == CFStringGetTypeID())
			{
				groupID = getGIDfromCFString(returnedValue);
			}
			else if (CFGetTypeID(returnedValue) == CFNumberGetTypeID())
			{
				Boolean status = CFNumberGetValue(returnedValue,
												  kCFNumberSInt32Type,
												  &groupID);
				if (!status)
				{
					LogError("Couldn't get number from plist for group of "
							 "config %s\n", path);
					groupID = -1;
				}
			}
			else {
				LogError("Internal error in config structure!\n");
			}
			
			if (p->fts_statp->st_gid != groupID && groupID != -1)
			{
				if (lchown(p->fts_path, -1, groupID) != 0)
				{
					LogError("chown %s: %s\n", p->fts_path,strerror(errno));
				}
				else
				{
					filesChanged++;
				}
			}
		}
				
		// Under certian criteria, go ahead and skip a directory's children,
		// because we know we already scanned it, and the permissions are 
		// correct.
		
		if (isFolder &&				// Only applicable for a folder/dir.
			p->fts_level > 0) {		// We aren't at the root.
			
			if (!force_recursion && // We weren't told specifically to rescan
				!changed &&			// We didn't detect a changed needed above.
				// We find that the ctime is greater than (or equal to) our
				// launch time.
				p->fts_statp->st_ctime >= globals->launch_time) {
				
				// We passed the test!  We know we can skip this now.
				LogMV("Skipping children of %s\n", p->fts_path);
				fts_set(ftsp, p, FTS_SKIP);
			}
			else if (p->fts_statp->st_ctime < globals->launch_time) {
				// We store the access and modify time, and set them to the
				// exact same thing.  This effectively changes ONLY the ctime,
				// which is much less visible to an end user.  Changing the
				// ctime will effectively mark it so we don't have to recurse
				// all the time (shwew!).  If necessary, this could probably be
				// stored in other file metadata, like extended attributes.
				// Let's consider this a "TODO," though.
				struct timeval times[2];
				times[0].tv_sec = p->fts_statp->st_atime;
				times[1].tv_sec = p->fts_statp->st_mtime;
				utimes(p->fts_path, times);
				filesTouched++;
			}
		}
	}
	
	if (acl)
	{
		acl_free(acl);
	}
	
	fts_close(ftsp);
	
	LogV("Applied Permission changes to %d file%s.\n", filesChanged,
		 (filesChanged != 1) ? "s" : "");
	LogV("Touched %d file%s.\n", filesTouched, (filesTouched != 1) ? "s" : "");
	LogV("Visited %d file%s.\n", filesVisited, (filesVisited != 1) ? "s" : "");
	
	return filesChanged;
}

#define OWNER_TYPE 0
#define GROUP_TYPE 1
UInt32 getUInt32fromSpecifiedString(CFStringRef mystring, int type)
{
	UInt32 retVal = -1;
	
	// Strategy.  This string could be anything from 0 to 501 to Frank.Fleschner
	// to who knows what else.  We'll use 0 as our base case, because this makes
	// it easy to detect if we got back an accurate number for our
	// CFStringGetIntValue call.  If we don't get an accurate number back, we
	// fall back to ... something.
	SInt32 result = CFStringCompare(mystring, CFSTR("0"), 0);
	
	if (result == kCFCompareEqualTo)
	{
		return 0;
	}
	
	result = CFStringGetIntValue(mystring);
	if (result != 0)
	{
		return (UInt32)result;
	}
	
	// Get the C string...this can take some work, because we try a short cut
	// the first time, and if it doesn't work, we do it the hard
	// (computationally expensive) way.
	
	
#define SHORT_NAME_LENGTH 50
	const char *short_name_quick = NULL;
	char short_string_nonquick[SHORT_NAME_LENGTH];
	const char *string_to_use = NULL;
	bzero(short_string_nonquick, SHORT_NAME_LENGTH);
	
	// Quick way...
	short_name_quick = CFStringGetCStringPtr(mystring, kCFStringEncodingUTF8);
	
	// If it works, point our final to it.
	if (short_name_quick && *short_name_quick)
	{
		string_to_use = short_name_quick;
	}
	// If not, try it again, but the long way, and point our bookmark to it
	// (also only if it works).
	else
	{
		Boolean status = CFStringGetCString(mystring,
											short_string_nonquick,
											SHORT_NAME_LENGTH-1,
											kCFStringEncodingUTF8);
		
		if (status)
		{
			string_to_use = short_string_nonquick;
		}
	}
#undef SHORT_NAME_LENGTH
	
	// If we have a string_to_use
	if (string_to_use)
	{
		if (type == GROUP_TYPE)
		{
			struct group *group_info = NULL;
			
			group_info = getgrnam(string_to_use);
			
			if (group_info)
			{
				retVal = group_info->gr_gid;
			}
		}
		else if (type == OWNER_TYPE)
		{
			struct passwd *user_info = NULL;
			
			user_info = getpwnam(string_to_use);
			
			if (user_info)
			{
				retVal = user_info->pw_uid;
			}
		}
		else {
			LogError("Internal Error: Unsupported type specified to "
					 "getUInt32fromSpecifiedString\n");
		}

			
	}
	
	return retVal;
}
	
// Returns the UID specified in the CFString (whether the string is a username
// or a UID itself.
uid_t getUIDfromCFString(CFStringRef myString)
{
	uid_t retVal = -1;
	assert(myString);
	
	retVal = getUInt32fromSpecifiedString(myString, OWNER_TYPE);
	
	return retVal;
}

// Returns the GID specified in the CFString (whether the string is a username
// or a GID itself.
gid_t getGIDfromCFString(CFStringRef myString)
{
	gid_t retVal = -1;
	assert(myString);
	
	retVal = getUInt32fromSpecifiedString(myString, GROUP_TYPE);
	
	return retVal;
}

Boolean fileNeedsACLApplied(const char *path, acl_t acl)
{
	Boolean retVal = FALSE;
	acl_t test_acl;
	
	test_acl = acl_get_link_np(path, ACL_TYPE_EXTENDED);
	
	if (test_acl == (acl_t)NULL) {
		LogV("%s has no ACL, assuming we need to propigate one to it!\n", path);
		retVal = true;
	}
	
	acl_free((void *) test_acl);
	
	return retVal;
}

// Prints the usage to stderr
void usage(void)
{
	fprintf(stderr, "\nUsage: %s [-H -L -f -F -v -V -h -a] -d "
			"</path/to/directory>  -p <chmod-style permissions to use>\n"
			"For example:  %s -F -d /Users/Shared \"a+w\"\n", 
			getprogname(), getprogname());
}
// Signal related functions
void setup_signals(void)
{
	signal(SIGUSR1, handle);
	signal(SIGUSR2, handle);
	signal(SIGINT, handle);	
	signal(SIGHUP, handle);
	signal(SIGTERM, handle);
}
void handle(int signal)
{
	switch (signal) {
		case SIGUSR1:
		case SIGUSR2:
			globals->rescanSignal = true;
			break;
		case SIGINT:
		case SIGTERM:
			globals->quitSignal = true;
			break;
		default:
			break;
	}
}

// Stream Array callbacks:
void MyCFArrayReleaseCallback(CFAllocatorRef allocator,
							  const void *value)
{
	FSEventStreamRelease((FSEventStreamRef)value);
}
Boolean MyCFArrayEqualCallBack(const void *value1,
							   const void *value2)
{
	return value1 == value2;
}
const void *MyCFArrayRetainCallBack(CFAllocatorRef allocator,
									const void *value)
{
	FSEventStreamRetain((FSEventStreamRef)value);
	return value;
}
