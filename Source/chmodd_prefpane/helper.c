#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/stat.h>
#include <Security/Security.h>

#define RIGHT "com.backlight.chmodd.admin"

#define CONFIG_FILE_PATH "/etc/chmodd.conf"
#define LAUNCHD_JOB_PATH "/Library/LaunchDaemons/com.backlight.chmodd.plist"

#define mode		"4555"
#define owner		0
#define group		-1

// Global variables.
struct globals_t {
	// Control verbosity/output
	Boolean					verbose;
	Boolean					megaVerbose;
	
	char	myPath[PATH_MAX];	// path to executable.
	
	Boolean	checkPerms;			// Use this to check to see if a repair is
								// needed, and repair if necessary
	
	Boolean					moveConfigFile;
	char					configFilePath[PATH_MAX];
	
	Boolean					unloadJob;
	Boolean					loadJob;
	
	Boolean					installJob;
	char					jobPath[PATH_MAX];
	
	Boolean					checkStatus;

} _globals;

struct globals_t *globals = &_globals;


// Local function prototypes
void self_repair(void);
// Logs errors to stderr.
static void LogError(const char *format, ...)
__attribute__((format(printf, 1, 2)));

// For verbose (-v) output, goes to stderr.
static void LogV(const char *format, ...)
__attribute__((format(printf, 1, 2)));

// For mega-verbose (-V) output, goes to stderr.
static void LogMV(const char *format, ...)
__attribute__((format(printf, 1, 2)));

int main (int argc, char * argv[])
{
	OSStatus status;
	AuthorizationRef auth;
	AuthorizationExternalForm extAuth;
	int return_status;
	
	/* DEFAULTS */
	globals->verbose			= true;
	globals->megaVerbose		= true;
	globals->checkPerms			= false;
	globals->moveConfigFile		= false;
	globals->unloadJob			= false;
	globals->loadJob			= false;
	globals->installJob			= false;
	globals->checkStatus		= false;
	
	bzero(globals->jobPath, PATH_MAX);
	bzero(globals->myPath, PATH_MAX);
	bzero(globals->configFilePath, PATH_MAX);
	
	// Store our path, for future use.
	if (realpath(argv[0], globals->myPath) == NULL)
	{
		LogError("Couldn't find path from call: %s.\n"
				 "Please call using an absolute path.\n", argv[0]);
		exit(-1);
	}
	LogV("Path to me: %s\n", globals->myPath);
	
	int c; opterr = 0;
	while ((c = getopt(argc, argv, "crvVulRm:L:C")) != -1)
	{
		switch (c) {
			case 'c':
				globals->checkPerms = true;
				break;
			case 'r':
				self_repair();
				break;
			case 'V':
				globals->megaVerbose = true;
				/* FALLTHROUGH: -V implies -v */
			case 'v':
				globals->verbose = true;
				break;
			case 'm':
				globals->moveConfigFile = true;
				if (realpath(optarg, globals->configFilePath) == NULL)
				{
					LogError("Can't find file \"%s\"\n", optarg);
				
					exit(-1);
				}

				globals->loadJob = true;
				globals->unloadJob = true;

				break;
			case 'L':
				globals->installJob = true;
				if (realpath(optarg, globals->jobPath) == NULL)
				{
					LogError("Can't find file \"%s\"\n", optarg);
					
					exit(-1);
				}
				break;				
			case 'R':
				globals->loadJob = true;
				globals->unloadJob = true;
				break;
			case 'C':
				globals->checkStatus = true;
				break;
			case 'u':
				globals->unloadJob = true;
				break;
			case 'l':
				globals->loadJob = true;
				break;
			case '?':
			default:
				LogError("Incorrect usage: %c\n", c);
				exit(-1);
				break;
		}
	}
	
	// If we're not effectively root, we need to repair ourself.
	if (geteuid() != 0)
	{
		AuthorizationRef repairAuth;
		LogV("%s must be run as root!  Attempting to repair\n", getprogname());
		
		AuthorizationCreate(0,
							kAuthorizationEmptyEnvironment,
							0,
							&repairAuth);
		
		char *repair_arguments[] = {"-r", NULL};
		
		AuthorizationExecuteWithPrivileges(repairAuth,
										   globals->myPath,
										   kAuthorizationFlagDefaults,
										   repair_arguments,
										   NULL);
		
		if (globals->checkPerms)
		{
			exit(0);
		}
		else
		{
			exit(-1);
		}
	}
	
	// If we're just checking permissions, then we've succeeded, and need to
	// exit cleanly
	if (globals->checkPerms)
	{
		exit(0);
	}
	
	// Read Authorization Data
	if (fread(&extAuth, sizeof(extAuth), 1, stdin) != 1)
	{
		LogError("Could not read Authorization\n");
		exit(-1);
	}
	
	// Restore external to regular
	if (AuthorizationCreateFromExternalForm(&extAuth, &auth))
	{
		LogError("Unable to parse authorization data\n");
		exit(-1);
	}
	
	// Create the rights structures
	AuthorizationItem right = {RIGHT, 0, NULL, 0};
	AuthorizationRights rights = {1, &right};
	AuthorizationFlags flags = kAuthorizationFlagDefaults |
	kAuthorizationFlagExtendRights;
	
	LogV("Tool authorizing right %s for command.\n", RIGHT);
	
	status = AuthorizationCopyRights(auth,
									 &rights, 
									 kAuthorizationEmptyEnvironment, 
									 flags, 
									 NULL);
	
	if (status != 0) {
		LogError("Authorization failed: %ld\n", (long int) status);
		exit(-1);
	}
	
	if (setuid(0) == -1)
	{
		LogError("Couldn't setuid to 0 in normal usage!\n");
		exit(-1);
	}
	
	if (globals->checkStatus)
	{
		return_status = system("/bin/launchctl list com.backlight.chmodd");
		
		LogV("return from launchctl = %i", return_status);
		
		int myReturn = (return_status == 0) ? 5 : 6;
		
		exit(myReturn);
	}
	
	// Install plist file.
	if (globals->installJob)
	{
		LogV("Installing job: mv %s %s\n", globals->jobPath, LAUNCHD_JOB_PATH);
		rename(globals->jobPath, LAUNCHD_JOB_PATH);
		system("/usr/sbin/chown 0:0 "LAUNCHD_JOB_PATH);
		system("/bin/chmod 644 "LAUNCHD_JOB_PATH);
	}
	
	// Real action, done in a specific order.
	
	if (globals->moveConfigFile)
	{
		rename(globals->configFilePath, CONFIG_FILE_PATH);
	}
	
	if (globals->unloadJob)
	{
		system("/bin/launchctl unload -w "LAUNCHD_JOB_PATH);
		system("/usr/bin/killall chmodd");
	}
	
	if (globals->loadJob)
	{
		system("/usr/sbin/chown 0:0 "LAUNCHD_JOB_PATH);
		system("/bin/chmod 644 "LAUNCHD_JOB_PATH);
		system("/bin/launchctl load -w "LAUNCHD_JOB_PATH);
	}
	
    return 0;
}

void self_repair(void)
{
	struct stat info;
	mode_t *proposed, new_mode;
	
	// Setuid -- this is a good test to see if we have priveleges.  And it may
	// be necessary in some cases.
	if (setuid(0) == -1)
	{
		LogError("Couldn't setuid during repair");
		exit(-1);
	}
	
	// Stat so we can chmod in a bit...
	if (lstat(globals->myPath, &info) == -1)
	{
		LogError("Couldn't stat");
		exit(-1);
	}
	
	// Make sure our mode is OK before we chown.
	if ((proposed = setmode(mode)) == NULL)
	{
		LogError("Couldn't setmode");
		exit(-1);
	}	
	
	// Chown to root.
	if (lchown(globals->myPath, owner, group) == -1)
	{
		LogError("Couldn't set owner to root");
		exit(-1);
	}
	
	new_mode = getmode(proposed, info.st_mode);
	free(proposed);
	
	if (new_mode != info.st_mode)
	{
		if ((chmod(globals->myPath, new_mode)) == -1)
		{
			LogError("Couldn't chmod");
			exit(-1);
		}
	}
	
	LogV("Success!\n");
	
	// Exit out of program.
	exit(0);
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

