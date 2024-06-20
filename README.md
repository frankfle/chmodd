# chmodd

`chmodd` is a simple background daemon that watches for fiel system events in a given part or parts of a filesystem, and can enforce ownership/permissions (posix or ACLs) on all the contents of that folder.

It was written in C and uses CoreFoundation and FSEvents APIs.  It can be used by directly passing configuration options via the command line, or can be configured via plist file to watch several folders and enforce several ownership/permission schemes.
