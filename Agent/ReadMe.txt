Setup VM:
    
# Enable test signing
    bcdedit /set testsigning on

# Enable kernel debugging (optional but recommended)
    bcdedit /debug on

# Disable driver signature enforcement
    bcdedit /set nointegritychecks on

# Reboot for changes to take effect
    shutdown /r /t 0


Install the kernel driver:
    sc create NetMonPOC type= kernel binPath= "C:\Path\To\netmon.sys"
    sc start NetMonPOC

Run the agent as Administrator:
    NetMonAgent.exe


