# BehavEye
Advanced malware analysis tool that monitors malware behavior and give a comprehensive log about everything that happened.
# Features
* Monitoring Connections

* Monitors File Actions (creating or opening a file)
  
* Monitors Process Actions (Impersonating Tokens, Creating Spoofed Parent, opening a process handle, creating a new process, setting process information, getting system information, process memory writing/reading, etc)

* Monitors Registry Actions

* Monitors the User API (for example if the process tried to find a window with a specific name, getting clipboard data, getting the last time the user was active, hooking mouse or keyboard which could be used for keylogging, etc)

* Monitor Driver Actions (monitoring driver/service creation, monitoring if the process tried to commuincate with a service/kernel driver, etc)

* Misc Monitoring (monitoring if the process tried to crash the system, shutdown the system, etc)
