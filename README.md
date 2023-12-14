# kpmacaudit

This script is used by KirkpatrickPrice auditors to collect information from MacOS devices.  Unlike many other tools out there, the approach used in this script is "keep it lite":
* Keep it simple -- there is only one file that is needed -- `kpmacaudit.sh`.  Everything runs from there.
* Keep it simple -- the script tries not to use any crazy Bash-fu.  Comments are embedded througout to facilitate source code review for interested personnel prior to running it on your device
* Use only commands that are already built into the operating system (no Python, Perl, jq, etc required)
* Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection.  This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.
* Fail quietly -- If a command isn't found or the piece of software isn't installed, note that in the output and keep going

All Git Commits are signed to increase reliability that code hasn't been changed by anyone but KirkpatrickPrice.  You can verify the signature of any commit by clicking on the commit message or hash ID and noting that "Verified" is indicated.

## Critical dependencies ##
* Shell: `bash` -- the default version (v3) that comes with MacOS
* Package managers: MacOS native `.app` and `brew`
* Service management: `launchctl`
* Misc. commands:   `find` `which` `echo` `awk` `uname` `sysctl` `grep` `head` `tail` `netstat` `mount`
* MacOS-specific commands: `dscl` `security` `defaults` `disktuil` `system_profiler` `softwareupdate` `csrutil` `systemsetup`

The script has been tested against MacOS 13.3 Ventura, but it will also likely run well on other MacOS versions so long as it supports the dependencies above.

## Installation
Installation is as simple as copying or cloning the Bash script to your system.

`git clone https://github.com/kirkpatrickprice/macos-auditor`

or using `curl`:

```
curl https://raw.githubusercontent.com/kirkpatrickprice/macos-auditor/main/kpmacaudit.sh -o kpmacaudit.sh
chmod u+x kpmacaudit.sh
```

or right-click on [this link](https://raw.githubusercontent.com/kirkpatrickprice/macos-auditor/main/kpmacaudit.sh) and save it to your computer.

## Usage and Results
If you're unfamiliar with the Linux/MacOS command line, the following steps will ensure that you can successfully run the program:
1. Right-click on [this link](https://raw.githubusercontent.com/kirkpatrickprice/macos-auditor/main/kpmacaudit.sh) and save it to your Home folder
    NOTE: The Home folder will be named the same as your username and should be used to avoid MacOS permission problems with Terminal being able to access files in other user folders.
2. Use the LaunchPad to open the `Terminal` application
3. Type: 
    ```
    chmod u+x kpmacaudit.sh
    ```
    NOTE: 
    * If you see an error message about `kpmacaudit: No such file or directory`, confirm that you're in your Home folder by typing: 
        ```
        cd ~
        ``` 
        and then repeat the `chmod u+x kpmacaudit.sh` command above.
    * If you still see the error message, confirm that you saved the file to your Home folder by typing:
        ```
        ls
        ```
        If you don't see the `kpmacaudit.sh` file, repeat step 1 and make sure you save it in your Home folder.
4. Type: 
    ```
    sudo ./kpmacaudit.sh
    ```
5. When prompted by `sudo` for a password, use the same password you use to login.
    NOTES: 
    * If you get an error message about `kpmacaudit.sh: command not found`, be sure that you included the `./` before the `kpmacaudit.sh`.
6. Once it's has finished, you can safely remove the program by typing: 
    ```
    rm kpmacaudit.sh
    ```
7. When the program has finished, type:
    ```
    exit
    ```
    and close the `Terminal` window

The end result is a text file named as `<computername>.txt` in each user's Home folder.  Collect all of the files from the identified sample and save them in a ZIP.  Upload the ZIP file to the Online Audit Manager portal.

## Rarely Needed
There are some options to facilitate troublshooting, but they should rarely be needed and only used under KP advisement.
```
USAGE:
        kpmacaudit.sh [ -cdh ]
        Options:
            -c      Print DumpCmd errors messages to STDERR instead of redirecting them to /dev/null
            -d      Print DEBUG messages to STDOUT and to REPORT_NAME
            -h      this help

        NOTE: This script must be run as ROOT
```
