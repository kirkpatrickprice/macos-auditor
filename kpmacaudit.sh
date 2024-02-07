#!/bin/bash

# Copyright 2023 KirkpatrickPrice, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# KirkpatrickPrice *nix Audit Script
# Author: Randy Bartels (original version by Michael Fowl)
# Usage example: "sudo ./kpnixaudit.sh" to audit common configs and setting on MacOS devices.

# A report titled "hostname".txt will be generated in the working directory.
# NOTE: The script must be run as ROOT


# CHANGELOG
# Version 0.1.0 (June 27, 2023):
#   - Initial version, based significantly on https://github.com/kirkpatrickprice/linux-audit-scripts/kpnixaudit.sh and CIS MacOS 13 Ventura Benchmark v1.0.0 (https://cisecurity.org)

KPMACVERSION="0.1.0"

function usage () {
    echo "
    $(basename $0) Version ${KPMACVERSION}

    Creates a text file in ~/<hostname>.txt with system configuraiton information needed to audit Linux systems

    USAGE:
        $(basename $0) [ -cdhw ]
        Options:
            -c      Print DumpCmd errors messages to STDERR instead of redirecting them to /dev/null
            -d      Print DEBUG messages to STDOUT and to REPORT_NAME
            -h      this help

        NOTE: This script must be run as ROOT
    "
}

function debug () {
    # Function to print debug messages if required
    if [ $DEBUG -eq 1 ]; then
        echo -e "#[DEBUG]:: $1" | tee -a $REPORT_NAME
    fi
}

function header () {
    #Print a header message for each testing group
    #Parameters:
    #   $1 - Section Heading Name
    #   $2 - CIS Reference number

    SECTION="$1"
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    echo -e "Checking: $1"
    echo -e "#[BEGIN]: $1" 2> /dev/null >> $REPORT_NAME
    #echo -e "#[CISReference]: $2" >> $REPORT_NAME

}

function footer () {
    #Print a closing footer message for each testing group
    #Parameters:
    #   None (inherit $SECTION from "heading" function)

    echo -e "#[END]: $SECTION" >> $REPORT_NAME
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    SECTION=""
}

function comment () {
    #Print comment lines preceded by "###" to make them easy to find (and grep out) when analyzing the results
    #Parameters:
    #   $1 - Comment to insert into report

    echo -e "###$1" 2>/dev/null >> $REPORT_NAME
}

function dumpcmd () {
    #Print each line of the command's output with the section name as the prefix to make it easier to grep the results
    #Parameters:
    #    $1 - Command to process and dump results into $REPORT_NAME

    comment "Running: $1"
    debug "Running: $1"

    local COMMAND_ROOT="$(echo -e "$1" | awk '{ print $1 }')"
    local COMMAND_PATH="$(which $COMMAND_ROOT 2> /dev/null)"

    debug "DumpCmd: $COMMAND_ROOT==>$COMMAND_PATH"

    if [ -n "$COMMAND_PATH" ]; then
        if [ $DEBUGCMD = 0 ]; then
            local RESULTS=$(${1} 2> /dev/null)
        else
            local RESULTS=$(${1})
        fi

        echo "$RESULTS" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME

    else
        comment "$COMMAND_ROOT command not found."
    fi
}

function dumpcmdForEachUser () {
    # A function to iterate through system users to gather some piece of user-specific data (probably through the 'defaults' command)
    # It will automatically append the user's name to the section heading before calling dumpcmd
    #   $1 - The command to run

    local USERNAME
    local ORIG_SECTION=$SECTION
    for USERNAME in $(dscl . list /Users); do
        if ! [[ "$USERNAME" =~ $IGNORE_USERS ]]; then
            SECTION="$ORIG_SECTION-$USERNAME"
            dumpcmd "sudo -u $USERNAME $1"
        fi
    done;
    SECTION=$ORIG_SECTION
}

function dumpcmdgrep {
    # A function to process a command's results through grep to filter specific results
        #$1 comamnd to run
        #$2 grep options (e.g. -c, -o, etc)
        #$3 filter criteria

    comment "Running: $1 | grep $2 \"$3\""
    debug "Running: $1 | grep $2 \"$3\""

    local COMMAND_ROOT=$(echo -e "$1" | awk '{ print $1 }')
    local COMMAND_PATH=$(which $COMMAND_ROOT 2> /dev/null)

    debug "DumpCmd: $COMMAND_ROOT==>$COMMAND_PATH"

    if [ -n "$COMMAND_PATH" ]; then
        if [ $DEBUGCMD = 0 ]; then
            local RESULTS=$(${1} 2> /dev/null | grep $2 "$3")
        else
            local RESULTS=$(${1}) | grep $2 "$3"
        fi

        echo "$RESULTS" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME

    else
        comment "$COMMAND_ROOT command not found."
    fi
}


function dumpfile () {
    #Print the output of the specified file(s) preceded by the section and file name to make the results easier to grep
    #Parameters:
    #   $1 - Path to start from -- do NOT include the trailing "/"
    #   $2 - Filespec to match against (e.g. *.conf) / requires regex syntax as this is used by 'find -iname <filespec>'
    #   $3 - Optional MAXDEPTH / assume 1 if none provided
    #       - "0" will only search the starting point passed in $1 / it won't find any files matched in $2 / DO NOT USE
    #       - "1" will search the current <path> in $1 but not recurse any directories
    #       - "2" will search the current path in $1 plus one more level of directies under that...
    #       - "3" and so on...

    debug "Dumpfile: $1 $2 $3"

    if [ -n "$3" ]; then
        #If provided, set MAXDEPTH to $3
        local MAXDEPTH="$3"
    else
        #If not provided, assume MAXDEPTH is 1 (see function comments above for interpretation)
        local MAXDEPTH="1"
    fi

    debug "Dumpfile: $1 $2 $MAXDEPTH"

    if [ -d "$1" ]; then
        for n in $(find -L $1 -maxdepth $MAXDEPTH -type f -iname "$2"); do
            debug "Find: $n"
            comment "File contents: $n"

            # Use awk to format each line as SECTION::FILENAME::LINE
            awk \
                -v vSECTION="$SECTION" \
                -v vFILE=$n \
                '{
                    printf "%s::%s::%s\n",vSECTION,vFILE,$0;
                }' $n >> $REPORT_NAME
        done
    else
        debug "$1 directory does not exist"
        comment "$1 directory does not exist."
    fi
}

function dumpgrep () {
    #Using grep/zgrep, dump lines matching $1 in files matching fileglob in $2
    #Parameters:
    #   $1 - Regex to use for matching
    #   $2 - Path to start from -- do NOT include the trailing "/"
    #   $3 - Filespec to match against (e.g. *.conf) / requires regex syntax as this is used by 'find -iname <filespec>'
    #   $4 - Optional MAXDEPTH / assume 1 if none provided
    #       - "0" will only search the starting point passed in $1 / it won't find any files matched in $2 / DO NOT USE
    #       - "1" will search the current <path> in $1 but not recurse any directories
    #       - "2" will search the current path in $1 plus one more level of directies under that...
    #       - "3" and so on...

    local FILE
    local PATTERN=$1
    local SEARCHPATH=$2
    local FILESPEC=$3

    if [ -n "$4" ]; then
        #If provided, set MAXDEPTH to $3
        local MAXDEPTH="$4"
    else
        #If not provided, assume MAXDEPTH is 1 (see function comments above for interpretation)
        local MAXDEPTH="1"
    fi

    debug "DumpGrep: Pattern:\"$PATTERN\" PATH:$SEARCHPATH FILESPEC:\"$FILESPEC\" DEPTH:$MAXDEPTH"

    for FILE in $(find -L $SEARCHPATH -maxdepth $MAXDEPTH -type f -iname "$FILESPEC" | sort); do
        case $FILE in
            *.gz )
                local CMD="zgrep"
                ;;
            * )
                local CMD="grep"
                ;;
        esac

        comment "Running: $CMD \"$PATTERN\" $FILE"
        debug "Running: $CMD \"$PATTERN\" $FILE"

        local COMMAND_ROOT="$(echo -e "$CMD" | awk '{ print $1 }')"
        local COMMAND_PATH="$(which $COMMAND_ROOT 2> /dev/null)"

        debug "DumpCmd: $COMMAND_ROOT==>$COMMAND_PATH"

        if [ -n "$COMMAND_PATH" ]; then
            if [ $DEBUGCMD = 0 ]; then
                local RESULTS="$($CMD "$PATTERN" "$FILE" 2> /dev/null)"
            else
                local RESULTS="$($CMD "$PATTERN" "$FILE")"
            fi

            echo "$RESULTS" | awk -v vSECTION=$SECTION -v vFILE=$FILE '{ printf "%s::%s::%s\n",vSECTION,vFILE,$0; }' >> $REPORT_NAME

        else
            comment "$COMMAND_ROOT command not found."
        fi
    done
}

function getDefaults () {
    # Function to retrieve results from the MacOS 'defaults' command
    #   $1 - Domain to read from (e.g. a PLIST file located in /Library/Preferences/commerce.plist)
    #   $2 - Value to retrieve (e.g. AutoUpdate)
    local RESULTS=$(defaults read $1 $2 2>/dev/null)

    if [[ ${#RESULTS} -lt 1 ]]; then
        RESULTS="Unset"
    fi

    echo "$2=$RESULTS" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME
}

function getInstalledApps () {
    # Function to scan the file system for *.app folders.

    local FOLDERS=( /Applications /System /Users )
    comment "Running: find ${FOLDERS[*]} -iname '*.app' -type d 2>/dev/null | grep -v /Contents/"
    echo -e "[*] Enumerating installed applications, which could take a while.\n[*] Please wait..."
    RESULTS=$(find ${FOLDERS[*]} -iname '*.app' -type d 2>/dev/null | grep -v /Contents/)
    echo "$RESULTS" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME
}

function getOsaUserDefault () {
    # Function to return a value from osascript:
    #   $1 - suiteName
    #   $2 - objectKey

    local RESULTS=$(osascript -l JavaScript -e "\$.NSUserDefaults.alloc.initWithSuiteName('$1').objectForKey('$2').js")

    if [[ ${#RESULTS} -lt 1 ]]; then
        RESULTS="Unset"
    fi

    echo "$2=$RESULTS" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME
}

function getPWPolicy () {
    # Function to return the important items for the local password policy

    local POLICY=()
    local LOThreshold=$(pwpolicy -getaccountpolicies 2> /dev/null | tail +2 | xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' -)
    POLICY+=("maxFailedLogins=${LOThreshold}")
    local LODuration=$(pwpolicy -getaccountpolicies 2> /dev/null | tail +2 | xmllint --xpath '//dict/key[text()="policyAttributeMinutesUntilFailedAuthenticationReset"]/following-sibling::integer[1]/text()' -)
    POLICY+=("LockoutDuration=${LODuration}")
    POLICY+=("minLength=$(pwpolicy -getaccountpolicies | grep -e "policyAttributePassword matches" | cut -b 46-53 | cut -d',' -f1 | cut -d'{' -f2 | grep -e '\d\+')")
    POLICY+=($(pwpolicy -getglobalpolicy | grep -o "requiresAlpha=1"))
    POLICY+=($(pwpolicy -getglobalpolicy | grep -o "requiresMixedCase=1"))
    POLICY+=($(pwpolicy -getglobalpolicy | grep -o "requiresNumeric=1"))
    POLICY+=($(pwpolicy -getglobalpolicy | grep -o "requiresSymbol=1"))
    POLICY+=($(pwpolicy -getglobalpolicy | grep -o "maxMinutesUntilChangePassword=\d\+"))

    for p in ${POLICY[*]}; do
        printf "$p\n" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME
    done
}

function getSubString () {
    #Function to search the global STRING variable to find the substring when provided with the following paramaters:
    #    $1 - Prefix string (include any glob characters such as *<text>)
    #    $2 - Suffix string (include any glob characters such as <text>*)
    #All text between and exclusive of PREFIX and SUFFIX will be put back into the SUBSTRING global variable

    local PREFIX=$1
    local SUFFIX=$2
    local TEMP=""

    debug "STRING: '$STRING'"
    debug "PREFIX: '$PREFIX'"
    debug "SUFFIX: '$SUFFIX'"

    # Use BASH parameter substitution to eliminate the text before the PREFIX and after the SUFFIX (inclusive).  Return what's left as SUBSTRING
    local TEMP=${STRING##$PREFIX}
    SUBSTRING=${TEMP%%$SUFFIX}
    debug "SUBSTRING=$SUBSTRING"
}

function getSystemPrefsLocked() {
    # Function to read the system preferences setting for whether or not the system-wide preferences are protected with a password

    RESULTS=$(security authorizationdb read system.preferences 2>/dev/null | grep -A1 shared | grep -c false)

    echo $RESULTS | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME
}

function redactfile () {
    #Print the output of the specified file preceded by the section and file name to make the results easier to grep
    #Redact lines that include the text provided in $2
    #Parameters:
    #   $1 - Full path of the file
    #   $2 - Regex pattern for the content that should be redacted
    #   $3 - Text to use for redaction
    # For example, if you want to replace "secret: <base64_string>" with "secret: <REDACTED>"
    #   $1 - File to process
    #   $2 - "secret:.*"
    #   $3 - "secret: <REDACTED>"

    debug "Redactfile: $1 $2 $3"

    local FILE=$1
    local PATTERN="$2"
    local REPLACE="$3"

    if [ -f "$FILE" ]; then
    # A short AWK script that finds all PATTERNs and replaces them with REPLACE
        awk \
            -v vPATTERN="$PATTERN" \
            -v vREPLACE="$REPLACE" \
            -v vSECTION="$SECTION" \
            -v vFILE=$FILE \
            '{
                gsub(vPATTERN,vREPLACE);
                printf "%s::%s::%s\n",vSECTION,vFILE,$0;
        }' $FILE >> $REPORT_NAME
    else
        debug "$1 file does not exist"
        comment "$1 file does not exist."
    fi
}

function System {
    header "System_Periodic"
        comment "Periodic is the task scheduler, so you can use this to get a list of (and even the contents of) the scheduled tasks running on a system."
        dumpfile "/etc/defaults" "periodic.conf"
        dumpfile "/etc/periodic" "*" "2"
    footer

    header "System_FSEncryption"
        comment "File system encryption on MacOS is provided by FileVault.  The exact implementation depends on the file system type -- APFS or CoreStorage."
        comment "APFS uses the 'fdesetup' and 'diskutil ap' command sets, while CoreStorage status can be seen with the 'diskutil cs list' command."
        comment "See https://support.apple.com/guide/deployment/manage-filevault-with-mdm-dep0a2cb7686/web for additional information."
        local BASE_SECTION="System_FSEncryption-APFS"
        SECTION=$BASE_SECTION
        dumpcmd "diskutil ap list"
        local COMMANDS=( status list haspersonalrecoverykey hasinstitutionalrecoverykey )
        for COMMAND in ${COMMANDS[*]}; do
            SECTION="${BASE_SECTION}-${COMMAND}"
            dumpcmd "fdesetup $COMMAND -extended"
        done
        SECTION="System_FSEncryption-CoreStorage"
        dumpcmd "diskutil cs list"
        SECTION="System_FSEncryption"
    footer

    header "System_FSMounts"
        comment "This will collect a list of all file system mounts.  Sometimes, for instance, the backups are written to a remote NFS server.  In this case, the mount point will be listed here."
        SECTION='System_FSMounts-mounts'
            dumpcmd "mount"
        SECTION='System_FSMounts-fstab'
            dumpfile "/etc" "fstab"
        SECTION='System_FSMounts'
    footer

    header "System_KernelSysctlRunningConfig"
        comment "This section collects the RUNNING status for various kernel parameters.  Most of these details are probably not useful in most audits, but they're here if you need them."
        dumpcmd "sysctl -a"
    footer

    header "System_InstalledApps"
        comment "This section collects a list of installed applications.  It includes apps installed as .app folders in the typical MacOS way, as well as Brew-installed apps"
        comment "Brew is popular software management tool to install software that's not readily available through Apple-managed channels"
        SECTION="System_InstalledApps-MacOS"
        #Commented out on 6/22/2023 in favor of the system_profiler method
        #getInstalledApps
        dumpcmd "system_profiler SPApplicationsDataType"
        SECTION="System_InstalledApps-Brew"
        dumpcmdForEachUser "brew list --versions"
        SECTION="System_InstalledApps"
    footer

    header "System_AutoUpdateConfig"
        comment "This content identifies the auto-update configuration settings for MacOS.  The section heading names directly reference items in the CIS MacOS Benchmark"
        BASE_SECTION=$SECTION
        SETTINGS=( AutomaticCheckEnabled AutomaticDownload AutomaticallyInstallMacOSUpdates ConfigDataInstall CriticalUpdateInstall )
        for SETTING in ${SETTINGS[@]}; do
            #SECTION="$BASE_SECTION-$SETTING"
            getDefaults "/Library/Preferences/com.apple.SoftwareUpdate" "$SETTING"
        done
        SECTION="$BASE_SECTION-AppStoreUpdate"
            getDefaults "/Library/Preferences/com.apple.commerce" "AutoUpdate"
        SECTION="$BASE_SECTION-EnforcedSoftwareUpdateDelay"
            getOsaUserDefault "com.apple.applicationaccess" "enforcedSoftwareUpdateDelay"
        SECTION=$BASE_SECTION
    footer

    header "System_PendingUpdates"
        comment "This section identifies any missing critical security and other updates.  We use the operating system's own tools"
        comment "to compare available updates against currently-installed software versions.  Use this section to determine the criticality of any missing updates."
        echo -e "[*] Enumerating any missing package manager updates, which could take a while.\n[*] Please wait..."
        SECTION="System_PendingUpdates-Apple"
        dumpcmd "softwareupdate -l"
        SECTION="System_PendingUpdates-Brew"
        # NOTE: The brew command includes the "-n" option to simulate the upgrade process, without actually performing it.  It results in a list of things that /would be/ updated.
        SECTION="System_PendingUpdates-Brew"
        dumpcmdForEachUser "brew upgrade -n"
        SECTION="System_PendingUpdates"
    footer

    header "System_RunningProcesses"
        comment "This is as good as a blood test at the doctor's office.  If it's not listed here, the process isn't running. You can use it to find running"
        comment "anti-virus daemons, web servers, productivity software, and just about everything else."
        dumpcmd "ps -ef"
    footer

    header "System_ServiceInfo" "Backgroun"
        comment "This section attempts to get the status of all of the running services on a system.  MacOS services are more OS feature-related than how we use the same term in Linxu (network-accessible servers)"
        comment "For network-accessible servers, see \"Network_ListeningServices\" below."
        comment "In this list, if there's a number in the first field, it means the service is currently running."
        SECTION="System_ServiceInfo"
            dumpcmd "launchctl list"
    footer

    header "System_IntegrityProtection"
        comment "System Integrity Protection provides restrictions on interactions with system-level processes."
        dumpcmd "csrutil status"
    footer

    header "System_AMFI"
        comment "Apple Mobile File Integrity (AMFI) is the macOS kernel module that enforces code-signing and library validation.  It's always enabled unless it's been specifically disabled."
        comment "This check should report as '0' meaning that the service has NOT been disabled."
        dumpcmdgrep "nvram -p" "-c" "amfi_get_out_of_my_way=1"
    footer

    header "System_SSV"
        comment "The Sealed System Volume (SSV) feature computes a SHA-256 hash of system files that should not change.  The hash is compared at boot time."
        dumpcmd "csrutil authenticated-root status"
    footer

    header "System_SystemPrefsLocked"
        comment "This setting determines whether a password is required to access system-wide preferences."
        comment "We're looking for \"1\" to show that the setting is enabled"
        getSystemPrefsLocked
    footer
}

function Network {
    header "Network_ConnectivityTest"
        comment "A quick PING test to google.com.  On a PCI audit, ideally this would fail from systems in the CDE (not necessarily those that are \"connected to\")."
        comment "If it doesn't, it's worth a conversation as all inbound and outbound communication must be explicitly defined for the CDE."
        comment "If it's not a PCI audit, you can decide if this is helpful to you."
        comment "Pinging www.google.com"
            dumpcmd "ping -c4 www.google.com"
    footer

    header "Network_DNSResolver"
        comment "We collect the DNS resolver configuration.  Using an external resolver (e.g. 8.8.8.8 for Google) could open up some interesting attack vectors through DNS poisoning."
        comment "It's also interesting to note if there are any differences across the sample population as differences could be indicative of systems under differing levels of management."
        dumpfile "/etc" "resolv.conf"
    footer

    header "Network_FirewallStatus"
        comment "MacOS' ALF (Application Level Firewall?) is the built-in desktop firewall for the system.  This section provides the basic status information,"
        comment "but if you want to see the rules, you'll want to inspect those separately."
        comment "We'll use the system_profiler command to get the data in a standard, and human-readble, format."
        #comment "The actual setting could be controlled in either of two files, so we'll grab them both."
        # Commented out on 6/22/2023 in favor of the system_profiler reporting method
        # BASE_SECTION=$SECTION
        # SECTION="$BASE_SECTION-alfGlobalState"
        # dumpcmd "defaults read /Library/Preferences/com.apple.alf globalstate"
        # SECTION="$BASE_SECTION-FirewallEnabled"
        # dumpcmd "defaults read /Library/Preferences/com.apple.security.firewall EnableFirewall"
        # SECTION=$BASE_SECTION
        dumpcmd "system_profiler SPFirewallDataType"
    footer

    header "Network_InterfacesSummary"
        comment "We collect the MacOS Interface Summary which includes useful information about each interface (including IP addresses)."
        dumpcmd "system_profiler SPNetworkDataType"
        # BASE_SECTION=$SECTION
        # or INTERFACE in $(ipconfig getiflist); do
        #     SECTION="$BASE_SECTION-$INTERFACE"
        #     dumpcmd "ipconfig getsummary $INTERFACE"
        # done
        # SECTION=$BASE_SECTION
    footer

    header "Network_ListeningServices"
        comment "We list all of the listening ports, including the binary that's listening on it.  I consider \"System_RunningProcesses\", \"System_PackageManagerUpdates\","
        comment "and this section to be three most-valuable sections in the report."
        dumpcmdgrep "lsof -i -P" "-e" "LISTEN"
    footer

    header "Network_OpenSSHServerConfig"
        comment "We collect the active configuration of the SSH server, including both actively configured and default settings"
        comment "including the various defaults as applied.  The second method provides the entire sshd_config file, including"
        comment "comments, overridden values, etc."
        comment "OpenSSH effective configuration"
        dumpcmd "sshd -T"
    footer

    header "Network_OpenSSHClientConfig"
        comment "The site-wide client SSH configurations are used when an SSH sessions is initiated from this systems -- e.g. if this server is jumpbox used to connect to other systems."
        comment "NOTE: Users may also have a ~/.ssh/ssh_config file which might override some of these settings."
            dumpfile "/etc/ssh" "ssh_config"
            dumpfile "/etc/ssh/ssh_config.d" "*"
    footer

    header "Network_RouteTable"
        comment "This is probably only useful if you end up having to chase down something wonky in the network routing table.  But, we collect it just in case you might need it."
        dumpcmd "netstat -rn"
    footer

    header "Network_SharesNFS"
        comment "These configurations drive whether or not this server is providing network file sharing services."
        comment "The Network File System (NFS) is common in Unix/Linux-only environments where SMB compatability is not needed for access to/from Windows systems"
        comment "MacOS can run an NFS server as nfsd and the directories that will be shared are listed in /etc/exports"

        #Get the status of the NFS server
        dumpcmd "nfsd status"

        comment "NFS Server Configurations"
        dumpfile "/etc" "nfs.conf"

        comment "/etc/exports -- File systems/directories exported as NFS mount points that other systems can connect to."
            dumpfile "/etc" "exports"
    footer

    header "Network_SharesSamba"
        comment "MacOS SMB configuration settings if the device is configured with File Sharing.  Also be sure to check if the device is listening on port 445/tcp"
        comment "to determine if the system is currently available as a Windows file share (Network_ListeningServices)."
            dumpcmdgrep "defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist" "-i" "NetBIOSName\|ServerDescription\|Workgroup"
        SECTION="Network_SharesSamba-SharedFolders"
        dumpcmd "dscl . -readall /Sharepoints afp_guestacces afp_shared directory_path smb_shared smb_guessaccess smb_createmask smb_directorymask smb_sealed"
        SECTION="Network_SharesSamba"
    footer

    header "Network_EtcHosts"
        comment "/etc/hosts -- local name-to-IP mapping.  Entries in this file generally tend to override DNS lookup or any other name-to-IP mapping."
            dumpfile "/etc" "hosts"
    footer

    header "Network_SNMPInfo"
        comment "We collect the SNMP configuration.  Of particular interest here is the permissions granted to each community strings -- could be read-only or read-write."
        comment "Read-write should be used sparingly if at all.  Even read-only can be interesting if it's using SNMPv2 -- which can't do encryption -- or SNMPv3 without crypto."
        comment "Also check Network_ListeningServices for any listener on 161/udp to determine if the SNMP agent is active."
        dumpfile "/etc/snmp" "snmpd.conf"
    footer

    header "Network_NTP"
        comment "MacOS NTP settings are maintained in /etc/ntp.conf.  Only trusted time sources should be used.  Anything pulling time from pool.ntp.org is getting time from a random (and untrustworthy) time source."
        dumpcmd "systemsetup -getusingnetworktime"
        dumpcmd "systemsetup -getnetworktimeserver"
        SECTION="Network_NTP-config"
            dumpfile "/etc" "ntp.conf" "3"
        SECTION="Network_NTP"
    footer

    header "Network_WebServer"
        comment "A MacOS device can run a personal web server based on Apache HTTPD.  This can, among other things, allow other users to login to the device and transfer files via HTTP."
        comment "The ideal response is \"0\" meaning that the webserver is disabled."
        dumpcmdgrep "launchctl list" "-c" "org.apache.httpd"
    footer
}

function Logging {
    header "Logging_AuditdStatus"
        comment "AuditD performs kernel-level logging.  It can generate a lot of data and requires special tools to make the most sense out of the output, so we only grab the configs and none of the events."
        comment "According to CIS Benchmarks, the correct response below is that auditd shows up in the list."
        dumpcmdgrep "launchctl list" "-e" "auditd"
    footer

    header "Logging_InstallLog"
        comment "macOS writes information pertaining to system-related events to the file /var/log/install.log.  The retention period for this log file is set in the /etc/asl/com.apple.install configuration file."
        comment "Specifically, we want to see a 'ttl=365' or greater.  We do NOT want to see 'all_max=' followed by a file size (default all_max=50mb)."
        dumpfile "/etc/asl" "com.apple.install"
    footer

    header "Logging_AuditConfig"
        comment "The /etc/security directory includes configurations for the MacOS auditing system, and includes:"
        comment "  - audit_control defines several parameters, but most important is the 'expire-after' parameter.  If set, this is the length of time or max size after which old logs will be deleted."
        comment "    If not set, logs will be retained indefinitely.  An example configuration might be 'expire-after:60d or 5G' which would remote old logs after 2 months or 10GB."
        comment "  - audit_user defines the audit actions that will be taken for specific users"
        comment "  - audit_event includes the various events that will be logged such as starting a new process, opening a file, etc.  audit_events are associated with an audit_class."
        comment "  - audit_class describes the classes of events such as 'login_logout', 'file_create' and 'network'."
        comment "At least for a PCI audit, if the MacOS device is in scope, we would want to see that audit_user defines logging for all actions (executing commands, file read/write, etc) taken by the root user."
        dumpfile "/etc/security" "*"
    footer

    header "Logging_AuditPermissions"
        comment "Permissions should be restricted to the local folders where log files are written (/var/log and /var/audit)."
        dumpcmd "ls -l /private/var"
    footer

    header "Logging_Firewall"
        comment "Firewall logging should be enabled to capture events from the MacOS desktop firewall (socketFilter)"
        comment "We want to see:"
        comment "  - firewall-EnableLogging: true"
        comment "  - firewall-LoggingOption: detail"
        comment "  - alf-loggingenabled: 1"
        comment "  - alf-loggingoption: 4"

        SECTION="Logging_Firewall-firewall"
            getOsaUserDefault "com.apple.security.firewall" "EnableLogging"
            getOsaUserDefault "com.apple.security.firewall" "LoggingOption"
        SECTION="Logging_Firewall-alf"
            getOsaUserDefault "com.apple.security.alf" "loggingenabled"
            getOsaUserDefault "com.apple.security.alf" "loggingoption"
        SECTION="Logging_Firewall"
    footer

    header "Logging_SyslogConfig"
        comment "A common check here is to make sure that logs are shipped to an external, centralized log server.  OSSEC or another tool might also capture the logs, but if none of those"
        comment "are installed, then SysLog will need to do it.  Check for lines with an @ sign."
        comment "Default logging facility for recent Ubuntu and CentOS installations"
        dumpfile "/etc" "syslog.conf"
        dumpfile "/etc" "asl.conf"
    footer

    header "Logging_Samples"
        comment "A full list of the /var/log sub-directory.  Below, we grab samples of some of the common ones, but if any of these other log files look interesting, you'll need to request those separately"
        SECTION="Logging_SamplesVarLogList"
            dumpcmd "find /var/log"

        comment "We collect samples of various logs below.  To save space, we collect only the first and last 25 lines of each file to confirm that events were and continue to be written to the logs."
        comment "If you need to see more of some log files, you'll need to ask for those separately"

        #Setup an array of log files (under /var/log) that we'll loop through below
        ITEMS=(system.log install.log alf.log appfirewall.log)

        #For each of the log files in the array, grab the first and last 25 lines from the file
        for ITEM in ${ITEMS[*]}; do
            SECTION="Logging_Samples-$ITEM-head"
            dumpcmd "head --lines=25 /var/log/$ITEM"
            SECTION="Logging_Samples-$ITEM-tail"
            dumpcmd "tail --lines=25 /var/log/$ITEM"
        done
        SECTION="Logging_Samples"
    footer
}

function Users {
    header "Users_AuthConfig"
        comment "This section shows the authentication systems that the device is configured for.  Examples include:"
        comment "  Active Directory - self-explanatory"
        comment "  KerberosKDC - probably directly tied to Active Directory since AD is also built on Kerberos"
        comment "  shadowhash - local authentication source"
        dumpcmd "dscl . -list /Config"
    footer

    header "Users_HomeFolders"
        comment "This list provides the permissions for all folders under the /Users directories.  Only the user should have permissions to their own folder, so pay special attention to 'group' and 'other' permissions."
        comment "Ideally, \"drwx------\" or \"drwx--x--x\" is what you should see."
        dumpcmd "ls -l /Users"
    footer

    header "Users_PasswordPolicy"
        comment "This is the password policy for locally-defined accounts.  Note: MacOS can also be joined to an Active Directory domain, in which case the relevant policy from AD will apply but only to those specific users.  See Users_ADConfig for those details."
        getPWPolicy

    header "Users_LocalUsers"
        comment "A list of all locally-defined users.  You can safely disregard any user with \"/usr/bin/false\" or \"/sbin/nologin\" as they can't login.  But any user with other shells is fair game."
        dumpcmd "dscl . -readall /Users RecordName UniqueID NFSHomeDirectory UserShell"
    footer

    header "Users_LocalGroups"
        comment "A list of groups and their memberships.  Of special interest:"
        comment "  sudo -- Users who can issue commands as root (default /etc/sudoers configuration)"
        comment "  adm -- Users who might be able to issue commands as root (check the /etc/sudoers configuration)"
        comment "  Any other group listed in the /etc/sudoers config listed in Users_SudoersConfig section"
        dumpcmd "dscl . -readall /Groups RecordName GroupMembership PrimaryGroupID"
    footer

    header "Users_RootStatus"
        comment "The root user shouldn't be used except when a regular user account has elevated their permissions through sudo.  This check determines if the root account is enabled with a local password."
        comment "  0  - Disabled"
        comment "  1+ - Enabled"
        dumpcmdgrep "dscl . -read /Users/Root AuthenticationAuthority" "-c" "ShadowHash\|Kerberos"
    footer

    header "Users_AdminScreenSaverBypass"
        comment "If enabled, an administrative user on a MacOS device can bypass the screensaver lock of another user"
        dumpcmdgrep "security authorizationdb read system.login.screensaver" "-c" "use-login-window-ui"

    header "Users_SudoersConfig"
        comment "The Sudoers config determines which users and groups can execute commands as ROOT by prefacing the command with \"sudo <command\"."
        comment "See https://xkcd.com/149/ for a visual reference of the effect that the SUDO command has and https://www.linux.com/training-tutorials/configuring-linux-sudoers-file/ for a more detailed explanation."
        dumpfile "/etc" "sudoers"
        dumpfile "/etc/sudoers.d" "*"
        dumpfile "/etc" "sudo.conf"
    footer

    header "Users_AuthorizedKeys"
        comment "The presence of a user's .ssh/authorized_keys file indicates the potential to login via SSH.  This would override the LOCKED status results of the Users_UserStatus check later in the script."
        dumpcmd "ls -1 /Users/*/.ssh/authorized_keys"
    footer

    header "Users_SiriStatus"
        comment "Siri can be enabled on a MacOS system just like on the iPhone.  This section identifies if Siri is enabled and, if so, the settings are also displayed"
        comment "Siri is enabled if a '1' is returned in the '-Enabled' result below.  Otherwise (blank or 0), it's disabled."
        BASE_SECTION=$SECTION
        for USERNAME in $(dscl . list /Users); do
            if ! [[ "$USERNAME" =~ $IGNORE_USERS ]]; then
                SECTION="$BASE_SECTION-$USERNAME-Enabled"
                dumpcmd "sudo -u $USERNAME defaults read com.apple.assistant.support.plist"
                SECTION="$BASE_SECTION-$USERNAME-Config"
                dumpcmd "sudo -u $USERNAME defaults read com.apple.Siri.plist"
            fi
        done;
        SECTION=$BASE_SECTION
    footer

    header "Users_ScreensaverStatus"
        comment "Screensavers should lock within 15 minutes (900 seconds) of inactivity on the system.  If the following is blank, then the default is in use, which is 20 minutes"
        dumpcmdForEachUser "defaults -currentHost read com.apple.screensaver idleTime"
    footer

    header "Users_PasswordHints"
        comment "Passowrd hints should not be used as they are often directly related to the user's password and even when they're not, they're still just another form of \"someting you know\" and do regularly meet the password complexity requirements."
        comment "This section shows if hints are displayed on the login screen.  The value should 0."
        getOsaUserDefault "com.apple.loginwindow" "RetriesUntilHint"
    footer

    header "Users_SecureKeyboardEntryTerminal"
        comment "The Secure Keyboard Entry Terminal application minimizes the risk of keyboard loggers intercepting keypresses when using the Terminal (shell prompt) app."
        comment "It should be enabled (1)"
    dumpcmdForEachUser "defaults read -app Terminal SecureKeyboardEntry"

}


function WorldFiles {
    header "WorldFiles"
        echo -e "[*] Finding world writable files, which could take awhile.\n[*] Please wait..."
        comment  "World Writable Files/Directories"
        DIRS=('/System/Volumes/Data/System' '/Applications' '/System/Data/System/Library')
        for d in ${DIRS[*]}; do
            SECTION="WorldFiles-$d"
            dumpcmd "find $d -perm -2 -ls"
        done
        SECTION="WorldFiles"
    footer
}

clear

# Set some global variables
USER=$(whoami)
HOSTNAME=$(hostname -s)
FANCY_HOSTNAME=$(systemsetup -getcomputername | tr -dc '[A-Za-z0-9 ]')
FANCY_HOSTNAME=${FANCY_HOSTNAME/Computer Name /}
IGNORE_USERS="^_|daemon|root|nobody"
DEBUG=0                                                                                 # Holder variable to enable/disable debug mode
DEBUGCMD=0                                                                              # Holder variable to enable/disable debugcmd mode
WORLDFILES=1                                                                            # Holder variable to enable/disable WORLDFILES checking
MODULESLIST=( System Network Logging Users WorldFiles )                                 # An array to hold the valid list of modules
REPORT_NAME=$HOSTNAME.txt                                                               # Where to write the report to
START_DIR=$(pwd)

#Check if running as ROOT / display help and exit if not
if [ "$USER" != "root" ]; then
    echo -e "Not running as ROOT"
    usage
    EXITCODE=1
    exit $EXITCODE
fi

#Get the command line options
while getopts ":cdh" OPTION; do
    case $OPTION in
        c )
            DEBUGCMD=1
            ;;
        d )
            DEBUG=1
            DEBUGCMD=1
            ;;
        * )
            usage
            EXITCODE=1
            exit $EXITCODE
            ;;
    esac
done

if [ -e $REPORT_NAME ]; then
    #Clean up previous runs of the script
    echo -e "Previous report file $REPORT_NAME found.  Deleting..."
    rm $REPORT_NAME
fi

echo -e ''$_{1..50}'+' 2> /dev/null >> $REPORT_NAME
echo -e "[*] Beginning KP MacOS Audit Script v$KPMACVERSION\n[*] Please wait..."
echo "System Report for $(hostname)" > $REPORT_NAME
echo "This report was generated $(date)" 2> /dev/null >> $REPORT_NAME
echo "KPMACVERSION: $KPMACVERSION" 2> /dev/null >> $REPORT_NAME
echo "System Full Name: $FANCY_HOSTNAME" >> $REPORT_NAME
echo -e ''$_{1..50}'+' 2> /dev/null >> $REPORT_NAME

# Always run this check to give context to the system we're looking at
header "System_VersionInformation"
    comment "Collecting some basic information about the system.  Take a look through this section to find the string (it varies from RPM-based and Debian-based distros) that will let you see"
    comment "in one list which OS types and versions are in use.  You can use that to check online to make sure that all OSes in use are still supported by the vendor."
    dumpcmd "uname -a"
    comment "OS Release:"
        dumpcmd "sw_vers"
footer

# Run each module
for MODULE in "${MODULESLIST[@]}"; do
    debug "Calling $MODULE"
    $MODULE
    debug "Finished $MODULE"
done

echo "[*] Finished KP MacOS Audit Script"
echo "[*] Results are located in $REPORT_NAME"
