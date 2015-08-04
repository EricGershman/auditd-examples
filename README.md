# Auditd - The Linux Auditing System 
The Linux Auditing system has been widely adopted as a way to meet auditing standards and aid forensics investigations. Combined with a Host Intrusion Detection System, Auditd can be used for more than just forensics, it can be used to help find intrusion attempts and successful attacks. This repository aims to be a collection of examples, guidance and background information to help an administrator or security engineer deploy auditd in a detection capacity. 

## Configuring Auditd

###/etc/audit/auditd.conf

Settings in auditd.conf should be defined based on the importance of log integrity and how long you would like to keep records.

Here are the options that manage log rotation: 

```bash
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 6 
max_log_file_action = ROTATE
space_left = 75
```

The "_action" options determine how errors or disk space issues should be handled:

```bash
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
```

###/etc/audit/audit.rules

Example rule sets for most Linux distributions are stored in ```/usr/share/doc/auditd/examples```

This contains all of the rules that are loaded when the system starts, most audit.rules files start with the following control rules: 

```bash
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to panic
-f 2

```

Followed by the audit rules:

```
-a exit,always -S unlink -S rmdir
-a exit,always -S stime.*
-a exit,always -S setrlimit.*
-w /etc/group -p wa 
-w /etc/passwd -p wa 
-w /etc/shadow -p wa 
-w /etc/sudoers -p wa
```

The audit.rules file should end with the immutability settings:

```
#Enable auditd
-e 1 

#Make the configuration immutable, a reboot is required to change the configuration settings or rulesets.
-e 2 
```

Rules can be stored in '''/etc/audit/audit.rules''' or the ruleset can be changed while the daemon is running using the auditctl command.  

##Rules
“audit rules come in 3 varieties: control, file, and syscall”
  * Control - “configuring the audit system”
  * File - “audit access to particular files or directories”
  * Syscall - “loaded into a matching engine that intercepts each syscall”
```
-a action list: always log on syscall exit
-F field 
-S syscall: execve
-k Logging Key: programs
```
```bash
-a always,exit -F arch=b32 -F uid=33 -S execve -k programs -k www
-a always,exit -F arch=b64 -F uid=33 -S execve -k programs -k www
-a always,exit -F arch=b32 -C auid!=uid -S execve -k su_program -k programs
-a always,exit -F arch=b64 -C auid!=uid -S execve -k su_program -k programs
-a exit,always -S unlink -S rmdir
-a exit,always -S stime.*
-a exit,always -S setrlimit.*
-w /var/www -p wa
-w /etc/group -p wa
-w /etc/passwd -p wa
-w /etc/shadow -p wa
-w /etc/sudoers -p wa
```

##Commands
###auditd
```auditd -f``` - foreground auditd, messages go to stderr
```SIGHUP``` - Reconfigure Auditd, re-read configuration files 

"A boot param of audit=1 should be added to ensure that all processes that run before the audit daemon starts is marked as auditable by the kernel. "
- [Auditd Man Page] [auditd_man]

###auditctl
"auditctl program is used to control the behavior, get status, and add or delete rules into the 2.6 kernel’s audit system."

```auditctl - l``` - List current rule set

####Control Behavior 
   * ```auditctl -e 0``` - Temporarily disable auditing 
   * ```auditctl -e 1``` - Re-enable auditing
   * ```auditctl -e 2``` - Lock auditing to enabled, reboot to change configuration. 
   * ```auditctl -f 0``` - Do not report critical errors 
   * ```auditctl -f 1``` - Default, printk critical errors 
   * ```auditctl -f 2``` - Panic on critical errors 
- [Auditctl Man Page] [auditctl_man]

####Manage Rules
   * ```auditctl -D``` - Clear all rules
   * ```auditctl -l``` - List ruleset
   * ```auditctl -w /file -p rwxa -k file_alert``` - Watch all actions on a file and label with file_alert
   * ```auditctl -a always,exit -F arch=b32 -F uid=www-data -S execve -k programs -k www``` - Log all commands executed by the www-data user and label with programs and www keywords

###ausearch

   * ```ausearch -a 104``` - Search for event id 104
   * ```ausearch --uid 0 --syscall EXECVE --success yes``` - Search for all programs executed by root that were successful 
   * ```ausearch -ui 0 -sc EXECVE -sv yes``` - Search for all programs executed by root that were successful 

###aureport

   * ```aureport --auth``` - Authentication Report
   * ```aureport --login --failed``` - Failed Login Report
   * ```aureport --file``` - File Report

### ausearch and aureport together
Both ausearch and aureport are able to take in raw audit logs from STDIN, here is an example where we are looking at the executable report for a specific event: 

```
sysadmin@server:~$ sudo ausearch --event 662 --raw | aureport --executable --interpret

Executable Report
====================================
# date time exe term host auid event
====================================
1. 07/27/2015 16:13:29 /usr/bin/whoami (none) ? unset 662
```

 
#Links

## Man Pages

 * auditd: [http://linux.die.net/man/8/auditd](http://linux.die.net/man/8/auditd)
 * auditctl: [http://linux.die.net/man/8/auditctl](http://linux.die.net/man/8/auditctl)
 * audit.rules: [audit.rules_man](http://linux.die.net/man/7/audit.rules)

## Intro to Auditd
 * [http://security.blogoverflow.com/2013/01/a-brief-introduction-to-auditd/](http://security.blogoverflow.com/2013/01/a-brief-introduction-to-auditd/)
 * [https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-system_auditing.html](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-system_auditing.html)

## Reporting and Alerting

 * Splunk: [https://splunkbase.splunk.com/app/2642/](https://splunkbase.splunk.com/app/2642/)
 * Logstash Example: [https://gist.github.com/artbikes/2313040](https://gist.github.com/artbikes/2313040) 
 * Logstash on serverfault: [http://serverfault.com/questions/609192/how-to-parse-audit-log-using-logstash](http://serverfault.com/questions/609192/how-to-parse-audit-log-using-logstash) 
 * auditd Bro Framework: [https://github.com/set-element/auditdBroFramework](https://github.com/set-element/auditdBroFramework)
 * Ossec Decoder: [https://github.com/ossec/ossec-docs/blob/master/decoders/10_auditd_decoder.xml](https://github.com/ossec/ossec-docs/blob/master/decoders/10_auditd_decoder.xml) 

## Presentations
 * Audit & IDS by Steve Grubb [http://people.redhat.com/sgrubb/audit/audit-ids.pdf](http://people.redhat.com/sgrubb/audit/audit-ids.pdf)

### Upcoming 
* "Looking for Ghosts in the Machine" By Scott Campbell for BroCon ‘15: [https://www.bro.org/brocon2015/brocon2015_abstracts.html#looking-for-ghosts-in-themachine](https://www.bro.org/brocon2015/brocon2015_abstracts.html#looking-for-ghosts-in-themachine) 

##PCI-DSS
[http://linux-audit.com/category/compliance/pci-dss/](http://linux-audit.com/category/compliance/pci-dss/)
[http://networkrecipes.blogspot.com/2013/03/auditd-in-linux-for-pci-dss-compliance.html](http://networkrecipes.blogspot.com/2013/03/auditd-in-linux-for-pci-dss-compliance.html)

##CIS Benchmark
[https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.1.0.pdf](https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.1.0.pdf)
[http://blog.ptsecurity.com/2010/11/requirement-10-track-and-monitor-all.html](http://blog.ptsecurity.com/2010/11/requirement-10-track-and-monitor-all.html)

