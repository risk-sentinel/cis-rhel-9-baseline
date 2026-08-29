# encoding: UTF-8

control 'C-2.4.1.8' do
  title 'Ensure crontab is restricted to authorized users'
  desc  "
    `crontab` is the program used to install, deinstall, or list the tables used to drive the cron daemon. Each user can have their own crontab, and though these are files in `/var/spool/cron/crontabs`, they are not intended to be edited directly.

    If the `/etc/cron.allow` file exists, then you must be listed (one user per line) therein in order to be allowed to use this command. If the `/etc/cron.allow` file does not exist but the `/etc/cron.deny` file does exist, then you must not be listed in the `/etc/cron.deny` file in order to use this command.

    If neither of these files exists, then depending on site-dependent configuration parameters, only the super user will be allowed to use this command, or all users will be able to use this command.

    If both files exist then `/etc/cron.allow` takes precedence. Which means that `/etc/cron.deny` is not considered and your user must be listed in `/etc/cron.allow` in order to be able to use the crontab.

    Regardless of the existence of any of these files, the root administrative user is always allowed to setup a crontab.

    The files `/etc/cron.allow` and `/etc/cron.deny`, if they exist, must be either world-readable, or readable by group `crontab`. If they are not, then cron will deny access to all users until the permissions are fixed.

    There is one file for each user's crontab under the `/var/spool/cron/crontabs` directory. Users are not allowed to edit the files under that directory directly to ensure that only users allowed by the system to run periodic tasks can add them, and only syntactically correct crontabs will be written there. This is enforced by having the directory writable only by the `crontab` group and configuring crontab command with the setgid bid set for that specific group.

    Note:
    - Even though a given user is not listed in `cron.allow`, cron jobs can still be run as that user
    - The files `/etc/cron.allow` and `/etc/cron.deny`, if they exist, only controls administrative access to the crontab command for scheduling and modifying cron jobs

    On many systems, only the system administrator is authorized to schedule `cron` jobs. Using the `cron.allow` file to control who can run `cron` jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  desc  'rationale', "
    `crontab` is the program used to install, deinstall, or list the tables used to drive the cron daemon. Each user can have their own crontab, and though these are files in `/var/spool/cron/crontabs`, they are not intended to be edited directly.

    If the `/etc/cron.allow` file exists, then you must be listed (one user per line) therein in order to be allowed to use this command. If the `/etc/cron.allow` file does not exist but the `/etc/cron.deny` file does exist, then you must not be listed in the `/etc/cron.deny` file in order to use this command.

    If neither of these files exists, then depending on site-dependent configuration parameters, only the super user will be allowed to use this command, or all users will be able to use this command.

    If both files exist then `/etc/cron.allow` takes precedence. Which means that `/etc/cron.deny` is not considered and your user must be listed in `/etc/cron.allow` in order to be able to use the crontab.

    Regardless of the existence of any of these files, the root administrative user is always allowed to setup a crontab.

    The files `/etc/cron.allow` and `/etc/cron.deny`, if they exist, must be either world-readable, or readable by group `crontab`. If they are not, then cron will deny access to all users until the permissions are fixed.

    There is one file for each user's crontab under the `/var/spool/cron/crontabs` directory. Users are not allowed to edit the files under that directory directly to ensure that only users allowed by the system to run periodic tasks can add them, and only syntactically correct crontabs will be written there. This is enforced by having the directory writable only by the `crontab` group and configuring crontab command with the setgid bid set for that specific group.

    Note:
    - Even though a given user is not listed in `cron.allow`, cron jobs can still be run as that user
    - The files `/etc/cron.allow` and `/etc/cron.deny`, if they exist, only controls administrative access to the crontab command for scheduling and modifying cron jobs

    On many systems, only the system administrator is authorized to schedule `cron` jobs. Using the `cron.allow` file to control who can run `cron` jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  desc  'check', "
    - IF - cron is installed on the system:

    Run the following command to verify `/etc/cron.allow`:
    - Exists
    - Is mode `0640` or more restrictive
    - Is owned by the user `root`
    - Is group owned by the group `root`

    ```
    # stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/cron.allow

    Access: (640/-rw-r-----) Owner: (root) Group: (root)
    ```

    Run the following command to verify either `cron.deny` doesn't exist or is:
    - Mode `0640` or more restrictive
    - Owned by the user `root`
    - Group owned by the group `root`

    ```
    # [ -e \"/etc/cron.deny\" ] && stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/cron.deny
    ```
	
    Verify either nothing is returned or returned value is:

    ```
    Access: (640/-rw-r-----) Owner: (root) Group: (root)
    ```
  "
  desc  'fix', "
    - IF - cron is installed on the system:

    Run the following script to:
    - Create `/etc/cron.allow` if it doesn't exist
    - Change owner to user `root`
    - Change group owner to group `root`
    - Change mode to `640` or more restrictive

    ```
    #!/usr/bin/env bash

    {
       [ ! -e \"/etc/cron.allow\" ] && touch /etc/cron.allow
       chown root:root /etc/cron.allow
       chmod u-x,g-wx,o-rwx /etc/cron.allow
    }
    ```

    - IF - `/etc/cron.deny` exists, run the following commands to:
    - Change owner to user `root`
    - Change group owner to group `root`
    - Change mode to `640` or more restrictive

    ```
    # [ -e \"/etc/cron.deny\" ] && chown root:root /etc/cron.deny
    # [ -e \"/etc/cron.deny\" ] && chmod u-x,g-wx,o-rwx /etc/cron.deny
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '2.4.1.8'
  tag cis_number:            '2.4.1.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-02040108r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/cron.allow') do
    it { should exist }
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end