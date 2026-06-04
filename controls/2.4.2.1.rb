# encoding: UTF-8

control 'C-2.4.2.1' do
  title 'Ensure at is restricted to authorized users'
  desc  "
    `at` allows fairly complex time specifications, extending the POSIX.2 standard. It accepts times of the form HH:MM to run a job at a specific time of day. (If that time is already past, the next day is assumed.) You may also specify midnight, noon, or teatime (4pm) and you can have a time-of-day suffixed with AM or PM for running in the morning or the evening. You can also say what day the job will be run, by giving a date in the form month-name day with an optional year, or giving a date of the form MMDD[CC]YY, MM/DD/[CC]YY,  DD.MM.[CC]YY or [CC]YY-MM-DD. The specification of a date must follow the specification of the time of day. You can also give times like now + count time-units, where the time-units can be minutes, hours, days, or weeks and you can tell at to run the job today by suffixing the time with today and to run the job tomorrow by suffixing the time with tomorrow.

    The `/etc/at.allow` and `/etc/at.deny` files determine which user can submit commands for later execution via at or batch. The format of the files is a list of usernames, one on each line. Whitespace is not permitted. If the file `/etc/at.allow` exists, only usernames mentioned in it are allowed to use at. If `/etc/at.allow` does not exist, `/etc/at.deny` is checked, every username not mentioned in it is then allowed to use at. An empty `/etc/at.deny` means that every user may use at. If neither file exists, only the superuser is allowed to use at.

    On many systems, only the system administrator is authorized to schedule `at` jobs. Using the `at.allow` file to control who can run `at` jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  desc  'rationale', "
    `at` allows fairly complex time specifications, extending the POSIX.2 standard. It accepts times of the form HH:MM to run a job at a specific time of day. (If that time is already past, the next day is assumed.) You may also specify midnight, noon, or teatime (4pm) and you can have a time-of-day suffixed with AM or PM for running in the morning or the evening. You can also say what day the job will be run, by giving a date in the form month-name day with an optional year, or giving a date of the form MMDD[CC]YY, MM/DD/[CC]YY,  DD.MM.[CC]YY or [CC]YY-MM-DD. The specification of a date must follow the specification of the time of day. You can also give times like now + count time-units, where the time-units can be minutes, hours, days, or weeks and you can tell at to run the job today by suffixing the time with today and to run the job tomorrow by suffixing the time with tomorrow.

    The `/etc/at.allow` and `/etc/at.deny` files determine which user can submit commands for later execution via at or batch. The format of the files is a list of usernames, one on each line. Whitespace is not permitted. If the file `/etc/at.allow` exists, only usernames mentioned in it are allowed to use at. If `/etc/at.allow` does not exist, `/etc/at.deny` is checked, every username not mentioned in it is then allowed to use at. An empty `/etc/at.deny` means that every user may use at. If neither file exists, only the superuser is allowed to use at.

    On many systems, only the system administrator is authorized to schedule `at` jobs. Using the `at.allow` file to control who can run `at` jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  desc  'check', "
    - IF - at is installed on the system:

    Run the following command to verify `/etc/at.allow`:
    - Exists
    - Is mode `0640` or more restrictive
    - Is owned by the user `root`
    - Is group owned by the group `daemon` or group `root`

    ```
    # stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/at.allow

    Access: (640/-rw-r-----) Owner: (root) Group: (daemon)
    -OR-
    Access: (640/-rw-r-----) Owner: (root) Group: (root)
    ```

    Verify mode is `640` or more restrictive, owner is `root`, and group is `daemon` or `root`

    Run the following command to verify `at.deny` doesn't exist, -OR- is:
    - Mode `0640` or more restrictive
    - Owned by the user `root`
    - Group owned by the group `daemon` or group `root`

    ```
    # [ -e \"/etc/at.deny\" ] && stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/at.deny

    Access: (640/-rw-r-----) Owner: (root) Group: (daemon)
    -OR-
    Access: (640/-rw-r-----) Owner: (root) Group: (root)
    -OR-
    Nothing is returned
    ```

    If a value is returned, verify mode is 640 or more restrictive, owner is `root`, and group is `daemon` or `root`
  "
  desc  'fix', "
    - IF - at is installed on the system:

    Run the following script to:
    - `/etc/at.allow`:
      - Create the file if it doesn't exist
      - Change owner or user `root`
      - If group `daemon` exists, change to group `daemon`, else change group to `root`
      - Change mode to `640` or more restrictive
    - - IF - `/etc/at.deny` exists:
      - Change owner or user `root`
      - If group `daemon` exists, change to group `daemon`, else change group to `root`
      - Change mode to `640` or more restrictive

    ```
    #!/usr/bin/env bash

    {
       grep -Pq -- '^daemon\\b' /etc/group && l_group=\"daemon\" || l_group=\"root\"
       [ ! -e \"/etc/at.allow\" ] && touch /etc/at.allow
       chown root:\"$l_group\" /etc/at.allow
       chmod u-x,g-wx,o-rwx /etc/at.allow
       [ -e \"/etc/at.deny\" ] && chown root:\"$l_group\" /etc/at.deny
       [ -e \"/etc/at.deny\" ] && chmod u-x,g-wx,o-rwx /etc/at.deny
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '2.4.2.1'
  tag cis_number:            '2.4.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-02040201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/at.allow') do
    it { should exist }
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end