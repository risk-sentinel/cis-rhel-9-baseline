# encoding: UTF-8

control 'C-6.2.1.2' do
  title 'Ensure journald log file access is configured'
  desc  "
    Journald will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.

    It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.
  "
  desc  'rationale', "
    Journald will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.

    It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.
  "
  desc  'check', "
    First determine if there is an override file `/etc/tmpfiles.d/systemd.conf`. If so, this file will override all default settings as defined in `/usr/lib/tmpfiles.d/systemd.conf` and should be inspected.

    If no override file exists, inspect the default `/usr/lib/tmpfiles.d/systemd.conf` against the site specific requirements.

    Ensure that file permissions are mode `0640` or more restrictive.

    Run the following script to verify if an override file exists or not and if the files permissions are mode `640` or more restrictive:
    ```
    #!/usr/bin/env bash

    {
        l_output=\"\" file_path=\"\"
        # Check for the existence of an override file
        if [ -f /etc/tmpfiles.d/systemd.conf ]; then
            file_path=\"/etc/tmpfiles.d/systemd.conf\"
        elif [ -f /usr/lib/tmpfiles.d/systemd.conf ]; then
            file_path=\"/usr/lib/tmpfiles.d/systemd.conf\"
        fi   
        if [ -n \"$file_path\" ]; then # Ensure a file path is found
            higher_permissions_found=false  # Initialize a flag to check if higher permissions are found
            # Read the file line by line and check for permissions higher than 0640
            while IFS= read -r line; do
                if echo \"$line\" | grep -Piq '^\\s*[a-z]+\\s+[^\\s]+\\s+0*([6-7][4-7][1-7]|7[0-7][0-7])\\s+'; then
                    higher_permissions_found=true
                    break
                fi
            done < \"$file_path\"
            if $higher_permissions_found; then
                echo -e \"\\n - permissions other than 0640 found in $file_path\"
    			l_output=\"$l_output\\n - Inspect $file_path\"
            else
                echo -e \"All permissions inside $file_path are 0640 or more restrictive.\"
            fi
        fi
       if [ -z \"$l_output\" ]; then # Provide output from checks
          echo -e \"\\n- Audit Result:\\n   PASS \\n$file_path exists and has correct permissions set\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   REVIEW \\n$l_output\\n - Review permissions to ensure they are set IAW site policy\"
       fi    
    }
    ```
  "
  desc  'fix', "
    If the default configuration is not appropriate for the site specific requirements, copy `/usr/lib/tmpfiles.d/systemd.conf` to `/etc/tmpfiles.d/systemd.conf` and modify as required. Requirements is either `0640` or site policy if that is less restrictive.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.2.1.2'
  tag cis_number:            '6.2.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # log_pipeline axis: off-box forwarding/retention is proven by durable CloudWatch
  # ingestion (e.g. via the CloudWatch agent); onbox => logs retained on-box (N/A).
  if log_offbox?
    impact 0.5
    cwl = cw_ingestion
    only_if("log_pipeline ships off-box but CloudWatch ingestion could not be read live (#{cwl.error}); evidence supplied by SAF attestation.") { cwl.available? }
    describe cwl do
      it { should be_ingesting_within(input('cloudwatch_max_ingestion_lag')) }
    end
  else
    impact 0.0
    describe 'Off-box log pipeline N/A (log_pipeline=onbox; logs retained on-box)' do
      subject { true }
      it { is_expected.to eq true }
    end
  end
end
