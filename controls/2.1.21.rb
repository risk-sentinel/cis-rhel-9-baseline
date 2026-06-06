# encoding: UTF-8

control 'C-2.1.21' do
  title 'Ensure mail transfer agents are configured for local-only mode'
  desc  "
    Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.

    The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems.
  "
  desc  'rationale', "
    Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.

    The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems.
  "
  desc  'check', "
    Run the following script to verify that the MTA is not listening on any non-loopback address `( 127.0.0.1 or ::1)`:
    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       a_port_list=(\"25\" \"465\" \"587\")
       if [ \"$(postconf -n inet_interfaces)\" != \"inet_interfaces = all\" ]; then
          for l_port_number in \"${a_port_list[@]}\"; do
             if ss -plntu | grep -P -- ':'\"$l_port_number\"'\\b' | grep -Pvq -- '\\h+(127\\.0\\.0\\.1|\\[?::1\\]?):'\"$l_port_number\"'\\b'; then
                   l_output2=\"$l_output2\\n - Port \\\"$l_port_number\\\" is listening on a non-loopback network interface\"
             else
                   l_output=\"$l_output\\n - Port \\\"$l_port_number\\\" is not listening on a non-loopback network interface\"
             fi
          done
       else
          l_output2=\"$l_output2\\n - Postfix is bound to all interfaces\"
       fi
       unset a_port_list
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Edit `/etc/postfix/main.cf` and add the following line to the RECEIVING MAIL section. If the line already exists, change it to look like the line below:

    ```
    inet_interfaces = loopback-only
    ```

    Run the following command to restart `postfix`:

    ```
    # systemctl restart postfix
    ```

    Note:
    - This remediation is designed around the postfix mail server.
    - Depending on your environment you may have an alternative MTA installed such as sendmail. If this is the case consult the documentation for your installed MTA to configure the recommended state.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.21'
  tag cis_number:            '2.1.21'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020121r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command("ss -plntu | grep -E ':25\b'") do
    its('stdout') { should_not match(/0\.0\.0\.0:25|\[::\]:25/) }
  end
end