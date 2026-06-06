# encoding: UTF-8

control 'C-4.1.2' do
  title 'Ensure a single firewall configuration utility is in use'
  desc  "
    In Linux security, employing a single, effective firewall configuration utility is crucial. Firewalls act as digital gatekeepers by filtering network traffic based on rules. Proper firewall configurations ensure that only legitimate traffic gets processed, reducing the system's exposure to potential threats. The choice between FirewallD and NFTables depends on organizational specific needs:
 
    `FirewallD` - Is a firewall service daemon that provides a dynamic customizable host-based firewall with a D-Bus interface. Being dynamic, it enables creating, changing, and deleting the rules without the necessity to restart the firewall daemon each time the rules are changed.

    `NFTables` - Includes the nft utility for configuration of the nftables subsystem of the Linux kernel.


    Notes: 
    - firewalld with nftables backend does not support passing custom nftables rules to firewalld, using the `--direct` option.
    - In order to configure firewall rules for nftables, a firewall utility needs to be installed and active of the system. The use of more than one firewall utility may produce unexpected results.
    - Allow port 22(ssh) needs to be updated to only allow systems requiring ssh connectivity to connect, as per site policy.

    Proper configuration of a single firewall utility minimizes cyber threats and protects services and data, while avoiding vulnerabilities like open ports or exposed services. Standardizing on a single tool simplifies management, reduces errors, and fortifies security across Linux systems.
  "
  desc  'rationale', "
    In Linux security, employing a single, effective firewall configuration utility is crucial. Firewalls act as digital gatekeepers by filtering network traffic based on rules. Proper firewall configurations ensure that only legitimate traffic gets processed, reducing the system's exposure to potential threats. The choice between FirewallD and NFTables depends on organizational specific needs:
 
    `FirewallD` - Is a firewall service daemon that provides a dynamic customizable host-based firewall with a D-Bus interface. Being dynamic, it enables creating, changing, and deleting the rules without the necessity to restart the firewall daemon each time the rules are changed.

    `NFTables` - Includes the nft utility for configuration of the nftables subsystem of the Linux kernel.


    Notes: 
    - firewalld with nftables backend does not support passing custom nftables rules to firewalld, using the `--direct` option.
    - In order to configure firewall rules for nftables, a firewall utility needs to be installed and active of the system. The use of more than one firewall utility may produce unexpected results.
    - Allow port 22(ssh) needs to be updated to only allow systems requiring ssh connectivity to connect, as per site policy.

    Proper configuration of a single firewall utility minimizes cyber threats and protects services and data, while avoiding vulnerabilities like open ports or exposed services. Standardizing on a single tool simplifies management, reduces errors, and fortifies security across Linux systems.
  "
  desc  'check', "
    Run the following script to verify that a single firewall utility is in use on the system:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\" l_fwd_status=\"\" l_nft_status=\"\" l_fwutil_status=\"\"
       # Determine FirewallD utility Status
       rpm -q firewalld > /dev/null 2>&1 && l_fwd_status=\"$(systemctl is-enabled firewalld.service):$(systemctl is-active firewalld.service)\"
       # Determine NFTables utility Status
       rpm -q nftables > /dev/null 2>&1 && l_nft_status=\"$(systemctl is-enabled nftables.service):$(systemctl is-active nftables.service)\"
       l_fwutil_status=\"$l_fwd_status:$l_nft_status\"
       case $l_fwutil_status in
          enabled:active:masked:inactive|enabled:active:disabled:inactive) 
             l_output=\"\\n - FirewallD utility is in use, enabled and active\\n - NFTables utility is correctly disabled or masked and inactive\\n - Only configure the recommendations found in the Configure Firewalld subsection\" ;;
          masked:inactive:enabled:active|disabled:inactive:enabled:active) 
             l_output=\"\\n - NFTables utility is in use, enabled and active\\n - FirewallD utility is correctly disabled or masked and inactive\\n - Only configure the recommendations found in the Configure NFTables subsection\" ;;
          enabled:active:enabled:active)
             l_output2=\"\\n - Both FirewallD and NFTables utilities are enabled and active. Configure only ONE firewall either NFTables OR Firewalld\" ;;
          enabled:*:enabled:*)
             l_output2=\"\\n - Both FirewallD and NFTables utilities are enabled\\n - Configure only ONE firewall: either NFTables OR Firewalld\" ;;
          *:active:*:active) 
             l_output2=\"\\n - Both FirewallD and NFTables utilities are enabled\\n - Configure only ONE firewall: either NFTables OR Firewalld\" ;;
          :enabled:active) 
             l_output=\"\\n - NFTables utility is in use, enabled, and active\\n - FirewallD package is not installed\\n - Only configure the recommendations found in the Configure NFTables subsection\" ;;
          :) 
             l_output2=\"\\n - Neither FirewallD or NFTables is installed. Configure only ONE firewall either NFTables OR Firewalld\" ;;
          *:*:) 
             l_output2=\"\\n - NFTables package is not installed on the system. Install NFTables and Configure only ONE firewall either NFTables OR Firewalld\" ;;
          *) 
             l_output2=\"\\n - Unable to determine firewall state. Configure only ONE firewall either NFTables OR Firewalld\" ;;
       esac
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Results:\\n  Pass \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Results:\\n  Fail \\n$l_output2\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to ensure that a single firewall utility is in use on the system:

    ```
    #!/usr/bin/env bash

    {
       l_fwd_status=\"\" l_nft_status=\"\" l_fwutil_status=\"\"
       # Determine FirewallD utility Status
       rpm -q firewalld > /dev/null 2>&1 && l_fwd_status=\"$(systemctl is-enabled firewalld.service):$(systemctl is-active firewalld.service)\"
       # Determine NFTables utility Status
       rpm -q nftables > /dev/null 2>&1 && l_nft_status=\"$(systemctl is-enabled nftables.service):$(systemctl is-active nftables.service)\"
       l_fwutil_status=\"$l_fwd_status:$l_nft_status\"
       case $l_fwutil_status in
          enabled:active:masked:inactive|enabled:active:disabled:inactive) 
             echo -e \"\\n - FirewallD utility is in use, enabled and active\\n - NFTables utility is correctly disabled or masked and inactive\\n - no remediation required\" ;;
          masked:inactive:enabled:active|disabled:inactive:enabled:active) 
             echo -e \"\\n - NFTables utility is in use, enabled and active\\n - FirewallD utility is correctly disabled or masked and inactive\\n - no remediation required\" ;;
          enabled:active:enabled:active)
             echo -e \"\\n - Both FirewallD and NFTables utilities are enabled and active\\n - stopping and masking NFTables utility\"
             systemctl stop nftables && systemctl --now mask nftables ;;
          enabled:*:enabled:*)
             echo -e \"\\n - Both FirewallD and NFTables utilities are enabled\\n - remediating\"
             if [ \"$(awk -F: '{print $2}' <<< \"$l_fwutil_status\")\" = \"active\" ] && [ \"$(awk -F: '{print $4}' <<< \"$l_fwutil_status\")\" = \"inactive\" ]; then
                echo \" - masking NFTables utility\"
                systemctl stop nftables && systemctl --now mask nftables
             elif [ \"$(awk -F: '{print $4}' <<< \"$l_fwutil_status\")\" = \"active\" ] && [ \"$(awk -F: '{print $2}' <<< \"$l_fwutil_status\")\" = \"inactive\" ]; then
                echo \" - masking FirewallD utility\"
                systemctl stop firewalld && systemctl --now mask firewalld
             fi ;;
          *:active:*:active) 
             echo -e \"\\n - Both FirewallD and NFTables utilities are active\\n - remediating\"
             if [ \"$(awk -F: '{print $1}' <<< \"$l_fwutil_status\")\" = \"enabled\" ] && [ \"$(awk -F: '{print $3}' <<< \"$l_fwutil_status\")\" != \"enabled\" ]; then
                echo \" - stopping and masking NFTables utility\"
                systemctl stop nftables && systemctl --now mask nftables
             elif [ \"$(awk -F: '{print $3}' <<< \"$l_fwutil_status\")\" = \"enabled\" ] && [ \"$(awk -F: '{print $1}' <<< \"$l_fwutil_status\")\" != \"enabled\" ]; then
                echo \" - stopping and masking FirewallD utility\"
                systemctl stop firewalld && systemctl --now mask firewalld
             fi ;;
          :enabled:active) 
             echo -e \"\\n - NFTables utility is in use, enabled, and active\\n - FirewallD package is not installed\\n - no remediation required\" ;;
          :) 
             echo -e \"\\n - Neither FirewallD or NFTables is installed.\\n - remediating\\n - installing NFTables\"
             echo -e \"\\n - Configure only ONE firewall either NFTables OR Firewalld and follow the according subsection to complete this remediation process\"
             dnf -q install nftables ;;
          *:*:) 
             echo -e \"\\n - NFTables package is not installed on the system\\n - remediating\\n - installing NFTables\"
             echo -e \"\\n - Configure only ONE firewall either NFTables OR Firewalld and follow the according subsection to complete this remediation process\"
             dnf -q install nftables ;;
          *) 
             echo -e \"\\n - Unable to determine firewall state\" 
             echo -e \"\\n - MANUAL REMEDIATION REQUIRED: Configure only ONE firewall either NFTables OR Firewalld\" ;;
       esac
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.1.2'
  tag cis_number:            '4.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  # network_firewall axis (#4): under cloud_sg/both the single ingress-governing utility
  # is the AWS security group — assert its default-deny posture (positive evidence
  # replacing the host-front-end attestation). host_nftables keeps the attestation.
  if fw_cloud?
    fw = firewall_posture
    sg = aws_security_group_posture
    if sg.available?
      impact 0.5
      describe sg do
        it { should be_default_deny }
      end
    else
      impact 0.5
      describe 'SG ingress posture (live read unavailable)' do
        skip "network_firewall=#{fw} but SG posture could not be read live (#{sg.error}); SAF attestation supplies evidence."
      end
    end
  else
    impact 0.5
    describe 'single firewall utility in use (4.1.2)' do
      skip 'operational: the firewall front-end (firewalld vs standalone nftables vs iptables) is a consumer architecture decision; §4.2 (firewalld) and §4.3 (nftables) are mutually-exclusive and each guarded N/A on the non-chosen path.'
    end
  end
end