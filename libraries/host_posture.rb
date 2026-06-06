# encoding: UTF-8
#
# host_posture — host-visible signals used to auto-resolve deployment-posture axes
# (issue #4, posture-aware evidence routing).
#
# Pure host reads only (DMI / service state / nftables). No AWS API calls, no inputs.
# Every probe is fail-soft: a missing file / absent service / unprivileged read
# resolves to a conservative `false` (or "") so auto-detection never errors a control
# and never silently relaxes the strict path.

class HostPosture < Inspec.resource(1)
  name "host_posture"
  supports platform: "unix"
  desc "Host-visible signals for posture auto-detection (issue #4)."
  example <<~EXAMPLE
    describe host_posture do
      it { should be_aws_nitro }
    end
  EXAMPLE

  # True on AWS Nitro / EC2 — the SMBIOS system/board vendor is "Amazon EC2".
  def aws_nitro?
    vendor = read_dmi("sys_vendor") + read_dmi("board_vendor") + read_dmi("bios_vendor")
    vendor.include?("Amazon EC2") || vendor.include?("Amazon")
  end

  def firewalld_running?
    inspec.service("firewalld").running?
  rescue StandardError
    false
  end

  # A populated ruleset (at least one `table` line) means nftables is actively filtering.
  def nftables_active?
    inspec.command("nft list ruleset 2>/dev/null").stdout.to_s.match?(/^\s*table\s/)
  rescue StandardError
    false
  end

  def host_firewall_active?
    firewalld_running? || nftables_active?
  end

  def to_s
    "Host posture signals"
  end

  private

  def read_dmi(key)
    f = inspec.file("/sys/class/dmi/id/#{key}")
    f.exist? ? f.content.to_s : ""
  rescue StandardError
    ""
  end
end
