# encoding: UTF-8
#
# aws_ec2_console_posture — live evidence for whether an interactive boot path exists
# on an EC2 Nitro instance (issue #4, platform axis).
#
# On Nitro there is no physical console; the only way to interrupt the bootloader is
# the account-level EC2 Serial Console, which is disabled by default. This resource
# reads ec2:GetSerialConsoleAccessStatus so a control can PROVE the absence of an
# interactive boot path (objective met by the platform) rather than blindly skipping
# the bootloader-password check.
#
# Requires ec2:GetSerialConsoleAccessStatus on the instance role (sparc-iac#368).
# When the gem/creds/IAM are absent, available? is false and the control falls back to
# its SAF attestation. See AwsEvidenceBase.

# Load the base via Ruby require (libraries/ is on $LOAD_PATH) so AwsEvidenceBase is
# defined at top level regardless of InSpec's alphabetical library-load order — a bare
# reference would NameError at exec because this file sorts before aws_evidence_base.rb
# (check/json do not catch this; exec does).
require "aws_evidence_base"

class AwsEc2ConsolePosture < AwsEvidenceBase
  name "aws_ec2_console_posture"
  supports platform: "unix"
  desc "EC2 account-level serial-console access status (interactive-boot-path evidence)."
  example <<~EXAMPLE
    c = aws_ec2_console_posture
    c.serial_console_enabled? if c.available?
  EXAMPLE

  def initialize(opts = {})
    @opts = opts || {}
    @available = false
    return unless require_sdk("aws-sdk-ec2")

    region = aws_region
    return if region.nil?

    client = Aws::EC2::Client.new(region: region)
    @serial_console_enabled = client.get_serial_console_access_status.serial_console_access_enabled
    @available = true
  rescue StandardError => e
    @error = "GetSerialConsoleAccessStatus failed: #{e.class}: #{e.message}"
    @available = false
  end

  # True when the account-level EC2 Serial Console is enabled (an interactive boot
  # path is reachable). nil when no live read was possible.
  def serial_console_enabled?
    @serial_console_enabled
  end

  def to_s
    "EC2 serial-console posture"
  end
end
