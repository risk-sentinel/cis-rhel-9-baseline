# encoding: UTF-8
#
# AwsEvidenceBase — base for the posture cloud-evidence resources.
#
# Each concrete resource extends this, lazily requires its aws-sdk-* gem, and
# self-initializes a client from the instance-role credentials. This is deliberately
# NOT inspec-aws: a host scan runs `-t local://`, which has no `aws://` train
# transport, so inspec-aws resources cannot run inside it. Instead we use the AWS SDK
# directly, in-process, relying on the SDK default credential chain (the EC2 instance
# profile via IMDS).
#
# Deployment assumption: the scan runs ON the target instance (a self-hosted runner /
# honeypot `-t local://` model), so the in-process SDK sees the host's instance role
# and region. This is the supported model for the cloud-evidence branches.
#
# Fail-soft contract: if the gem is absent, we're not on EC2, credentials don't
# resolve, or the API errors, `available?` returns false and `error` carries why — the
# routed control then falls back to its SAF attestation (skip-with-rationale). The base
# is abstract: it declares no `name`, so it is never registered as a usable resource.

class AwsEvidenceBase < Inspec.resource(1)
  # Concrete subclasses set their own `name`. Abstract base => intentionally unnamed.

  # True only when a live read succeeded end-to-end. Subclasses set @available.
  def available?
    @available == true
  end

  # Human-readable reason a live read was not possible (nil when available?).
  attr_reader :error

  protected

  # Lazily require an aws-sdk gem. Records + returns false on LoadError so a consumer
  # running stock cinc without the SDK gems degrades to the SAF fallback rather than
  # crashing the control load.
  def require_sdk(gem_name)
    require gem_name
    true
  rescue LoadError => e
    @error = "aws-sdk gem '#{gem_name}' unavailable: #{e.message}"
    false
  end

  # Region resolved from the environment, else IMDSv2 on the target host. Returns nil
  # (recorded in @error) when neither is available.
  def aws_region
    env = ENV["AWS_REGION"] || ENV["AWS_DEFAULT_REGION"]
    return env unless env.to_s.empty?
    r = imds("/latest/meta-data/placement/region")
    @error ||= "could not resolve AWS region (not on EC2 / IMDS unreachable)" if r.to_s.empty?
    r.to_s.empty? ? nil : r
  end

  def instance_id
    id = imds("/latest/meta-data/instance-id")
    id.to_s.empty? ? nil : id
  end

  private

  # IMDSv2 fetch via the target host (inspec.command runs on the scan target, so this
  # respects the transport — for `-t local://` that is the instance itself).
  def imds(path)
    token = inspec.command(
      'curl -s -X PUT "http://169.254.169.254/latest/api/token" ' \
      '-H "X-aws-ec2-metadata-token-ttl-seconds: 60" --max-time 2'
    ).stdout.to_s.strip
    return "" if token.empty?
    # `path` is a full IMDS path from root (e.g. /latest/meta-data/instance-id,
    # /latest/dynamic/instance-identity/document) — do NOT prepend a prefix here, or it
    # double-prefixes to /latest/meta-data/latest/... and 404s.
    inspec.command(
      %(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: #{token}" ) +
      %(http://169.254.169.254#{path})
    ).stdout.to_s.strip
  rescue StandardError => e
    @error ||= "IMDS lookup failed: #{e.message}"
    ""
  end
end
