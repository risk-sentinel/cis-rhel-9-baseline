# encoding: UTF-8
#
# cloudwatch_log_ingestion — live evidence that logs are ACTUALLY landing in CloudWatch
# (issue #4, log_pipeline axis), not merely that the host is configured to ship them.
#
# Level-2 assurance: reads the host's stream via logs:DescribeLogStreams and reports
# whether the most recent ingestion is within a freshness window — proving events are
# being generated and ingested, recently, for this host. (Level 1 = group exists;
# Level 3 = content pattern; Level 4 = closed-loop probe — future opt-ins.)
#
# Requires logs:DescribeLogStreams on the instance role (sparc-iac#368). A missing gem /
# creds / IAM / log group => available?=false + error, and the control falls back to its
# SAF attestation. See AwsEvidenceBase.

# Load the base via Ruby require so AwsEvidenceBase resolves regardless of InSpec's
# alphabetical library-load order (the bare reference NameErrors at exec).
require "aws_evidence_base"

class CloudwatchLogIngestion < AwsEvidenceBase
  name "cloudwatch_log_ingestion"
  supports platform: "unix"
  desc "Live CloudWatch Logs ingestion evidence for the host's audit/journald stream."
  example <<~EXAMPLE
    describe cloudwatch_log_ingestion(group: input('cloudwatch_audit_log_group')) do
      it { should be_ingesting_within(3600) }
    end
  EXAMPLE

  def initialize(opts = {})
    @opts      = opts || {}
    @available = false
    @log_group = (@opts[:group] || "").to_s
    if @log_group.empty?
      @error = "no cloudwatch_audit_log_group provided (cannot verify off-box ingestion)"
      return
    end
    return unless require_sdk("aws-sdk-cloudwatchlogs")

    region = aws_region
    return if region.nil?

    @stream = (@opts[:stream] || "").to_s
    @stream = instance_id.to_s if @stream.empty?

    client = Aws::CloudWatchLogs::Client.new(region: region)
    # NOTE: the API forbids combining log_stream_name_prefix with order_by=LastEventTime,
    # so we prefix-match this host's stream when we know it, else take the most recently
    # active stream in the group.
    resp =
      if @stream.empty?
        client.describe_log_streams(log_group_name: @log_group, order_by: "LastEventTime", descending: true, limit: 1)
      else
        client.describe_log_streams(log_group_name: @log_group, log_stream_name_prefix: @stream, limit: 1)
      end

    s = resp.log_streams.first
    if s.nil?
      @error = "no log stream found in #{@log_group}#{@stream.empty? ? '' : " for prefix #{@stream}"}"
      return
    end
    @stream_name    = s.log_stream_name
    @last_ingestion = s.last_ingestion_time || s.last_event_timestamp # epoch millis
    @available      = true
  rescue StandardError => e
    @error     = "CloudWatch ingestion lookup failed: #{e.class}: #{e.message}"
    @available = false
  end

  attr_reader :log_group, :stream_name, :last_ingestion

  # Seconds since the most recent ingestion (nil if unknown).
  def last_ingestion_age
    return nil if @last_ingestion.nil?
    Time.now.to_i - (@last_ingestion / 1000)
  end

  # True when the most recent ingestion is within lag_seconds — the Level-2 proof that
  # the off-box pipeline is live for this host. Drives `should be_ingesting_within(n)`.
  def ingesting_within?(lag_seconds)
    age = last_ingestion_age
    !age.nil? && age >= 0 && age <= lag_seconds.to_i
  end

  def to_s
    "CloudWatch ingestion (#{@log_group}#{@stream_name ? "/#{@stream_name}" : ''})"
  end
end
