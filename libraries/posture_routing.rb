# encoding: UTF-8
#
# PostureRouting — maps a declared posture axis value (or 'auto') to a concrete
# branch a control routes its assertion on (issue #4).
#
# Included into every control via ::Inspec::Rule.include. The leading `::` is
# required under InSpec 7: a bare `Inspec::Rule.include` raises an
# uninitialized-constant NameError at exec (check/json pass, exec fails to load).
#
# Fail-closed contract: 'auto' only ever resolves toward the strict/host branch.
# Routing a control to a cloud / off-box / attested branch is always an explicit
# consumer declaration — auto-detection never relaxes the strict path on its own,
# so a misconfigured or under-declared scan over-reports rather than silently passes.

module PostureRouting
  # platform_class: 'auto' is safe to resolve from DMI — cloud_nitro is a *correct*
  # classification, not a relaxation (its branch must still positively prove the
  # absence of an interactive boot path; it is not a free skip).
  def resolve_platform_class(declared)
    d = declared.to_s
    return d unless d == "auto"
    host_posture.aws_nitro? ? "cloud_nitro" : "baremetal"
  end

  # The remaining axes refuse to leave the strict/host branch on 'auto': the host
  # cannot positively prove a cloud SG, an off-box log destination, or a federated
  # access boundary, so 'auto' demands the host path and only an explicit declaration
  # routes to the compensating-evidence branch.
  def resolve_firewall(declared)
    d = declared.to_s
    d == "auto" ? "host_nftables" : d
  end

  def resolve_log_pipeline(declared)
    d = declared.to_s
    d == "auto" ? "onbox" : d
  end

  def resolve_host_lifecycle(declared)
    d = declared.to_s
    d == "auto" ? "persistent" : d
  end

  def resolve_access_model(declared)
    d = declared.to_s
    d == "auto" ? "interactive" : d
  end

  # host_lifecycle axis (#4) — dynamic §1.1.2 filesystem-isolation routing keyed off the
  # ACTUAL mount state, not just the flag. True => this path's separate-mount isolation
  # is Not Applicable: it is folded into root AND the consumer declared an ephemeral
  # lifecycle. In every other case the strict assertion runs:
  #   - distinct mount (real partition / EBS volume / tmpfs) => strict in BOTH postures,
  #     so tmpfs /tmp & /dev/shm still get their nodev/nosuid/noexec asserted on ephemeral;
  #   - folded into root + persistent => strict assertion FAILS (the partition should exist).
  # The control keeps its `describe` blocks inline (static-visible to `check`) and selects
  # a literal impact per branch (avoids the InSpec-7 impact-by-method-call AST crash).
  def fs_na?(path)
    !mount(path).mounted? && resolve_host_lifecycle(input("host_lifecycle")) == "ephemeral"
  end

  # log_pipeline axis (#4): true when logs are shipped off-box (offbox or both), so a
  # control should positively assert durable CloudWatch ingestion rather than (or in
  # addition to) the on-box mechanism.
  def log_offbox?
    %w[offbox both].include?(resolve_log_pipeline(input("log_pipeline")))
  end

  # Builds the CloudWatch ingestion evidence resource from the declared inputs.
  def cw_ingestion
    cloudwatch_log_ingestion(
      group:  input("cloudwatch_audit_log_group"),
      stream: input("cloudwatch_audit_stream"),
    )
  end

  # network_firewall axis (#4).
  def firewall_posture
    resolve_firewall(input("network_firewall"))
  end

  # true when AWS security groups are (one of) the ingress-enforcement points.
  def fw_cloud?
    %w[cloud_sg both].include?(firewall_posture)
  end

  # true when defense-in-depth is explicitly requested (assert host AND SG).
  def fw_both?
    firewall_posture == "both"
  end
end

::Inspec::Rule.include(PostureRouting)
