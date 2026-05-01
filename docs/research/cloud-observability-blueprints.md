# Cloud observability blueprints — is OTel-only enough?

**Status:** TODO — week 1 spike, ~1 day.

## Question being answered

Each major cloud now publishes an opinionated observability blueprint / reference architecture (Google's just released; AWS has CloudWatch + Application Signals; Azure has Monitor + Application Insights). Our position in `000-architecture.md` is "emit OTLP and stop." Does that hold, or do these blueprints expect resource attributes, semantic conventions, correlation IDs, or export shapes that pure OTLP doesn't satisfy out of the box?

The risk we're auditing: a regulated user on GCP / AWS / Azure adopts pgsleuth, points it at their managed observability stack, and finds the signal doesn't ingest cleanly without an adapter we didn't write.

## Approach

Per cloud, read the current blueprint end-to-end and answer the same set of questions. ~2 hours per cloud + 2 hours synthesis.

### Per platform

For each of: GCP (newly released blueprint), AWS (CloudWatch / Application Signals), Azure (Monitor / Application Insights)

- [ ] What's the canonical ingest path for a third-party agent? (OTLP endpoint, vendor SDK, log-based, metric-based?)
- [ ] Does the blueprint mandate specific OTel resource attributes (e.g. `cloud.provider`, `cloud.region`, `cloud.account.id`, `service.namespace`) beyond the OTel defaults?
- [ ] Does it expect a specific semantic-convention version, or extend the conventions with vendor-specific keys?
- [ ] How are traces, metrics, and logs correlated? Is a particular trace/span ID format required (W3C Trace Context vs vendor)?
- [ ] What does the blueprint say about DB-tier signals specifically? (Many blueprints lean app-tier; DB signals are often a footnote.)
- [ ] Is there a managed OTel collector offering, and does it impose constraints on what it'll forward?
- [ ] Cost shape — per-signal, per-GB, per-attribute-cardinality?
- [ ] Sample minimal payload that the blueprint considers "well-formed."

## Verdict per platform

| Platform | OTel suffices | OTel + attribute mapping | First-class exporter needed | Notes |
|---|---|---|---|---|
| GCP (new blueprint) | TBD | TBD | TBD | |
| AWS (CloudWatch / App Signals) | TBD | TBD | TBD | |
| Azure (Monitor / App Insights) | TBD | TBD | TBD | |

## Decision we owe the architecture

Pick one for v1.0:

- **(a) OTel suffices.** Document the assumption; ship as-is. Cheapest.
- **(b) OTel + a thin per-cloud attribute-mapping layer in `pgsleuth-otel`.** Acceptable tax.
- **(c) First-class exporters per cloud.** Real surface-area cost — only justified if (a) and (b) leave a meaningful share of users unable to ingest.

## What this changes in the architecture

TBD — fill in based on findings. Likely candidates:

- A small `cloud_profile` config knob on the agent (`gcp` | `aws` | `azure` | `none`) that toggles the attribute-mapping layer.
- Whether `pgsleuth-otel` stays a single crate or grows per-cloud submodules.
- Whether the v0.2 launch demo should pick *one* cloud's blueprint to be a first-class citizen, or stay cloud-agnostic.

## References

### GCP — Cloud Observability + Agent Observability (Next '26)

- [Google Cloud Next '26 wrap-up — Agent Observability + agentic blueprint announcement](https://cloud.google.com/blog/topics/google-cloud-next/google-cloud-next-2026-wrap-up)
- [Google Cloud Observability documentation (Stackdriver)](https://docs.cloud.google.com/stackdriver/docs/observability)
- [Cloud Observability release notes](https://docs.cloud.google.com/stackdriver/docs/release-notes)
- [GCP Architecture Center — release notes](https://docs.cloud.google.com/architecture/release-notes)

### AWS — CloudWatch + Application Signals

- [Amazon CloudWatch — OpenTelemetry sections](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-OpenTelemetry-Sections.html)
- [CloudWatch Application Signals overview](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Monitoring-Sections.html)
- [Application Signals OpenTelemetry compatibility](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-compatibility.html)
- [Metrics collected by Application Signals](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AppSignals-MetricsCollected.html)
- [Announcement: native OTLP metrics in CloudWatch (April 2026, public preview)](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-cloudwatch-opentelemetry-metrics/)

### Azure — Monitor + Application Insights

- [OpenTelemetry on Azure (Application Insights)](https://learn.microsoft.com/en-us/azure/azure-monitor/app/opentelemetry)
- [Configuring OpenTelemetry in Application Insights](https://learn.microsoft.com/en-us/azure/azure-monitor/app/opentelemetry-configuration)
- [Azure SDK OpenTelemetry conventions](https://github.com/Azure/azure-sdk/blob/main/docs/observability/opentelemetry-conventions.md)
- [OpenTelemetry semantic conventions for Azure resources](https://opentelemetry.io/docs/specs/semconv/azure/)

### Cross-cutting

- [OpenTelemetry semantic conventions spec (current)](https://opentelemetry.io/docs/specs/semconv/)
- [OpenTelemetry semantic conventions — concept page](https://opentelemetry.io/docs/concepts/semantic-conventions/)
- [OpenTelemetry DB semantic conventions](https://opentelemetry.io/docs/specs/semconv/database/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)

## Notes / scratch
