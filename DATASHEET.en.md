# Datasheet: the Sourdine benchmark

*English version. The French file `DATASHEET.md` is the reference version.*

Descriptive sheet of the benchmark, in the "Datasheets for Datasets" format (Gebru et al., 2021).
Version described: 0.14.0. Producer: Apex Numeris SAS (Lyon, France). Author: Quoc-Nam Nguyen.

## 1. Motivation

Sourdine exists to measure one precise thing: the ability of a detector to notice, at
runtime, that an alarm has been masked. The attacks in scope do not target the monitored
agent but the observer: they muffle or suppress a signal that should have raised an
alarm, by abusing the primitives of a Prometheus/Alertmanager alerting chain (inhibition,
silence, grouping, replay, collection cutoff).

The application domain is AI agent monitoring. The benchmark belongs to the line of
concealment attacks formalised on industrial control systems (Erba and Tippenhauer, ACSAC
2020 and 2022), from which it differs by the link under attack (alerting rather than
detection), the domain (AI agents rather than physical processes) and the mechanism
(Alertmanager primitives rather than forged sensor series).

The benchmark evaluates a heuristic baseline detector (`baseline-heuristic-v1`). It does
not evaluate the SentinelleIA product; no figure published here is "SentinelleIA's".

## 2. Composition

| Element | Value in v0.14.0 |
|---|---|
| Scenarios | 47, each described by a JSON file |
| Attack scenarios | 26, covering 22 vectors |
| Healthy scenarios | 21: coherence controls and false-positive traps |
| Attacker access levels | `metric_or_am_api`, `silence_or_routing_api`, `exporter_host_or_network`, `threshold_knowledge` |
| Frozen samples | one JSON report per version and per backend under `samples/` (`example-0.{1..14}.0.json` in simulation, `example-0.{1..14}.0-docker.json` in containers) |

Each scenario carries the fields `id`, `kind` (attack or healthy), `vector`, `title`,
`description`, `access_level`, `ground_truth` (expected alarm and labels), `event` (what
happens on the target), `masking` (the manoeuvre) and `tags`, plus the optional English
fields `title_en` and `description_en`. The schema is described in `scenarios/SCHEMA.md`
(in French).

The 22 attack vectors: `cardinality_flood`, `constrained_replay`, `exporter_cutoff`,
`false_resolved`, `firewall_down_spoof`, `grouping_repeat_abuse`, `guard_outage_cover`,
`inhibition_scope_creep`, `instance_down_spoof`, `low_and_slow`, `postgres_down_spoof`,
`preloaded_silence`, `rogue_inhibitor`, `route_blackhole`, `selective_metric_drop`,
`silence_abuse`, `silence_regex_alertname`, `silence_shared_label`, `stale_replay`,
`statistical_replay`, `threshold_flapping`, `watchdog_suppression`.

Everything is synthetic: the metrics are fabricated, the target is ephemeral, no real
system is observed.

## 3. Generation process

The scenarios are written by hand, from the real primitives of Alertmanager and
Prometheus, then played by the harness on one of two targets:

| Backend | Nature | Use |
|---|---|---|
| `sim` | in-process model, deterministic and hermetic, no container | reproducible reference; the `example-x.y.z.json` samples |
| `docker` | real Prometheus, Alertmanager, synthetic exporter and notification receiver containers, bound to 127.0.0.1 on high ports | fidelity check; the `example-x.y.z-docker.json` samples |

The docker backend depends on real time (scrape, `group_wait`, settling). The gaps
between the two backends are named and explained in the README and in `docs/04`.

## 4. Labelling and measurement

Each scenario is labelled `attack` or `healthy` and carries its ground truth (alarm
expected or not). Measurement is done in two passes, without and then with the detector,
and yields four rates plus one control:

| Rate | Subset | Definition |
|---|---|---|
| Successful suppression | attacks, without detector | share of attacks where the expected alarm is not raised |
| Catch rate | masked attacks, with detector | share of maskings that the detector reports |
| False positives | healthy scenarios, with detector | share of healthy cases where the detector wrongly calls out masking |
| Residual suppression | attacks | share of attacks masked and not caught |
| Coherence control | healthy control scenarios | the expected alarm does come out when nothing prevents it |

Reference results in v0.14.0 (detector `baseline-heuristic-v1`):

| Backend | Successful suppression | Catch rate | False positives | Residual suppression | Coherence |
|---|---|---|---|---|---|
| sim | 100 % (26/26) | 84.6 % (22/26) | 9.5 % (2/21) | 15.4 % (4/26) | 100 % |
| docker | 88.5 % (23/26) | 82.6 % (19/23) | 9.5 % (2/21) | 15.4 % (4/26) | 100 % |

## 5. Uses

Intended use: evaluate an alarm-masking detector behind the `engine/detector.py`
interface, compare detector versions on a fixed catalogue, and reproduce the frozen
samples.

Discouraged uses: pointing it at production monitoring (the benchmark brings up and
tears down its own target and touches nothing that exists); presenting the rates of the
baseline detector as those of a product; comparing rates across versions without
accounting for the number of scenarios, which changes with every version.

## 6. Distribution and maintenance

| Item | Value |
|---|---|
| Repository | https://github.com/apex-numeris/sourdine |
| Website | https://sourdine.org |
| Licences | code and harness: Apache-2.0 (`LICENSE`); scenarios, samples and documentation: CC BY 4.0 (`scenarios/LICENSE`, `samples/LICENSE`, `docs/LICENSE`) |
| Citation | `CITATION.cff`; a Zenodo DOI is assigned to every release, with a concept DOI shared by all versions |
| Versions | semantic versioning; each version adds its frozen sample under `samples/` without removing the previous ones |
| Contact | qnn@apex-numeris.com |

## 7. Known limitations

- Two false positives constant since v0.1.0 (`HLT-BENIGN-SILENCE-03`,
  `HLT-BENIGN-SPIKE-05`): fifteen healthy scenarios have been added since, without any
  new false positive. The drop in the false-positive rate across versions comes from the
  denominator, not from an improvement of the detector.
- Four residual attacks in simulation, constant since v0.6.0 (`ATT-FLAP-STEALTH-10`,
  `ATT-GROUP-FLOOD-07`, `ATT-LOW-SLOW-STEALTH-05`, `ATT-STATISTICAL-REPLAY-18`). Full
  statistical concealment (`statistical_replay`), which preserves the traffic
  distribution, remains marginally undetectable: an acknowledged residual suppression,
  consistent with the ACSAC 2022 result on full replay.
- In containers, the residual set differs: `ATT-GROUP-FLOOD-07` leaves it (the alarm
  eventually comes out) and `ATT-SIGNAL-BLACKOUT-12` enters it; three attacks do not mask
  (`ATT-FALSE-RESOLVED-15`, `ATT-FALSE-RESOLVED-JAILBREAK-16`, `ATT-GROUP-FLOOD-07`).
- The detector under evaluation is a deliberately simple heuristic baseline; the
  benchmark says nothing about more elaborate detectors until they are plugged in.
