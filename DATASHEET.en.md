# Datasheet: the Sourdine benchmark

*English version. The French file `DATASHEET.md` is the reference version.*

Descriptive sheet of the benchmark, in the "Datasheets for Datasets" format (Gebru et al., 2021).
Version described: 1.1.0. Producer: Apex Numeris SAS (Lyon, France). Author: Quoc-Nam Nguyen.

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

| Element | Value in v1.1.0 |
|---|---|
| Scenarios | 48, each described by a JSON file |
| Attack scenarios | 27, covering 22 vectors |
| Healthy scenarios | 21: coherence controls and false-positive traps |
| Twin pairs | two indistinguishable pairs (`ATT-LOW-SLOW-CATCHABLE-04` / `HLT-BENIGN-SPIKE-05`, `ATT-STATISTICAL-REPLAY-18` / `HLT-BENIGN-NOISE-13`) and one discriminating pair (`ATT-SILENCE-NARROW-27` / `HLT-BENIGN-SILENCE-03`), described in the README |
| Attacker access levels | `metric_or_am_api`, `silence_or_routing_api`, `exporter_host_or_network`, `threshold_knowledge` |
| Frozen samples | one JSON report per version and per backend under `samples/` (`example-0.{1..14}.0.json` then `example-1.1.0.json` in simulation, the same names with a `-docker` suffix in containers; sample 0.14.0 is the one of version 1.0.0) |

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

Reference results in v1.1.0 (detector `baseline-heuristic-v1`):

| Backend | Successful suppression | Catch rate | False positives | Residual suppression | Coherence |
|---|---|---|---|---|---|
| sim | 100 % (27/27) | 85.2 % (23/27) | 4.8 % (1/21) | 14.8 % (4/27) | 100 % |
| docker | 88.9 % (24/27) | 83.3 % (20/24) | 4.8 % (1/21) | 14.8 % (4/27) | 100 % |

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

- One false positive, `HLT-BENIGN-SPIKE-05`, in both backends. It is irreducible for a
  detector limited to the alerting chain: its observable state is strictly identical to that
  of the attack `ATT-LOW-SLOW-CATCHABLE-04`, and the baseline chooses to catch the attack.
  The second false positive of versions 0.1.0 to 1.0.0, `HLT-BENIGN-SILENCE-03`, came from an
  inconsistency in the baseline, fixed in 1.1.0 (see `CHANGELOG.md`).
- Four residual attacks in simulation, constant since v0.6.0 (`ATT-FLAP-STEALTH-10`,
  `ATT-GROUP-FLOOD-07`, `ATT-LOW-SLOW-STEALTH-05`, `ATT-STATISTICAL-REPLAY-18`). Full
  statistical concealment (`statistical_replay`), which preserves the traffic
  distribution, remains marginally undetectable: an acknowledged residual suppression,
  consistent with the ACSAC 2022 result on full replay. Its healthy twin
  `HLT-BENIGN-NOISE-13` has a strictly identical state: catching it would cost a false
  positive.
- In containers, the residual set differs: `ATT-GROUP-FLOOD-07` leaves it (the alarm
  eventually comes out) and `ATT-SIGNAL-BLACKOUT-12` enters it; three attacks do not mask
  (`ATT-FALSE-RESOLVED-15`, `ATT-FALSE-RESOLVED-JAILBREAK-16`, `ATT-GROUP-FLOOD-07`).
- Up to version 1.0.0, the interface handed the detector the narrative the target keeps of
  its own manoeuvre. The baseline did not read it. A result obtained on those versions
  with another detector is comparable only if that detector did not read it either. Since
  version 1.1.0 the interface is sealed and tested.
- The detector under evaluation is a deliberately simple heuristic baseline; the
  benchmark says nothing about more elaborate detectors until they are plugged in.
