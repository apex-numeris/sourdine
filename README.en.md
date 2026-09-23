# Sourdine: alarm-masking attack benchmark

*English version. The French file `README.md` is the reference version; in case of discrepancy, the French text prevails.*

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22900756.svg)](https://doi.org/10.5281/zenodo.22900756) [![tests](https://github.com/apex-numeris/sourdine/actions/workflows/tests.yml/badge.svg)](https://github.com/apex-numeris/sourdine/actions/workflows/tests.yml) [![docker-weekly](https://github.com/apex-numeris/sourdine/actions/workflows/docker-weekly.yml/badge.svg)](https://github.com/apex-numeris/sourdine/actions/workflows/docker-weekly.yml)

Sourdine measures how well an alerting chain resists **alarm masking**: attacks that
do not target an agent but **the observer**, by suppressing or muffling a signal that
should have raised an alarm.

The benchmark is **self-contained and disposable**: it brings up its **own** ephemeral
target (Prometheus + Alertmanager in isolated containers, or an in-process model), plays
a catalogue of labelled scenarios, and computes metrics. It never targets production
monitoring and never modifies any existing configuration.

> **The benchmark evaluates a detection _baseline_, not the SentinelleIA product.**
> No figure is "SentinelleIA's" until the real detector is plugged in behind the same
> interface (see "Plugging in the real detector").

---

## Lineage and positioning

Sourdine belongs to the line of **concealment / evasion attacks** formalised on
industrial control systems by Erba and Tippenhauer (ACSAC 2020, repository
`scy-phy/ICS-Evasion-Attacks`; ACSAC 2022, repository
`scy-phy/ICS_Generic_Concealment_Attacks`), and to the RICSS 2024 datasets derived from
DHALSIM and HAI. Those works attack the **detection** link: they evade an anomaly
detector (a learner watching a physical process) by **forging sensor time series**.

Sourdine attacks a **different link, alerting**, by abusing Alertmanager primitives
(inhibition, silence, grouping, collection cutoff), in the domain of **AI agent
monitoring** (not industrial processes). The positioning rests on three axes: the
**link under attack** (alerting versus detection), the **domain** (AI agents versus ICS)
and the **mechanism** (Alertmanager primitives versus forged sensor series). Sourdine
explicitly places itself in that lineage rather than claiming untouched ground.

---

## Detailed documentation

Under [`docs/`](docs/README.md) (in French): requirements, functional and technical
architecture, sequence diagrams, specifications, user and administrator manuals, and the
deployment procedure for a public results site.

## Why this is not a mere "attack success rate"

For an injection or an exfiltration, you attack a target and measure whether the attack
succeeds. For masking, **the attack targets the reporting**: each scenario must therefore
model **two objects**, *the event that should have raised an alarm* and *the manoeuvre
that makes that report disappear*, and measure in **two passes**:

1. **without a masking detector**: did the expected alarm come out?
2. **with the detector**: does the detector call out the masking?

### The four rates, plus the coherence control

| Rate | Subset | Definition | What it proves |
|---|---|---|---|
| **Successful suppression** | attacks, **without** detector | share of attacks where the expected alarm is not raised | the customer-side danger when nothing protects |
| **Catch rate** | attacks, **with** detector | among the alarms actually masked, share reported as masking | the value of the product |
| **False positives** | healthy scenarios, with detector | share of healthy cases where the detector wrongly calls out masking | the operational cost |
| **Residual suppression** | attacks, with detector | share of attacks where the masking goes unnoticed despite the detector | honesty (the mirror of the catch rate) |
| **Coherence control** | serious healthy cases | share of cases where the alarm does come out when nothing masks it (about 100 %) | that the target is not broken |

**Scoring rule**: the status is read **on the pass without detector**. An alarm that
disappears without a detector is a successful masking, even if the detector catches it
afterwards.

---

## Architecture

Three components plus a report.

1. **Ephemeral target**: Prometheus + Alertmanager in containers, loaded with a set of
   alerting and inhibition rules that is *representative but rebuilt* (never copied from
   production), plus a controllable synthetic exporter and a webhook sink that observes the
   notifications actually delivered. Everything is brought up, then torn down, by the
   benchmark. An in-process **sim** target offers the same semantics, deterministically
   and hermetically.
2. **Runner** (`engine/runner.py`): for each scenario, sets up the state, injects the
   event, applies the vector, observes without detector (pass 1), submits state plus trace
   to the detector (pass 2), records.
3. **Detector** (`engine/detector.py`): behind a stable interface (`MaskingDetector`).
   The benchmark ships `BaselineDetector` (heuristic, deliberately imperfect). The real
   detector will be measured against the same protocol.

### Course of a scenario

```
ground truth (alarm expected?)
  -> set up the initial state (representative rules + inhibition)
  -> inject the event that must raise the alarm
  -> apply the masking vector
  -> observe the alert state                 (pass 1, WITHOUT detector)  -> raw result
  -> hand over monitoring state + trace      (pass 2)                    -> verdict
  -> record (ground truth, raw result, verdict)
=> after all scenarios: compute the 4 rates + coherence + breakdown
```

The detector is **blind to the scenario**: it only receives observable monitoring data
(alerts, silences, metric history, collection gaps), never the vector nor the ground truth.

---

## Scenario catalogue

Each vector declares its **attacker access assumption** (the report breaks the rates
down by access level, which is what makes the benchmark defensible).

| Vector | Real alarm masked | Assumed attacker access |
|---|---|---|
| `FirewallDown` spoof | HighAttackRate, CriticalAttacksDetected, JailbreakSurge | metric injection / Alertmanager API |
| `InstanceDown` spoof | every alert of the instance | same |
| `PostgreSQLDown` spoof | every PostgreSQL alert | same |
| Low-and-slow below the threshold | the rate alerts | no monitoring access, knowledge of the thresholds |
| Threshold flapping (`for:` reset) | the rate alerts | knowledge of the thresholds |
| Silence / grouping abuse | a real alert killed or drowned | silences API / routing configuration |
| Silence on a shared label (job/service) | a whole class of alerts | silences API |
| Silence with a regex `alertname` (`~.+`) | a whole class of alerts (fake targeting) | silences API |
| Exporter / scrape cutoff | the alert that never leaves | exporter host / network |
| Selective signal blackout (instance UP) | the alert that never leaves | exporter host / network |
| False all-clear (forced `resolved`, MITRE T1562.011) | the security alert resolved while the threat persists | metric injection / Alertmanager API |
| Metric replay / freeze (ACSAC 2022 concealment) | the attack, frozen at a plateau after a crossing, no longer re-alerts | exporter host / metric ingestion |
| Statistical concealment (distribution-preserving, ACSAC 2022), **residual** | the attack diluted into realistic noise below the threshold (marginally undetectable) | exporter host / metric ingestion |
| Constrained replay (replay on a subset, ACSAC 2022) | the attack masked on `attack_rate` but not on `blocked_rate` (spatial incoherence) | exporter host / metric ingestion |
| Route black hole (indicator blocking, MITRE T1562.006) | the security alert active but rerouted to a black-hole receiver (notification swallowed), with neither silence nor inhibitor | Alertmanager API / routing configuration |
| Watchdog suppression (dead man's switch, MITRE T1562) | alerting chain disabled + attack signal blinded: nothing is observable, only the extinguished watchdog heartbeat gives it away | control plane / alerting chain infrastructure |
| Cardinality bomb (ingestion DoS, MITRE Impair Defenses) | flood of high-cardinality series, `sample_limit` exceeded, scrape rejected (`up`=0), real signal never ingested; the `scrape_samples` spike gives it away | metric ingestion |
| Rogue inhibition rule (MITRE T1562.001) | the attacker adds an inhibition rule whose source is NOT sanctioned and muffles the security class; configuration drift against the baseline | Alertmanager API / routing configuration |
| Induced guard outage (MITRE T1562.001) | the attacker **really** takes the firewall down, then attacks: the **sanctioned** inhibition `FirewallDown → security class` muffles the alert while working exactly as designed | firewall host / network |
| Inhibition scope creep (MITRE T1562.001) | the `equal` labels of a sanctioned rule are removed: a **real** outage on a harmless instance then muffles the security class of another instance | Alertmanager API / routing configuration |
| Preloaded silence (MITRE T1562.001) | a narrow, irreproachable silence is placed **during a quiet period**, long before the attack that later joins it: the form is perfect, only the **time offset** gives it away | silences API |
| **Healthy** (mandatory) | none | measure false positives + coherence |

The **healthy** scenarios include a serious case without attack (the alarm must come out)
and legitimate activities that *look like* a vector from afar (maintenance silence,
planned exporter restart, licit spike below the threshold): the detector must not call
out masking on them.

## Baseline detector: what it looks for

It does not look at the content of the attack: it looks for **suspicious silence** and
for manipulations of the alerting chain. Principle: *the dog that did not bark: the
abnormal absence of a signal is itself the signal.* One heuristic per family:

- **Isolated inhibiting source**: a `FirewallDown`/`InstanceDown`/`PostgreSQLDown`
  that appears **uncorroborated** (its target stays alive/high) and masks a real alert.
- **Low-and-slow**: sum integrated over a long window beyond a threshold, with no rate alert.
- **Threshold flapping**: repeated threshold crossings with no rate alert active (the `for:` is reset in a loop).
- **Silence abuse**: an over-scoped silence (broad instance matcher, **or no exact `alertname` matcher** (absent or regex `~.+`), sweeping a whole class of alerts), or a narrow silence placed during an activity rise.
- **Exporter cutoff**: a collection gap coinciding with high activity just before, the instance going down (`up` at 0).
- **Selective blackout**: an attack signal disappears after activity while the instance stays **UP** (no InstanceDown to give it away).
- **False all-clear** (`phantom_clear`): a rate signal stays **sustained above the threshold** (still hot at the last observed point) with no rate alert active, and neither inhibitor nor silence to explain it. Correlation between metric and alert (recommended for MITRE T1562.011): the alert was resolved/muffled *after* it should have fired: the dog silenced after it barked, as opposed to the vectors that prevent it from barking.
- **Replay / freeze** (`frozen_replay`): after a threshold **crossing** (real attack), the signal is **frozen** at a constant intermediate plateau (zero variance) without disappearing: the metric stays present and plausible, but its frozen dynamics give away the replay/stale (ACSAC 2022, temporal consistency). Distinct from low-and-slow (never above the threshold) and from the benign spike (which falls back to rest).
- **Spatial incoherence** (`spatial_incoherence`): `attack_rate` (reported attacks) and `blocked_rate` (blocked requests) are normally correlated; when the firewall **blocks massively** but **reports almost no attack**, two signals that should move together diverge, the signature of *constrained replay* (ACSAC 2022, spatial consistency). This is what marginal concealment, however careful, cannot get around if it masks only a subset of the signals.
- **Indicator blocking at routing** (`notification_blackhole`): a **security** alert is **active** and its threat **sustained above the threshold** (it should have notified), but its notification **never reached the receiver** (`route_muted`: rerouted to a black-hole receiver or muted at route level), **with neither** silence nor inhibitor to explain it. It is a fourth suppression lever, distinct from inhibition, silence and grouping (the wire is unplugged *after* firing, *before* the receiver); correlation between metric and delivery, recommended for MITRE T1562.006 ("detect the absence of reporting while activity is real"). The **discriminant is the class of the alert**: the non-delivery of an operational alert during a maintenance can be legitimate, that of a security alert during a sustained threat is not.
- **Dead man's switch** (`watchdog_gap`): the `watchdog` heartbeat, always emitted (`vector(1)`) as long as the alerting chain is alive, has **gone silent in a sustained way** (>= `WATCHDOG_MIN_SILENCE` ticks at the end of the window). *A monitoring system cannot reliably monitor its own failure*: when the chain (from Prometheus to delivery, through Alertmanager) is disabled, every alert falls silent without anything reporting it, except this heartbeat that stops, noticed by an **independent** watcher. It is the last line of defence (MITRE T1562 Impair Defenses): even an attacker who perfectly blinds the attack signal is given away by the switch. A **transient miss** (missed scrape) recovers and is tolerated; only a **sustained silence** counts, otherwise every jitter would be paid for (alert fatigue).
- **Cardinality bomb** (`cardinality_flood`): the number of scrape samples (`scrape_samples`) **explodes** beyond `CARDINALITY_FLOOD_THRESHOLD`. An attacker who injects a flood of high-cardinality series pushes Prometheus past its `sample_limit`, which **rejects the whole scrape**: `up` drops to 0 "as if the target had gone down" and the real signal is never ingested. The fake outage is **indistinguishable** from a real cutoff for absence heuristics; it is the **`scrape_samples` spike**, far beyond any legitimate growth (a deployment adds only a few dozen series), that sets the ingestion bomb apart, a denial of service of the monitoring for evasion purposes (MITRE Impair Defenses / T1499). Standard alert: `prometheus_target_scrapes_exceeded_sample_limit_total`.
- **Rogue inhibition rule** (`rogue_inhibitor`): a **security** alert is inhibited by an inhibition source that does **not** belong to the baseline's sanctioned set (`INHIBITOR_SOURCES`). The attacker added an inhibition rule whose source is a benign alert under their control, to muffle the security class (MITRE T1562.001 Disable or Modify Tools, alteration of the alerting configuration). It is **distinct from the spoofs** (which forge a *sanctioned* source and are caught by non-corroboration): here the source is *illegitimate*, so the inhibition heuristic, which only looks at sanctioned sources, does not even examine it. Detection by **configuration drift**. The discriminant combines **unsanctioned source AND security target**: an unsanctioned source inhibiting an *operational* alert (say, a database maintenance) remains legitimate.
- **Induced guard outage** (`guard_down_under_threat`): a **sanctioned and corroborated** inhibition source (`FirewallDown` with `fw_up` really at 0) inhibits a **security** alert while the threat is **real and sustained** above the threshold *during the outage*. The attacker forges nothing: they **really disable** the security control, then attack, and the noise-reduction rule ("do not cry overflow when the firewall is down") becomes their cover. It is the exact complement of **isolated inhibition**, on the same corroboration motif read backwards: there the source lies (uncorroborated outage = spoof), here it tells the truth, and that is what makes it invisible to corroboration. It is the documented motif of *EDR killers* (MITRE T1562.001: disable the control, then operate in the blind spot). The **discriminant is concomitance**, not the outage: a firewall maintenance is a routine operation; without this guard, each one would become a false positive.
- **Inhibition scope creep** (`inhibition_scope_creep`): a justified alert (its own signal above its own threshold) is inhibited by a **sanctioned** source, but **no active source of that name agrees with it on the rule's `equal` labels**: the inhibition crossed a boundary it had no right to cross. The Alertmanager documentation warns that if the `equal` labels are absent from both alerts, *the rule applies anyway*: removing them turns a targeted inhibition into a **global suppression**, and a real outage on a harmless instance is then enough to muffle the security class of another one. It is the fourth heuristic of the inhibition family, and the only one whose tell is neither the source's lie (`inhibitor_isolation`), nor its illegitimacy (`rogue_inhibitor`), nor the nature of the outage (`guard_down_under_threat`), but the **scope**. The discriminant is deliberately independent of the alert class: the healthy counterpart (a perfectly bounded inhibition, the normal noise-reduction mechanism) differs from it ONLY on that point.
- **Preloaded silence** (`silenced_under_threat`): a **security** alert is actually **muffled by a silence** while its threat is **real and sustained** above the threshold. The attacker placed the silence *during a quiet period*, long before striking: narrow, literal `alertname`, irreproachable scope: at creation time it is **indistinguishable from a planned maintenance**, which is exactly why silence abuse, which judges the **form** and the activity **at placement time**, can see nothing; `phantom_clear`, for its part, stands down as soon as a silence exists, taking it as a sufficient explanation. The whole manoeuvre rests on the **time offset** between placement and use. The tell is therefore neither the form nor the date, but the **observed effect**, which matches the recommended countermeasure: a suppression is re-verified **during** its window, not only at its opening. Discriminant = the **class** of the alert: silencing an operational alert during a maintenance is the most routine operations gesture there is.

These heuristics are **deliberately imperfect** so that false positives and residual
suppression are non-zero and credible. **Full statistical concealment**
(`statistical_replay`) is the emblematic example: by preserving the distribution of normal
traffic **and** the coherence of *all* signals, it breaks no verifiable consistency and
remains **undetectable** (see ACSAC 2022 on full replay), hence an acknowledged residual
suppression. Conversely, as soon as the concealment masks only a **subset** of the signals
(*constrained replay*), it breaks **spatial** consistency and becomes detectable again
(`spatial_incoherence`): this is exactly the ACSAC 2022 contrast between full and
constrained replay. The non-zero residual suppression honestly measures what remains out
of reach; the real detector will have to do better still.

---

## Running a campaign

No third-party Python dependency (stdlib, Python 3.10 or later).

```bash
# sim target (default): deterministic, hermetic, no container
python3 run_campaign.py

# docker target: real ephemeral containers (requires docker + compose v2)
scripts/target_up.sh          # optional: inspect the target by hand
python3 run_campaign.py --backend docker
scripts/target_down.sh        # the runner already tears the target down; this forces the purge
```

The JSON report is written under `reports/` (plus `reports/latest.json`, runtime,
git-ignored) and a readable summary is printed. Example runs are versioned (citable):
`samples/example-0.14.0.json` (latest) and its predecessors
(`example-0.{1..13}.0.json`), kept as history.

> **sim versus docker**: the **sim** target is the **deterministic reference**
> (reproducible rates). The **docker** target brings the fidelity of real
> Prometheus/Alertmanager; because it depends on real time (scrape, `group_wait`), the
> long-window vectors (low-and-slow, `repeat_interval`) need settling time and are less
> deterministic. The **detector is identical** in both cases.
>
> **Fidelity findings (docker run v0.14.0)**: surfaced by running the real target:
> (1) the real Alertmanager **refuses** a silence with a matcher that matches the empty
> string (`instance=~.*`, "silence everything" guardrail); the vector therefore uses
> `~.+`; (2) against a short `group_wait`, the **grouping flood** does not mask within the
> window (the first batch leaves with the real alert): docker scores it "not masked" where
> sim scores it masked; (3) the **selective blackout** (`selective_metric_drop`) is
> **caught in sim but not in docker**: a real Prometheus represents a removed metric by a
> series that stops, not by `None` gaps; (4) the **false all-clear** (`false_resolved`)
> **masks in sim but not in docker**: the resolved posted to the AM API does not hold
> against an active Prometheus rule, which re-asserts the alert (a defensive result);
> (5) the **replay/freeze** (`stale_replay`) **masks in both backends**, but its catch in
> docker depends on the visibility of the brief crossing spike (TIMING_SENSITIVE). Note:
> **statistical concealment** (`statistical_replay`) masks and stays **residual in both
> backends**; this is not a fidelity gap but a limit of the baseline (see "Baseline
> detector"). **Constrained replay** (`constrained_replay`), on the other hand, masks only
> a subset of the signals and is **caught by spatial consistency**
> (`spatial_incoherence`) in both backends, the ACSAC 2022 full-versus-constrained
> contrast. The **route black hole** (`route_blackhole`, MITRE T1562.006) masks
> **deterministically in both backends** (routing to the black-hole receiver does not
> depend on a time window) and is **caught by `notification_blackhole`**: a strong masker
> (STRONG), not a fidelity gap.
> **Watchdog suppression** (`watchdog_suppression`, MITRE T1562) also masks
> **deterministically in both backends** (the heartbeat set to 0 does not depend on timing)
> and is **caught by `watchdog_gap`**: strong masker (STRONG), no fidelity gap.
> The **cardinality bomb** (`cardinality_flood`, MITRE Impair Defenses / T1499) masks
> **deterministically in both backends** (high `scrape_samples` + `up`=0, explicit values)
> and is **caught by `cardinality_flood`**: strong masker (STRONG), no fidelity gap.
> The **rogue inhibition rule** (`rogue_inhibitor`, MITRE T1562.001) masks
> **deterministically in both backends** (baked rule with an unsanctioned source, applied
> preventively with confirmation and retry like the spoofs) and is **caught by
> `rogue_inhibitor`**: strong masker (STRONG), no fidelity gap.
> The **induced guard outage** (`guard_outage_cover`, MITRE T1562.001) is the only vector
> that **adds nothing to the target**: no rule, no label, no posted alert. It cuts `fw_up`;
> the `FirewallDown` rule fires by itself and the **sanctioned** inhibition
> `FirewallDown → security class` muffles the alert while working exactly as designed.
> The chain is taken **as it is**, which makes it a real hole rather than a benchmark
> artifact. Preventive masking (outage established and confirmed active before the fire):
> **deterministic in both backends**, **caught by `guard_down_under_threat`**, strong
> masker (STRONG), no fidelity gap.
> **Inhibition scope creep** (`inhibition_scope_creep`, MITRE T1562.001) relies on a rule
> stripped of its `equal`, **baked** into `alertmanager.yml` and **inert** as long as the
> decoy instance does not go down. The real Alertmanager then applies the inhibition
> **globally**, in line with the warning in its own documentation ("if all label names
> listed in `equal` are missing from both the source and target alerts, the inhibition
> rule will apply!"): this is the **real behaviour of the product**, not a benchmark
> convention. Preventive masking: **deterministic in both backends**, **caught by
> `inhibition_scope_creep`**, strong masker (STRONG), no fidelity gap.
> Docker totals: **88.5 / 82.6 / 9.5 / 15.4 / 100 %** (suppression / catch / FP /
> residual / coherence) versus sim **100 / 84.6 / 9.5 / 15.4 / 100 %**. Example:
> `samples/example-0.14.0-docker.json`. **Flapping** (including on `jailbreak_rate`)
> behaves as in sim.
>
> **Robustness of preventive maskings (v0.4.0 hardening).** Inhibition (spoofs) and
> silence are *deterministic by nature*, but their application by Alertmanager can lose a
> first-flush race: the alert is notified before the muting is applied. Under no load,
> `instance_down_spoof` and the `alertname=~.+` silence lost about one run in three. The
> docker target therefore establishes the masking **before** the event, **confirms its
> activation**, stabilises it (> 2× `group_interval`), then **retries** the scenario if the
> alert leaks (residual leak < 0.5 %). These vectors now mask reliably (validated by
> repetition: 8/8 after hardening, versus 2/3 before on the regex silence).

## Tests / non-regression

The **sim** run is deterministic: it serves as a non-regression guardrail.
`tests/test_sim_regression.py` replays a sim campaign and compares it with the frozen
sample `samples/example-0.14.0.json` (aggregate **and** every scenario; timestamps are
ignored). Stdlib `unittest`, no third-party dependency.

```bash
make test                       # non-regression of the sim run + determinism
```

The **docker** backend is non-deterministic (real time): `tests/test_docker_regression.py`
therefore does **not** check strict equality but verifies **invariants** (coherence at
100 %, deterministic maskers always masked and caught, coherence controls never flagged)
and **directional guardrails with tolerance** around `samples/example-0.14.0-docker.json`.
It brings up a real ephemeral target (about 6 to 18 minutes) and is therefore **not** part
of `make test`:

```bash
make test-docker                # LIVE non-regression of the docker backend (opt-in)
```

The logic of these checks, and its **proof by mutation**, does run inside `make test`
without docker.

An **intended** behaviour change is re-frozen with a deliberate gesture, diff in hand;
for the current version, the two samples:

```bash
python3 run_campaign.py --backend sim    --out samples/example-0.14.0.json --quiet
python3 run_campaign.py --backend docker --out samples/example-0.14.0-docker.json --quiet   # ~6-18 min
git diff samples/
```

(`make regen-sample` remains available but only re-freezes the historical example sample
`example-0.1.0.json`.)

Continuous integration (the repository's Actions tab) replays the sim run on every push,
on Python 3.10, 3.12 and 3.13, and runs the docker campaign every Monday morning.

## Output format

JSON with a **versioned schema** (`sourdine_report_version`), for citability and
comparison between runs:

- header: format version, benchmark version, timestamp, backend, detector;
- per scenario: id, vector, access level, ground truth, result without detector,
  verdict, timestamp;
- aggregate: the 4 rates, the coherence control, and the **breakdown by attacker access
  level**.

The scenario set (`scenarios/`) is an open artifact, separate from the runner.

## Plugging in the real detector (outside this repository)

Implement `engine/detector.py::MaskingDetector`:

```python
class SentinelleDetector(MaskingDetector):
    name = "sentinelleia-<version>"
    def detect(self, state, trace):
        # state: SupervisionState (alerts, silences, metric history)
        # trace: Trace (observable events)
        return Verdict(masking_suspected=..., scope=..., reason=..., heuristic=...)
```

then inject it into `run_campaign.py` in place of `BaselineDetector`. The benchmark
**does not import** the product; the real detector is measured against the same protocol,
and its results then replace the baseline's in the report.

## Adding a vector / a scenario

See `scenarios/SCHEMA.md` (in French). Drop a JSON file into `scenarios/{attacks,healthy}/`,
and for a new vector, add its interpretation in `engine/target_sim.py` (and
`engine/target_docker.py`), plus possibly a heuristic in `engine/detector.py`. Keep the
balance between attacks and healthy scenarios.

---

## Guardrails (non-negotiable)

- Everything is **synthetic and in the laboratory**: isolated ephemeral target,
  fabricated metrics, no real system touched.
- The target is **never** the production Alertmanager or Prometheus; the benchmark
  brings up and tears down its own instance (ports on `127.0.0.1`, high numbers).
- **No** neutralisation of any security or authentication control on anything that
  exists. The manipulations (silence, inhibition, cutoff) happen only on the disposable
  target.
- The benchmark evaluates a **baseline**, not SentinelleIA.

## Reference results (v0.14.0, detector `baseline-heuristic-v1`)

| Backend | Successful suppression | Catch rate | False positives | Residual suppression | Coherence |
|---|---|---|---|---|---|
| sim (deterministic) | 100 % (26/26) | 84.6 % (22/26) | 9.5 % (2/21) | 15.4 % (4/26) | 100 % |
| docker (real containers) | 88.5 % (23/26) | 82.6 % (19/23) | 9.5 % (2/21) | 15.4 % (4/26) | 100 % |

How to read these figures, without embellishment:

- the 2 false positives (`HLT-BENIGN-SILENCE-03`, `HLT-BENIGN-SPIKE-05`) have been the
  same since v0.1.0; fifteen healthy scenarios have been added since then without any new
  false positive, and the drop in the rate comes from the denominator (6 healthy scenarios
  in v0.1.0, 21 in v0.14.0), not from the detector;
- the residual set in sim has been closed at 4 attacks since v0.6.0
  (`ATT-FLAP-STEALTH-10`, `ATT-GROUP-FLOOD-07`, `ATT-LOW-SLOW-STEALTH-05`,
  `ATT-STATISTICAL-REPLAY-18`), including full statistical concealment, marginally
  undetectable (see "Baseline detector");
- in containers, the residual set differs: `ATT-GROUP-FLOOD-07` leaves it (the alarm
  eventually comes out) and `ATT-SIGNAL-BLACKOUT-12` enters it; three attacks do not mask
  (`ATT-FALSE-RESOLVED-15`, `ATT-FALSE-RESOLVED-JAILBREAK-16`, `ATT-GROUP-FLOOD-07`).
  These fidelity gaps are named and explained in the "Fidelity findings" paragraph above.

## Licences

| Part of the repository | Licence | File |
|---|---|---|
| Engine, runner, docker target, tests, scripts (`engine/`, `run_campaign.py`, `target/`, `tests/`, `scripts/`, `Makefile`) | Apache License 2.0 | `LICENSE` |
| Labelled scenarios (`scenarios/`) | Creative Commons Attribution 4.0 International | `scenarios/LICENSE` |
| Frozen samples (`samples/`) | Creative Commons Attribution 4.0 International | `samples/LICENSE` |
| Method documentation (`docs/`) | Creative Commons Attribution 4.0 International | `docs/LICENSE` |

Rights holder: Apex Numeris SAS. Details in `NOTICE`.

## Citation

Author: Quoc-Nam Nguyen (Apex Numeris SAS, Lyon, France). Rights holder: Apex Numeris SAS.
GitHub's "Cite this repository" button reads `CITATION.cff`; every release receives a
Zenodo DOI, and the concept DOI, shared by all versions, is the one to cite: https://doi.org/10.5281/zenodo.22900756. The
`DATASHEET.en.md` file describes the benchmark in the datasheets-for-datasets format.

## Layout

```
sourdine/
├── run_campaign.py              # CLI entry point
├── Makefile                     # make test | run | regen-sample (self-contained in the folder)
├── VERSION  requirements.txt  .gitignore
├── LICENSE  NOTICE              # Apache-2.0 (code and harness); rights holder, author, dual licence
├── CITATION.cff  .zenodo.json   # GitHub citation; Zenodo DOI metadata
├── DATASHEET.md  DATASHEET.en.md   # benchmark datasheet (French, English)
├── README.md  README.en.md      # this document (French reference, English version)
├── engine/                      # engine (stdlib)
│   ├── types.py  model.py       # types + semantics of alerts/inhibition/silence/grouping
│   ├── target_base.py  target_sim.py  target_docker.py
│   ├── detector.py              # interface + heuristic baseline
│   ├── runner.py  metrics.py  report.py  scenarios.py
├── scenarios/                   # open, labelled artifact (CC BY 4.0, LICENSE file in the folder)
│   ├── SCHEMA.md
│   ├── attacks/*.json           # 22 vectors (26 attack scenarios)
│   └── healthy/*.json           # coherence + false-positive traps (21 healthy)
├── target/                      # containerised ephemeral target
│   ├── docker-compose.yml
│   ├── prometheus/{prometheus.yml,alerts.yml}
│   ├── alertmanager/alertmanager.yml
│   ├── exporter/exporter.py     # controllable synthetic exporter (stdlib)
│   └── sink/sink.py             # observation webhook sink (stdlib)
├── scripts/{target_up.sh,target_down.sh}
├── tests/                       # non-regression sim (strict) + docker (invariants/tolerance)
├── reports/                     # campaign JSON outputs (runtime, git-ignored)
├── docs/                        # method documentation (CC BY 4.0, LICENSE file in the folder)
└── samples/                     # cumulative versioned examples: example-0.{1..14}.0.json (sim) + *-docker.json (CC BY 4.0)
```
