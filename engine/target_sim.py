"""Sourdine — cible simulée en process (déterministe, hermétique).

Interprète l'intention haut-niveau d'un scénario (`event` = ce qui devait lever
l'alarme ; `masking` = la manœuvre) en un état de supervision concret, puis
applique la sémantique Alertmanager (inhibition / silence / groupement) du
module `model`. Aucun conteneur, aucun port, aucun réseau : c'est la cible la
plus isolée possible, et elle donne des taux reproductibles.

La cible docker (`target_docker`) rejoue la MÊME intention contre de vrais
conteneurs ; les deux produisent les mêmes types (RawResult / SupervisionState /
Trace) pour que le détecteur soit identique.
"""
from __future__ import annotations

from typing import Optional

from engine import model
from engine.target_base import Target
from engine.types import (
    Alert, RawResult, Scenario, Silence, SupervisionState, Trace,
    VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF,
    VEC_LOW_AND_SLOW, VEC_SILENCE_ABUSE, VEC_SILENCE_SHARED_LABEL,
    VEC_GROUPING_REPEAT_ABUSE, VEC_EXPORTER_CUTOFF, VEC_THRESHOLD_FLAPPING,
)

H = model.HORIZON
_RECENT = 10  # ticks « récents » pour les corrélations

# valeur par défaut d'un signal "up" (1 = en vie)
UP = 1.0
DOWN = 0.0

# Corroboration attendue d'une alerte source inhibitrice (signal qui devrait être
# à 0 si la panne est réelle).
CORROBORATION_SIGNAL = {
    "InstanceDown": "up",
    "FirewallDown": "fw_up",
    "PostgreSQLDown": "pg_up",
}


def _const(value: Optional[float], n: int = H) -> list[Optional[float]]:
    return [value] * n


class SimTarget(Target):
    name = "sim"

    def setup(self) -> None:  # rien à monter
        pass

    def teardown(self) -> None:  # rien à détruire
        pass

    # -- évaluation de firing -------------------------------------------------
    @staticmethod
    def _fires_threshold(series: list[Optional[float]], threshold: float) -> bool:
        run = 0
        for v in series:
            if v is not None and v > threshold:
                run += 1
                if run >= model.FOR_TICKS:
                    return True
            else:
                run = 0
        return False

    @staticmethod
    def _fires_absence(series: list[Optional[float]]) -> bool:
        run = 0
        for v in series:
            if v is None or v == 0.0:
                run += 1
                if run >= model.FOR_TICKS:
                    return True
            else:
                run = 0
        return False

    # -- exécution ------------------------------------------------------------
    def execute(self, sc: Scenario) -> tuple[RawResult, SupervisionState, Trace]:
        gt = sc.ground_truth
        labels = dict(gt.labels) if gt.labels else {}
        job = labels.get("job", "firewall")
        instance = labels.get("instance", "fw-1")
        metrics: dict[str, list[Optional[float]]] = {}
        alerts: list[Alert] = []
        silences: list[Silence] = []
        trace = Trace()

        # signaux d'infra par défaut : tout est « up »
        metrics[model.series_key("up", {"instance": instance, "job": job})] = _const(UP)
        metrics[model.series_key("fw_up", {"job": job})] = _const(UP)
        metrics[model.series_key("pg_up", {"job": "postgresql"})] = _const(UP)

        expected_signal = model.ALERT_RULES.get(gt.expected_alert or "", {}).get("signal")
        expected_thr = model.ALERT_RULES.get(gt.expected_alert or "", {}).get("threshold", 0.0)
        make_fire = bool(sc.event.get("make_fire", False))

        # --- 1) poser l'événement qui devait lever l'alarme ------------------
        def set_expected_series(value: Optional[float]):
            if expected_signal:
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = _const(value)

        expected_fired = False
        if make_fire and expected_signal:
            # valeur franchement au-dessus du seuil -> la règle fire
            set_expected_series(expected_thr + max(70.0, expected_thr))
            expected_fired = True
            trace.add(0, "event_injected", alert=gt.expected_alert, signal=expected_signal)

        # --- 2) appliquer le vecteur de masquage -----------------------------
        v = sc.vector
        params = sc.masking.get("params", {}) if sc.masking else {}

        if v in (VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF):
            source = {
                VEC_FIREWALL_DOWN_SPOOF: ("FirewallDown", {"job": job}),
                VEC_INSTANCE_DOWN_SPOOF: ("InstanceDown", {"instance": instance, "job": job}),
                VEC_POSTGRES_DOWN_SPOOF: ("PostgreSQLDown", {"job": labels.get("job", "postgresql")}),
            }[v]
            src_alert = Alert(name=source[0], labels=source[1])
            alerts.append(src_alert)
            # contradiction : la cible prétendument "down" est en réalité up
            corr = CORROBORATION_SIGNAL[source[0]]
            corr_labels = source[1] if corr != "up" else {"instance": instance, "job": job}
            metrics[model.series_key(corr, corr_labels)] = _const(UP)  # reste UP -> spoof
            trace.add(2, "inhibitor_alert_appeared", alertname=source[0], labels=source[1])

        elif v == VEC_LOW_AND_SLOW:
            # l'alerte à taux ne fire jamais : on reste sous le seuil instantané…
            expected_fired = False
            under = params.get("rate", 30.0)  # < seuil
            set_expected_series(under)
            # …mais la somme intégrée est haute (catchable) ou juste sous (stealth/résiduel)
            trace.add(1, "sub_threshold_activity", rate=under, window=model.CUMULATIVE_WINDOW)

        elif v == VEC_THRESHOLD_FLAPPING:
            # oscillation autour du seuil : jamais FOR_TICKS consécutifs au-dessus,
            # donc l'alerte ne fire jamais (le `for:` est réinitialisé en boucle).
            expected_fired = False
            high = float(params.get("high", expected_thr + 20.0))
            low = float(params.get("low", 10.0))
            n_spikes = params.get("spikes")  # présent => variante FURTIVE (peu de franchissements)
            if n_spikes:
                series: list[Optional[float]] = [low] * H
                for k in range(int(n_spikes)):
                    idx = 2 + k * 4
                    if idx < H:
                        series[idx] = high
            else:
                series = [high if t % 2 == 0 else low for t in range(H)]
            if expected_signal:
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = series
            trace.add(1, "threshold_flapping", high=high, low=low, spikes=n_spikes)

        elif v == VEC_SILENCE_ABUSE:
            broad = bool(params.get("broad", False))
            if broad:
                matchers = {"instance": "~.+"}            # large (toute instance non vide) ; ~.* serait refusé par le vrai AM
            else:
                matchers = {"alertname": gt.expected_alert or "~.+", "job": job}
            sil = Silence(id="sil-atk", matchers=matchers, created_tick=params.get("at", 5),
                          comment=params.get("comment", "ops"), broad=broad)
            silences.append(sil)
            trace.add(sil.created_tick, "silence_created", matchers=matchers, broad=broad)

        elif v == VEC_SILENCE_SHARED_LABEL:
            # silence par label PARTAGÉ (job) sans matcher alertname : balaie toute une
            # classe d'alertes sous couvert de maintenance de service.
            label = params.get("label", "job")
            value = params.get("value", job if label == "job" else instance)
            matchers = {label: value}
            sil = Silence(id="sil-shared", matchers=matchers, created_tick=params.get("at", 5),
                          comment=params.get("comment", "service maintenance"), broad=False)
            silences.append(sil)
            trace.add(sil.created_tick, "silence_created", matchers=matchers, shared_label=label)

        elif v == VEC_GROUPING_REPEAT_ABUSE:
            # noyer la vraie alerte : flot de frères dans le même groupe
            count = int(params.get("count", model.FLOOD_MIN + 8))
            for i in range(count):
                alerts.append(Alert(name=gt.expected_alert or "HighAttackRate",
                                    labels={"job": job, "instance": f"flood-{i}"}))
            trace.add(3, "group_flood", group_size=count)

        elif v == VEC_EXPORTER_CUTOFF:
            # activité élevée PUIS coupure de collecte : l'alerte ne part jamais
            expected_fired = False
            pre = int(params.get("pre_ticks", 4))
            if expected_signal:
                series = _const(expected_thr + 80.0)
                for t in range(pre, H):
                    series[t] = None  # trou de collecte
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = series
            # l'instance tombe réellement -> up=0 (coupure), InstanceDown fire légitimement
            up_series = _const(UP)
            for t in range(pre, H):
                up_series[t] = DOWN
            metrics[model.series_key("up", {"instance": instance, "job": job})] = up_series
            trace.add(pre, "scrape_gap_start", instance=instance, preceded_by_activity=True)

        elif v == "none":
            # scénario sain : action bénigne éventuelle (ressemble de loin à un vecteur)
            bk = sc.masking.get("type") if sc.masking else None
            if bk == "benign_silence":
                broad = bool(params.get("broad", False))
                matchers = ({"instance": "~.+"} if broad
                            else {"alertname": params.get("alertname", "DiskSpaceLow"), "instance": instance})
                silences.append(Silence(id="sil-ops", matchers=matchers,
                                        created_tick=params.get("at", 5),
                                        comment="maintenance planifiée", broad=broad))
                # petite activité licite concomitante (source honnête de faux positif)
                if params.get("minor_activity"):
                    metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = _const(params["minor_activity"])
                trace.add(params.get("at", 5), "silence_created", matchers=matchers, broad=broad)
            elif bk == "benign_exporter_restart":
                pre = int(params.get("pre_ticks", 12))
                up_series = _const(UP)
                for t in range(pre, pre + int(params.get("gap", 4))):
                    up_series[t] = DOWN
                metrics[model.series_key("up", {"instance": instance, "job": job})] = up_series
                if params.get("minor_activity"):  # blip licite avant le redémarrage -> FP possible
                    ar = _const(0.0)
                    for t in range(max(0, pre - 3), pre):
                        ar[t] = params["minor_activity"]
                    metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = ar
                trace.add(pre, "scrape_gap_start", instance=instance, reason="maintenance")
            elif bk == "benign_spike":
                rate = params.get("rate", 30.0)  # sous le seuil instantané, volume licite
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = _const(rate)
                trace.add(1, "licit_traffic_spike", rate=rate)
            elif bk == "benign_jitter":
                # trafic licite en dents de scie, MAIS entièrement sous le seuil : 0
                # franchissement -> le détecteur de flapping ne doit pas s'y méprendre.
                high = float(params.get("high", 35.0))
                low = float(params.get("low", 5.0))
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = \
                    [high if t % 2 == 0 else low for t in range(H)]
                trace.add(1, "licit_jitter", high=high, low=low)
            elif bk == "benign_brief_spike":
                # un unique pic licite qui franchit le seuil trop brièvement pour firer
                # (< FOR_TICKS) : un seul franchissement -> ni alerte, ni flapping.
                spike = float(params.get("spike", 65.0))
                at = int(params.get("at", 6))
                dur = int(params.get("dur", 2))
                # ligne de base NON nulle : retomber à 0 serait lu comme un trou de
                # collecte (exporter_cutoff) après activité -> faux positif non voulu.
                ar: list[Optional[float]] = _const(float(params.get("baseline", 5.0)))
                for t in range(at, min(H, at + dur)):
                    ar[t] = spike
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = ar
                trace.add(at, "brief_licit_spike", spike=spike, dur=dur)

        # --- 3) inhibiteurs qui firent RÉELLEMENT (ex. coupure -> InstanceDown)
        up_key = model.series_key("up", {"instance": instance, "job": job})
        if self._fires_absence(metrics.get(up_key, _const(UP))):
            if not any(a.name == "InstanceDown" and a.labels.get("instance") == instance for a in alerts):
                alerts.append(Alert(name="InstanceDown", labels={"instance": instance, "job": job}))

        # --- 4) l'alerte attendue, si elle fire, entre dans l'ensemble actif --
        expected_alert_obj: Optional[Alert] = None
        if expected_fired and gt.expected_alert:
            expected_alert_obj = Alert(name=gt.expected_alert, labels=labels or {"job": job, "instance": instance})
            alerts.append(expected_alert_obj)

        # --- 5) sémantique Alertmanager -------------------------------------
        model.apply_inhibitions(alerts)
        model.apply_silences(alerts, silences)
        # groupement : la vraie alerte noyée par un groupe surchargé
        if v == VEC_GROUPING_REPEAT_ABUSE and expected_alert_obj is not None:
            same_group = [a for a in alerts if model.group_key(a) == model.group_key(expected_alert_obj)]
            if len(same_group) >= model.FLOOD_MIN:
                expected_alert_obj.delayed = True

        notified = [a for a in alerts if a.notified]

        # --- 6) résultat brut (passe 1) -------------------------------------
        alarm_raised = False
        if gt.alarm_expected and gt.expected_alert:
            alarm_raised = any(a.matches(gt.expected_alert, labels) for a in notified)

        raw = RawResult(
            alarm_raised=alarm_raised,
            notified_alerts=[{"name": a.name, "labels": a.labels} for a in notified],
            fired_alerts=[{"name": a.name, "labels": a.labels,
                           "inhibited_by": a.inhibited_by, "silenced_by": a.silenced_by,
                           "delayed": a.delayed} for a in alerts],
        )
        state = SupervisionState(alerts=alerts, silences=silences, metric_history=metrics, horizon=H)
        return raw, state, trace
