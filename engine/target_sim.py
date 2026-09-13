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
    VEC_SILENCE_REGEX_ALERTNAME, VEC_GROUPING_REPEAT_ABUSE, VEC_EXPORTER_CUTOFF,
    VEC_SELECTIVE_METRIC_DROP, VEC_THRESHOLD_FLAPPING, VEC_FALSE_RESOLVED,
    VEC_STALE_REPLAY, VEC_STATISTICAL_REPLAY, VEC_CONSTRAINED_REPLAY,
    VEC_ROUTE_BLACKHOLE, VEC_WATCHDOG_SUPPRESSION,
)

H = model.HORIZON
_RECENT = 10  # ticks « récents » pour les corrélations

# valeur par défaut d'un signal "up" (1 = en vie)
UP = 1.0
DOWN = 0.0

# Déviations déterministes imitant un bruit réaliste (somme ≈ 0) pour les signaux à
# distribution préservée (statistical_replay, benign_noise). Pas de random -> reproductible.
_NOISE = [3.0, -4.0, 6.0, -2.0, 5.0, -6.0, 8.0, -1.0, -3.0, 4.0, 0.0, -5.0, 2.0, -7.0, 7.0]

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
        # heartbeat watchdog (dead man's switch) : toujours vivant par défaut (1)
        metrics[model.series_key(model.WATCHDOG_SIGNAL, {})] = _const(UP)

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

        elif v == VEC_SILENCE_REGEX_ALERTNAME:
            # silence dont le matcher `alertname` est un REGEX (~.+) : balaie toutes les
            # alertes de l'instance en se faisant passer pour ciblé (matcher présent mais
            # non littéral). Contourne un détecteur qui se contente d'exiger un alertname.
            matchers = {"alertname": "~.+", "instance": instance}
            sil = Silence(id="sil-regex", matchers=matchers, created_tick=params.get("at", 5),
                          comment=params.get("comment", "targeted maintenance"), broad=False)
            silences.append(sil)
            trace.add(sil.created_tick, "silence_created", matchers=matchers, regex_alertname=True)

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

        elif v == VEC_SELECTIVE_METRIC_DROP:
            # le signal d'attaque monte brièvement (< FOR_TICKS -> ne fire pas) PUIS
            # disparaît, mais l'instance reste UP : aucune InstanceDown ne trahit la
            # panne. Plus furtif que exporter_cutoff (qui, lui, fait tomber up).
            expected_fired = False
            pre = int(params.get("pre_ticks", 2))  # < FOR_TICKS (3) -> pas de fire
            if expected_signal:
                series = _const(expected_thr + 80.0)
                for t in range(pre, H):
                    series[t] = None  # le signal disparaît
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = series
            # up laissé à sa valeur par défaut (1) -> instance vivante, pas d'InstanceDown
            trace.add(pre, "signal_blackout", instance=instance, instance_up=True)

        elif v == VEC_FALSE_RESOLVED:
            # T1562.011 Spoof Security Alerting — faux « all-clear ». L'attaque (re)monte
            # au-dessus du seuil sur les derniers instants ; l'alerte de sécurité, qui
            # aurait dû se déclencher, a été RÉSOLUE DE FORCE via l'API Alertmanager et
            # reste étouffée. En sim (état figé), on ne crée pas l'alerte attendue
            # (`expected_fired` reste False, make_fire=false) : le signal est posé haut
            # sur les `late_ticks` derniers ticks (reprise), plus bas avant.
            #   Le pic tient sur >= FOR_TICKS ticks récents (l'alerte AURAIT dû firer),
            #   mais sa somme intégrée reste SOUS le seuil low-and-slow : SEUL le détecteur
            #   de faux all-clear (phantom_clear) le rattrape. C'est ce qui distingue ce
            #   vecteur du low-and-slow (cumul) — garder late_ticks * high < seuil intégré.
            #   ⚠️ Fidélité : en docker, une VRAIE règle Prometheus ré-affirme l'alerte au
            #   cycle suivant -> le faux resolved NE TIENT PAS, l'alarme ressort. Écart
            #   assumé et mesuré (constat de fidélité 4) -> classé TIMING_SENSITIVE.
            high = float(params.get("rate", (expected_thr or model.ATTACK_RATE_THRESHOLD) + 70.0))
            late = int(params.get("late_ticks", 4))     # ticks récents au-dessus du seuil
            floor = float(params.get("floor", 0.0))     # fond calme avant la reprise
            if expected_signal:
                series = _const(floor)
                for t in range(max(0, H - late), H):
                    series[t] = high
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = series
            trace.add(max(0, H - late), "attack_resumed", signal=expected_signal, rate=high)
            trace.add(H - 1, "am_force_resolved", alert=gt.expected_alert, via="alertmanager_api")

        elif v == VEC_STALE_REPLAY:
            # ACSAC 2022 concealment (rejeu/gel — consistance TEMPORELLE) : l'attaque
            # franchit brièvement le seuil (< FOR_TICKS -> ne fire pas), puis l'attaquant
            # FIGE la métrique à un palier intermédiaire constant (rejeu/stale) au lieu de
            # la faire disparaître. Plus furtif qu'un trou : la métrique reste présente et
            # plausible, mais sa variance nulle APRÈS un franchissement trahit le rejeu.
            # low_and_slow (cumul sous le seuil intégré) et phantom_clear (figé SOUS le
            # seuil) ne le voient pas : seul `frozen_replay` le rattrape.
            expected_fired = False
            pre = int(params.get("pre_ticks", 2))       # franchissement bref (< FOR_TICKS)
            spike = float(params.get("spike", (expected_thr or model.ATTACK_RATE_THRESHOLD) + 30.0))
            frozen = float(params.get("frozen", 20.0))  # palier figé, zone grise sous le seuil
            if expected_signal:
                series = _const(frozen)
                for t in range(min(pre, H)):
                    series[t] = spike
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = series
            trace.add(0, "attack_crossed_threshold", signal=expected_signal, spike=spike)
            trace.add(pre, "stale_replay_injected", frozen=frozen)

        elif v == VEC_STATISTICAL_REPLAY:
            # ACSAC 2022 — full / distribution-preserving replay (consistances STATISTIQUE
            # ET temporelle préservées). L'attaquant remplace le signal d'attaque par un
            # échantillon tiré de la distribution du trafic NORMAL : bruité (variance
            # réaliste, pas figé), sous le seuil, cumul normal. Toutes les consistances
            # MARGINALES sont préservées -> INDÉTECTABLE par la baseline (ni frozen_replay,
            # ni low_and_slow, ni phantom_clear). Masquage RÉSIDUEL assumé : seule la
            # consistance SPATIALE (corrélation inter-signaux, hors baseline) ou le vrai
            # détecteur le rattraperait — c'est la limite qu'ACSAC 2022 démontre pour le
            # full replay (il ne brise aucune des trois consistances marginales).
            expected_fired = False
            mean = float(params.get("mean", 21.0))   # sous le seuil ; cumul(20) ~ mean*20 < seuil intégré
            if expected_signal:
                series = [max(0.0, mean + _NOISE[t % len(_NOISE)]) for t in range(H)]
                metrics[model.series_key(expected_signal, labels or {"job": job, "instance": instance})] = series
            trace.add(0, "statistical_replay_injected", mean=mean)

        elif v == VEC_CONSTRAINED_REPLAY:
            # ACSAC 2022 constrained replay : rejeu sur un SOUS-ENSEMBLE de signaux.
            # L'attaquant rejoue `attack_rate` bas (masque les attaques rapportées) mais NE
            # masque PAS `blocked_rate` (requêtes bloquées par le firewall, qui restent
            # élevées) → incohérence SPATIALE : le firewall bloque massivement mais ne
            # rapporte quasi aucune attaque. Détectable par la corrélation inter-signaux
            # (spatial_incoherence), là où le full statistical_replay (qui masque TOUT)
            # reste indétectable.
            expected_fired = False
            lset = labels or {"job": job, "instance": instance}
            attack_lo = float(params.get("attack", 20.0))     # rejeu bas (sous le seuil)
            blocked_hi = float(params.get("blocked", 80.0))   # attaque réelle bloquée, NON masquée
            if expected_signal:
                metrics[model.series_key(expected_signal, lset)] = \
                    [max(0.0, attack_lo + _NOISE[t % len(_NOISE)]) for t in range(H)]
            metrics[model.series_key("blocked_rate", lset)] = _const(blocked_hi)
            trace.add(0, "constrained_replay_injected", attack=attack_lo, blocked=blocked_hi)

        elif v == VEC_ROUTE_BLACKHOLE:
            # MITRE T1562.006 Indicator Blocking. L'alerte de sécurité FIRE (menace
            # réelle : le signal reste soutenu au-dessus du seuil), mais l'attaquant,
            # avec un accès au routage d'Alertmanager, a reroutré sa classe d'alertes
            # vers un récepteur « trou noir » (ou muté la route) : la notification n'atteint
            # JAMAIS le récepteur, SANS silence ni inhibiteur pour l'expliquer. C'est le
            # 4e levier de suppression (ni inhibition, ni silence, ni groupement) : on
            # marque l'alerte `route_muted` -> son `notified` est faux -> masquée. low_and_slow,
            # phantom_clear et flapping s'abstiennent (une alerte à taux EST active) : seul
            # `notification_blackhole` la rattrape (corrélation métrique <-> livraison).
            lset = labels or {"job": job, "instance": instance}
            high = float(params.get("rate", (expected_thr or model.ATTACK_RATE_THRESHOLD) + 70.0))
            if expected_signal:
                metrics[model.series_key(expected_signal, lset)] = _const(high)
            alerts.append(Alert(name=gt.expected_alert or "HighAttackRate",
                                labels=lset, route_muted=True))
            trace.add(2, "route_blackholed", alert=gt.expected_alert, receiver="blackhole")

        elif v == VEC_WATCHDOG_SUPPRESSION:
            # MITRE T1562 Impair Defenses — l'attaquant DÉSACTIVE la chaîne d'alerte
            # (Alertmanager / livraison) AVANT de frapper, puis aveugle le signal
            # d'attaque : rien de la menace n'est observable (aucune alerte active,
            # aucune métrique d'attaque), donc AUCUNE des heuristiques métrique/alerte ne
            # peut la voir. Le SEUL tell est le heartbeat watchdog qui s'éteint. On coupe
            # donc le watchdog (0) sur la queue de la fenêtre ; l'alarme attendue n'est ni
            # levée ni notifiée (masquée). Seul `watchdog_gap` la rattrape — dead man's switch.
            expected_fired = False
            silent_from = int(params.get("silent_from", H - 12))
            wd: list[Optional[float]] = _const(UP)
            for t in range(max(0, silent_from), H):
                wd[t] = DOWN                     # heartbeat éteint (0) = chaîne morte
            metrics[model.series_key(model.WATCHDOG_SIGNAL, {})] = wd
            trace.add(silent_from, "watchdog_silent", reason="alerting_pipeline_down")

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
            elif bk == "benign_signal_gap":
                # un signal cesse d'être exporté pendant une période CALME (activité
                # basse AVANT le trou) : ni signal_blackout ni exporter_cutoff ne doivent
                # crier au masquage, faute d'activité élevée avant. Vrai négatif.
                low = float(params.get("low", 8.0))
                at = int(params.get("at", 4))
                sg: list[Optional[float]] = _const(low)
                for t in range(at, H):
                    sg[t] = None
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = sg
                trace.add(at, "licit_signal_gap", low=low)
            elif bk == "benign_resolve":
                # all-clear LÉGITIME (pendant sain de false_resolved) : la menace
                # franchit le seuil (l'alerte a fire et été notifiée), PUIS retombe
                # RÉELLEMENT et durablement sous le seuil -> resolved légitime. En fin
                # de fenêtre : plus d'alerte ET signal bas. phantom_clear ne doit pas
                # crier (son dernier point observé est sous le seuil). Vrai négatif.
                high = float(params.get("high", model.ATTACK_RATE_THRESHOLD + 70.0))
                low = float(params.get("low", 8.0))
                at = int(params.get("at", 10))
                res: list[Optional[float]] = _const(high)
                for t in range(at, H):
                    res[t] = low
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = res
                trace.add(at, "legit_resolve", reason="menace retombee sous le seuil")
            elif bk == "benign_settle":
                # activité licite élevée mais SOUS le seuil, puis stabilisation à un palier :
                # la métrique se fige mais n'a JAMAIS franchi le seuil -> frozen_replay ne
                # doit pas crier (il exige un franchissement préalable). Vrai négatif du
                # rejeu/gel (garde anti-FP de stale_replay).
                high = float(params.get("high", 40.0))       # sous le seuil (50)
                frozen = float(params.get("frozen", 20.0))
                pre = int(params.get("pre_ticks", 4))
                st: list[Optional[float]] = _const(frozen)
                for t in range(min(pre, H)):
                    st[t] = high
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = st
                trace.add(pre, "licit_settle", high=high, frozen=frozen)
            elif bk == "benign_noise":
                # trafic licite bruité sous le seuil (même allure statistique qu'une attaque
                # diluée par statistical_replay) : la baseline marginale ne peut PAS le
                # distinguer d'une attaque à distribution préservée -> elle ne doit pas le
                # flaguer. Vrai négatif illustrant la limite (seule l'analyse de contenu /
                # la consistance spatiale distinguerait licite et malveillant à stats égales).
                mean = float(params.get("mean", 16.0))
                series = [max(0.0, mean + _NOISE[t % len(_NOISE)]) for t in range(H)]
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = series
                trace.add(1, "licit_noise", mean=mean)
            elif bk == "benign_correlated":
                # attack_rate et blocked_rate COHÉRENTS (corrélés, tous deux bas) : pas
                # d'incohérence spatiale -> spatial_incoherence ne doit pas crier. Vrai
                # négatif de constrained_replay (garde anti-FP de la consistance spatiale).
                lvl = float(params.get("level", 18.0))
                metrics[model.series_key("attack_rate", {"job": job, "instance": instance})] = \
                    [max(0.0, lvl + _NOISE[t % len(_NOISE)]) for t in range(H)]
                metrics[model.series_key("blocked_rate", {"job": job, "instance": instance})] = _const(lvl)
                trace.add(1, "licit_correlated", level=lvl)
            elif bk == "benign_route_mute":
                # maintenance légitime : une alerte NON-sécurité (PostgreSQLHighConnections)
                # est routée vers le trou noir pendant une fenêtre de maintenance planifiée
                # de la base. Réellement non délivrée (route_muted) MAIS ce n'est pas une
                # menace de sécurité -> notification_blackhole ne doit PAS crier (garde de
                # classe sécurité). Vrai négatif de route_blackhole : sans le garde de
                # classe, un détecteur naïf flaguerait cette maintenance -> faux positif.
                pg = float(params.get("pg_conns", model.PG_CONN_THRESHOLD + 60.0))
                metrics[model.series_key("pg_conns", {"job": "postgresql", "instance": instance})] = _const(pg)
                alerts.append(Alert(name="PostgreSQLHighConnections",
                                    labels={"job": "postgresql", "instance": instance},
                                    route_muted=True))
                trace.add(2, "route_blackholed", alert="PostgreSQLHighConnections", legit_maintenance=True)
            elif bk == "benign_watchdog_blip":
                # raté TRANSITOIRE du heartbeat watchdog (un scrape manqué) qui se
                # rétablit : la chaîne d'alerte est saine. watchdog_gap ne doit PAS crier
                # (il exige un silence SOUTENU en fin de fenêtre) — sinon on paierait chaque
                # jitter de scrape (alert fatigue). Vrai négatif du dead man's switch : sans
                # le garde de silence soutenu, ce blip transitoire deviendrait un faux positif.
                blip_at = int(params.get("at", 12))
                blip_len = int(params.get("len", 2))     # court, loin de la fin de fenêtre
                wd: list[Optional[float]] = _const(UP)
                for t in range(blip_at, min(H, blip_at + blip_len)):
                    wd[t] = None                          # scrape manqué (trou), puis rétabli
                metrics[model.series_key(model.WATCHDOG_SIGNAL, {})] = wd
                trace.add(blip_at, "watchdog_blip", transient=True, length=blip_len)

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
                           "delayed": a.delayed, "route_muted": a.route_muted} for a in alerts],
        )
        state = SupervisionState(alerts=alerts, silences=silences, metric_history=metrics, horizon=H)
        return raw, state, trace
