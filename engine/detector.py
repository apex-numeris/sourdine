"""Sourdine — détecteur de masquage (interface stable + baseline heuristique).

Le détecteur ne regarde PAS le contenu de l'attaque : il cherche le silence
suspect et les manipulations de la chaîne d'alerte. Principe directeur — le chien
qui n'aboie pas : l'absence anormale de signal est elle-même le signal.

`MaskingDetector` est l'interface stable. Le banc fournit `BaselineDetector`
(volontairement imparfaite). Le vrai détecteur de SentinelleIA viendra
implémenter la même interface, hors de ce worktree, et se mesurera au même
protocole — le banc n'importe pas le produit.

Le détecteur est AVEUGLE au scénario : il ne reçoit que SupervisionState + Trace.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from engine import model
from engine.types import SupervisionState, Trace, Verdict

_RECENT = 10


def parse_key(key: str) -> tuple[str, dict[str, str]]:
    signal, rest = key.split("{", 1)
    inner = rest[:-1]
    labels: dict[str, str] = {}
    if inner:
        for part in inner.split(","):
            k, vv = part.split("=", 1)
            labels[k] = vv
    return signal, labels


def _clean(series: list[Optional[float]]) -> list[float]:
    return [v for v in series if v is not None]


class MaskingDetector(ABC):
    name: str = "abstract"

    @abstractmethod
    def detect(self, state: SupervisionState, trace: Trace) -> Verdict:
        ...


class BaselineDetector(MaskingDetector):
    """Baseline honnête : une heuristique par famille de vecteurs."""

    name = "baseline-heuristic-v1"

    # -- accès métrique -------------------------------------------------------
    def _series(self, state: SupervisionState, signal: str,
                label_filter: Optional[dict] = None) -> list[tuple[dict, list[Optional[float]]]]:
        out = []
        for key, series in state.metric_history.items():
            sg, lbls = parse_key(key)
            if sg != signal:
                continue
            if label_filter and not all(lbls.get(k) == v for k, v in label_filter.items()):
                continue
            out.append((lbls, series))
        return out

    def _recent_max(self, state, signal, label_filter=None) -> float:
        best = 0.0
        for _lbls, series in self._series(state, signal, label_filter):
            vals = _clean(series[-_RECENT:])
            if vals:
                best = max(best, max(vals))
        return best

    def _is_recently_down(self, state, signal, label_filter=None) -> bool:
        """Vrai si le signal 'up' est réellement à 0/absent récemment (panne corroborée)."""
        found_any = False
        for _lbls, series in self._series(state, signal, label_filter):
            found_any = True
            tail = series[-model.FOR_TICKS:]
            if not all(v in (None, 0.0) for v in tail):
                return False
        return found_any  # corroboré seulement si on a bien vu le signal à 0

    # -- heuristiques ---------------------------------------------------------
    def _h_inhibitor_isolation(self, state) -> Optional[Verdict]:
        """Source inhibitrice isolée : masque une cible vivante sans être corroborée."""
        for src in state.alerts:
            if src.name not in model.INHIBITOR_SOURCES:
                continue
            corr = model.INHIBITOR_CORROBORATION[src.name]   # source unique (cf. model.py)
            corr_filter = {"instance": src.labels["instance"]} if (corr == "up" and "instance" in src.labels) \
                else ({"job": src.labels.get("job", "")} if src.labels.get("job") else None)
            corroborated = self._is_recently_down(state, corr, corr_filter)
            for tgt in state.alerts:
                if tgt is src:
                    continue
                if not any(ib.startswith(src.name) for ib in tgt.inhibited_by):
                    continue
                tgt_signal = model.ALERT_RULES.get(tgt.name, {}).get("signal")
                tgt_thr = model.ALERT_RULES.get(tgt.name, {}).get("threshold", 0.0)
                if not tgt_signal:
                    continue
                if self._recent_max(state, tgt_signal) > tgt_thr and not corroborated:
                    scope = (f"instance={src.labels.get('instance')}" if "instance" in src.labels
                             else f"job={src.labels.get('job')}")
                    return Verdict(True, scope=scope, heuristic="inhibitor_isolation",
                                   reason=(f"Alerte source {src.name} active et non corroborée "
                                           f"(sa cible vivante {tgt.name} reste élevée) — inhibition suspecte."))
        return None

    def _h_rogue_inhibitor(self, state) -> Optional[Verdict]:
        """Règle d'inhibition ROGUE (MITRE T1562.001 Disable or Modify Tools). Une alerte de
        sécurité est inhibée par une source qui n'appartient PAS à l'ensemble des sources
        d'inhibition sanctionnées (baseline) : l'attaquant a ajouté une règle d'inhibition dont
        la source est une alerte bénigne qu'il contrôle, pour étouffer la classe sécurité. C'est
        distinct des spoofs (round 1-3), qui FALSIFIENT une source SANCTIONNÉE (InstanceDown…) et
        que `inhibitor_isolation` rattrape par non-corroboration : ici la source est ILLÉGITIME,
        donc `inhibitor_isolation` — qui ne regarde que les sources sanctionnées — ne l'examine
        même pas. Détection par dérive de config : l'inhibition ne figure pas dans la baseline
        sanctionnée. Le discriminant est la LÉGITIMITÉ de la source, pas la corroboration."""
        for a in state.alerts:
            if a.name not in model.SECURITY_RATE_ALERTS:
                continue
            rogue = [ib for ib in a.inhibited_by
                     if not any(ib.startswith(s) for s in model.INHIBITOR_SOURCES)]
            if not rogue:
                continue
            signal = model.ALERT_RULES.get(a.name, {}).get("signal")
            thr = model.ALERT_RULES.get(a.name, {}).get("threshold", 0.0)
            if signal and self._recent_max(state, signal) > thr:
                return Verdict(True, scope=f"{a.name}<-{rogue[0]}", heuristic="rogue_inhibitor",
                               reason=(f"Alerte de sécurité {a.name} inhibée par une source NON "
                                       f"sanctionnée ({rogue[0]}) alors que la menace est réelle "
                                       f"(> {thr:.0f}) : règle d'inhibition rogue (config d'alerte "
                                       f"altérée, T1562.001)."))
        return None

    def _h_low_and_slow(self, state) -> Optional[Verdict]:
        rate_alert_present = any(a.name in ("HighAttackRate", "JailbreakSurge") for a in state.alerts)
        if rate_alert_present:
            return None
        for signal in ("attack_rate", "jailbreak_rate"):
            for lbls, series in self._series(state, signal):
                cum = sum(_clean(series[-model.CUMULATIVE_WINDOW:]))
                if cum > model.CUMULATIVE_THRESHOLD:
                    return Verdict(True, scope=f"{signal}{{job={lbls.get('job')}}}",
                                   heuristic="low_and_slow",
                                   reason=(f"Somme intégrée {cum:.0f} > {model.CUMULATIVE_THRESHOLD:.0f} "
                                           f"sur {model.CUMULATIVE_WINDOW} ticks sans alerte à taux."))
        return None

    def _h_silence_abuse(self, state) -> Optional[Verdict]:
        for sil in state.silences:
            # Sur-périmétré : matcher `instance` large (broad), OU pas de matcher
            # `alertname` EXACT (absent, ou regex type `~.+`) — le silence balaie alors
            # toute une classe d'alertes, y compris des alertes de sécurité. Une
            # maintenance légitime, elle, nomme un `alertname` littéral précis.
            exact_alertname = ("alertname" in sil.matchers
                               and not sil.matchers["alertname"].startswith("~"))
            over_scoped = sil.broad or not exact_alertname
            if over_scoped:
                return Verdict(True, scope=f"silence={sil.id}", heuristic="silence_abuse",
                               reason="Silence sur-périmétré (pas de matcher alertname, ou "
                                      "instance large) : met en sourdine toute une classe d'alertes.")
            # silence étroit (ciblé par alertname) : suspect seulement s'il est
            # posé pendant une montée d'activité (une maintenance légitime, elle,
            # est posée au calme).
            near = False
            for signal in ("attack_rate", "jailbreak_rate"):
                for _lbls, series in self._series(state, signal):
                    window = series[max(0, sil.created_tick - 2): sil.created_tick + 3]
                    if any(v is not None and v > 5.0 for v in window):
                        near = True
            if near:
                return Verdict(True, scope=f"silence={sil.id}", heuristic="silence_abuse",
                               reason="Silence étroit posé pendant une montée d'activité.")
        return None

    def _h_exporter_cutoff(self, state) -> Optional[Verdict]:
        for upsig in ("up", "fw_up", "pg_up"):
            for _lbls, series in self._series(state, upsig):
                gstart = self._gap_start(series)
                if gstart is not None and self._activity_before(state, gstart):
                    return Verdict(True, scope=f"{upsig}", heuristic="exporter_cutoff",
                                   reason="Trou de collecte coïncidant avec une activité élevée juste avant.")
        # trou sur le signal d'attaque lui-même
        for _lbls, series in self._series(state, "attack_rate"):
            gstart = self._gap_start(series)
            if gstart is not None and self._activity_before(state, gstart, series=series):
                return Verdict(True, scope="attack_rate", heuristic="exporter_cutoff",
                               reason="L'exporter devient muet au mauvais moment (activité juste avant le trou).")
        return None

    @staticmethod
    def _gap_start(series: list[Optional[float]]) -> Optional[int]:
        for i in range(1, len(series)):
            prev, cur = series[i - 1], series[i]
            if prev not in (None, 0.0) and cur in (None, 0.0):
                # confirmer un vrai trou (>=2 ticks)
                if all(v in (None, 0.0) for v in series[i:i + 2]):
                    return i
        return None

    def _activity_before(self, state, idx: int, series: Optional[list] = None, lookback: int = 4) -> bool:
        bar = model.ATTACK_RATE_THRESHOLD / 2.0
        candidates = [series] if series is not None else [s for _l, s in self._series(state, "attack_rate")]
        for s in candidates:
            window = s[max(0, idx - lookback): idx]
            if any(v is not None and v > bar for v in window):
                return True
        return False

    def _h_flapping(self, state) -> Optional[Verdict]:
        """Flapping volontaire : le signal franchit le seuil en boucle sans qu'aucune
        alerte à taux ne se déclenche (l'attaquant réinitialise le `for:`)."""
        if any(a.name in ("HighAttackRate", "JailbreakSurge") for a in state.alerts):
            return None  # une alerte à taux est active : pas de masquage par flapping
        for signal, thr in (("attack_rate", model.ATTACK_RATE_THRESHOLD),
                            ("jailbreak_rate", model.JAILBREAK_RATE_THRESHOLD)):
            for lbls, series in self._series(state, signal):
                crossings = self._up_crossings(series, thr)
                if crossings >= model.FLAP_MIN_CROSSINGS:
                    return Verdict(True, scope=f"{signal}{{job={lbls.get('job')}}}",
                                   heuristic="threshold_flapping",
                                   reason=(f"{crossings} franchissements montants du seuil "
                                           f"{thr:.0f} sans alerte à taux : `for:` réinitialisé en boucle."))
        return None

    @staticmethod
    def _up_crossings(series: list[Optional[float]], threshold: float) -> int:
        count, prev_above = 0, False
        for v in series:
            if v is None:
                continue
            above = v > threshold
            if above and not prev_above:
                count += 1
            prev_above = above
        return count

    def _h_signal_blackout(self, state) -> Optional[Verdict]:
        """Blackout sélectif : un signal d'attaque disparaît (trou) APRÈS activité,
        alors que l'instance reste UP (aucun InstanceDown pour trahir la panne).
        Distinct de exporter_cutoff, qui, lui, fait tomber l'instance (`up` -> 0)."""
        for signal in ("attack_rate", "jailbreak_rate"):
            for lbls, series in self._series(state, signal):
                gstart = self._gap_start(series)
                if gstart is None:
                    continue
                if not self._activity_before(state, gstart, series=series):
                    continue
                inst = lbls.get("instance")
                up_series = self._series(state, "up", {"instance": inst} if inst else None)
                instance_down = any(
                    any(v in (None, 0.0) for v in s[gstart:gstart + model.FOR_TICKS])
                    for _l, s in up_series)
                if not instance_down:  # l'instance reste UP -> blackout sélectif
                    return Verdict(True, scope=f"{signal}{{instance={inst}}}",
                                   heuristic="signal_blackout",
                                   reason=("Signal d'attaque disparu (trou) après activité, alors "
                                           "que l'instance reste UP : blackout sélectif du signal."))
        return None

    def _h_phantom_clear(self, state) -> Optional[Verdict]:
        """Faux all-clear (OWASP LLM-adjacent / MITRE T1562.011 Spoof Security Alerting) :
        un signal à taux reste SOUTENU au-dessus du seuil (>= FOR_TICKS consécutifs dans
        la fenêtre récente), donc l'alerte à taux AURAIT dû être active — mais aucune ne
        l'est, et aucune cause légitime de suppression n'existe (ni source inhibitrice, ni
        silence). L'alerte a été indûment résolue/étouffée alors que la menace persiste :
        le chien qu'on a fait taire APRÈS qu'il a aboyé, distinct des vecteurs qui
        l'empêchent d'aboyer. La détection est une corrélation métrique <-> alerte, comme
        recommandé pour T1562.011 (comparer la télémétrie à la notification)."""
        if any(a.name in ("HighAttackRate", "JailbreakSurge") for a in state.alerts):
            return None                       # une alerte à taux est active : pas de masquage
        if any(a.name in model.INHIBITOR_SOURCES for a in state.alerts):
            return None                       # inhibition en jeu -> _h_inhibitor_isolation qualifie
        if state.silences:
            return None                       # silence en jeu -> _h_silence_abuse qualifie
        for signal, thr in (("attack_rate", model.ATTACK_RATE_THRESHOLD),
                            ("jailbreak_rate", model.JAILBREAK_RATE_THRESHOLD)):
            for lbls, series in self._series(state, signal):
                recent = series[-_RECENT:]
                observed = [v for v in recent if v is not None]
                # signal ENCORE chaud (dernier point observé > seuil) ET run soutenu
                # récent : un all-clear légitime, lui, est retombé -> dernier point bas.
                if observed and observed[-1] > thr and self._sustained_above(recent, thr):
                    return Verdict(True, scope=f"{signal}{{job={lbls.get('job')}}}",
                                   heuristic="phantom_clear",
                                   reason=(f"{signal} encore au-dessus du seuil {thr:.0f} "
                                           f"(soutenu >= {model.FOR_TICKS} ticks récents) sans alerte "
                                           f"active ni cause de suppression : all-clear fantôme (resolved forcé)."))
        return None

    @staticmethod
    def _sustained_above(series: list[Optional[float]], threshold: float) -> bool:
        """Vrai s'il existe un run d'au moins FOR_TICKS valeurs consécutives > seuil
        (une alerte à taux se serait déclenchée : `for:` complété)."""
        run = 0
        for v in series:
            if v is not None and v > threshold:
                run += 1
                if run >= model.FOR_TICKS:
                    return True
            else:
                run = 0
        return False

    def _h_frozen_replay(self, state) -> Optional[Verdict]:
        """Rejeu / gel de données (ACSAC 2022 « generic concealment » — violation de
        consistance TEMPORELLE). Après avoir FRANCHI le seuil (attaque réelle), le signal
        est FIGÉ à une valeur intermédiaire constante (variance nulle) au lieu de
        disparaître : la métrique reste présente et plausible — plus furtif qu'un trou
        (`selective_metric_drop`) — mais sa dynamique gelée trahit le rejeu, là où un vrai
        signal continuerait de varier. Distinct du low-and-slow (jamais au-dessus du seuil)
        et du pic bénin bref (qui retombe au repos, pas à un palier intermédiaire)."""
        for signal, thr in (("attack_rate", model.ATTACK_RATE_THRESHOLD),
                            ("jailbreak_rate", model.JAILBREAK_RATE_THRESHOLD)):
            for lbls, series in self._series(state, signal):
                gstart = self._frozen_start(series)
                if gstart is None:
                    continue
                fval = series[-1]
                # figé dans la « zone grise » : trafic maintenu MAIS sous le seuil (au
                # repos -> pas suspect ; au-dessus du seuil -> ce serait phantom_clear).
                if fval is None or not (thr * 0.3 < fval <= thr):
                    continue
                # l'attaque a réellement franchi le seuil AVANT le gel
                if any(v is not None and v > thr for v in series[:gstart]):
                    return Verdict(True, scope=f"{signal}{{job={lbls.get('job')}}}",
                                   heuristic="frozen_replay",
                                   reason=(f"{signal} a franchi le seuil {thr:.0f} puis est FIGÉ à "
                                           f"{fval:.0f} (variance nulle >= {model.STALE_FROZEN_MIN} ticks) "
                                           f"sans trou : rejeu/stale masquant l'attaque."))
        return None

    @staticmethod
    def _frozen_start(series: list[Optional[float]]) -> Optional[int]:
        """Index de début de la plus longue queue EXACTEMENT constante (dernier point
        non-None, >= STALE_FROZEN_MIN points identiques), sinon None."""
        last = series[-1] if series else None
        if last is None:
            return None
        i = len(series) - 1
        while i > 0 and series[i - 1] == last:
            i -= 1
        return i if (len(series) - i) >= model.STALE_FROZEN_MIN else None

    def _h_spatial_incoherence(self, state) -> Optional[Verdict]:
        """Consistance SPATIALE (ACSAC 2022, constrained replay). `attack_rate` (attaques
        rapportées) et `blocked_rate` (requêtes bloquées par le firewall) sont normalement
        corrélés — ils mesurent la même activité malveillante sous deux angles. Un
        constrained replay rejoue attack_rate bas (masque le compteur d'attaques) mais ne
        masque PAS blocked_rate : le firewall bloque massivement alors qu'il ne rapporte
        quasi aucune attaque. Cette divergence entre deux signaux qui devraient bouger
        ensemble trahit le masquage — là où le full statistical_replay, qui masque TOUT,
        reste indétectable (aucune corrélation à briser)."""
        if any(a.name in ("HighAttackRate", "JailbreakSurge") for a in state.alerts):
            return None                       # une alerte à taux est active : pas de masquage
        thr = model.ATTACK_RATE_THRESHOLD
        blocked = self._recent_max(state, "blocked_rate")
        attack = self._recent_max(state, "attack_rate")
        if blocked > thr and attack < thr * 0.6:
            return Verdict(True, scope="attack_rate<->blocked_rate", heuristic="spatial_incoherence",
                           reason=(f"blocked_rate élevé ({blocked:.0f}) mais attack_rate bas "
                                   f"({attack:.0f}) : incohérence spatiale — deux signaux corrélés "
                                   f"divergent, le compteur d'attaques a été masqué (constrained replay)."))
        return None

    def _h_notification_blackhole(self, state) -> Optional[Verdict]:
        """Blocage d'indicateur au ROUTAGE (MITRE T1562.006 Indicator Blocking). Une
        alerte de sécurité est ACTIVE (la menace est réelle : son signal reste soutenu
        au-dessus du seuil, l'alerte à taux a donc dû firer), mais sa notification n'a
        JAMAIS atteint le récepteur — reroutée vers un récepteur « trou noir » ou mutée
        au niveau de la route (`route_muted`) — SANS silence ni inhibiteur pour
        l'expliquer. C'est un 4e levier de suppression, distinct de l'inhibition, du
        silence et du groupement : l'alerte aboie, mais quelqu'un a débranché le fil
        avant le récepteur. La détection est une corrélation métrique <-> livraison,
        comme recommandé pour T1562.006 (« détecter l'absence de report d'un capteur
        alors que l'activité est réelle »). Le discriminant est la CLASSE de l'alerte :
        la non-livraison d'une alerte opérationnelle (ex. PostgreSQLHighConnections
        pendant une maintenance) peut être légitime ; celle d'une alerte de sécurité
        pendant une menace soutenue ne l'est pas."""
        for a in state.alerts:
            if a.name not in model.SECURITY_RATE_ALERTS:
                continue                      # discriminant : seule une alerte de sécurité compte
            if not a.route_muted or a.silenced_by or a.inhibited_by:
                continue                      # silence/inhibition -> qualifiés par leurs heuristiques
            signal = model.ALERT_RULES.get(a.name, {}).get("signal")
            thr = model.ALERT_RULES.get(a.name, {}).get("threshold", 0.0)
            if not signal:
                continue
            # corroboration : la menace est RÉELLE et SOUTENUE (l'alerte aurait dû notifier).
            for _lbls, series in self._series(state, signal):
                if self._sustained_above(series[-_RECENT:], thr):
                    return Verdict(True, scope=f"{a.name}{{job={a.labels.get('job')}}}",
                                   heuristic="notification_blackhole",
                                   reason=(f"Alerte de sécurité {a.name} active et menace soutenue "
                                           f"(> {thr:.0f}) mais notification non délivrée (route mutée / "
                                           f"récepteur trou-noir), sans silence ni inhibiteur : blocage "
                                           f"d'indicateur au routage (T1562.006)."))
        return None

    def _h_watchdog_gap(self, state) -> Optional[Verdict]:
        """Dead man's switch (watchdog / heartbeat) déclenché — meta-monitoring. Le
        heartbeat `watchdog`, TOUJOURS émis quand la chaîne d'alerte est vivante
        (Prometheus -> Alertmanager -> livraison), a cessé pendant une période SOUTENUE :
        la chaîne elle-même est compromise, et l'ABSENCE d'alertes n'est donc plus une
        preuve d'absence de menace. C'est la dernière ligne de défense : même un
        attaquant qui aveugle parfaitement le signal d'attaque (aucune alerte, aucune
        métrique visible) est trahi par le heartbeat qui s'éteint (T1562 Impair Defenses —
        désactivation de la chaîne d'alerte). Un raté transitoire (un scrape manqué) se
        rétablit ; seule une silence d'au moins WATCHDOG_MIN_SILENCE ticks consécutifs
        en fin de fenêtre trompe le switch — sinon on paierait chaque jitter de scrape."""
        n = model.WATCHDOG_MIN_SILENCE
        for _lbls, series in self._series(state, model.WATCHDOG_SIGNAL):
            tail = series[-n:]
            if len(tail) >= n and all(v in (None, 0.0) for v in tail):
                return Verdict(True, scope="watchdog", heuristic="watchdog_gap",
                               reason=(f"Heartbeat watchdog éteint depuis >= {n} ticks : dead man's "
                                       f"switch déclenché, chaîne d'alerte compromise — l'absence "
                                       f"d'alertes n'est plus fiable (T1562 Impair Defenses)."))
        return None

    def _h_cardinality_flood(self, state) -> Optional[Verdict]:
        """DoS d'ingestion par explosion de cardinalité (MITRE Impair Defenses via épuisement
        de ressources). Un attaquant injecte un flot de séries à très haute cardinalité (labels
        uniques) ; le scrape dépasse `sample_limit` et Prometheus REJETTE le scrape entier —
        `up` passe à 0 « comme si la cible était tombée », et le vrai signal n'est jamais ingéré.
        La panne est donc INDISCERNABLE d'une vraie coupure pour les heuristiques d'absence
        (exporter_cutoff, inhibitor_isolation) — sauf que le nombre d'échantillons du scrape
        (`scrape_samples`) explose bien au-delà de toute croissance légitime (un déploiement
        n'ajoute que quelques dizaines de séries). C'est ce pic qui distingue la bombe de
        cardinalité d'une vraie panne ; alerte standard `prometheus_target_scrapes_exceeded_sample_limit_total`."""
        flood = self._recent_max(state, model.CARDINALITY_SIGNAL)
        if flood > model.CARDINALITY_FLOOD_THRESHOLD:
            return Verdict(True, scope=model.CARDINALITY_SIGNAL, heuristic="cardinality_flood",
                           reason=(f"scrape_samples={flood:.0f} > {model.CARDINALITY_FLOOD_THRESHOLD:.0f} : "
                                   f"explosion de cardinalité (bombe de séries) faisant échouer le scrape "
                                   f"(sample_limit -> up=0) et masquant le vrai signal — DoS d'ingestion."))
        return None

    def _h_guard_down_under_threat(self, state) -> Optional[Verdict]:
        """Panne INDUITE du garde (MITRE T1562.001 Disable or Modify Tools). L'attaquant
        ne falsifie rien : il met RÉELLEMENT le composant de sécurité hors service, puis
        attaque une fois la panne établie. La règle d'inhibition sanctionnée
        `FirewallDown -> classe sécurité` fonctionne alors exactement comme prévu et
        étouffe l'alerte — la règle de réduction de bruit devient l'outil du masquage.

        C'est le complément EXACT de `inhibitor_isolation`, sur le même motif de
        corroboration lu en sens inverse : là-bas la source ment (panne non corroborée =
        spoof), ici elle dit vrai (panne corroborée) et c'est précisément ce qui la rend
        indétectable par corroboration. `rogue_inhibitor` ne la voit pas non plus — la
        source est parfaitement sanctionnée. Et les heuristiques métriques s'abstiennent
        toutes dès qu'une alerte à taux est présente : elle l'est, ayant fire puis été
        inhibée. Enfin l'ORDRE de la manœuvre neutralise `exporter_cutoff`, qui exige de
        l'activité AVANT le trou de collecte : couper le garde d'abord vide cette fenêtre.

        Le discriminant n'est PAS la panne du garde — une maintenance de firewall est une
        opération banale et planifiée — mais sa CONCOMITANCE avec une menace réelle et
        SOUTENUE au-dessus du seuil. Sans ce garde, toute maintenance deviendrait un faux
        positif et l'heuristique serait désactivée en exploitation (alert fatigue)."""
        for src in state.alerts:
            if src.name not in model.SECURITY_GUARD_SOURCES:
                continue
            corr = model.INHIBITOR_CORROBORATION.get(src.name)
            if not corr:
                continue
            corr_filter = {"job": src.labels["job"]} if src.labels.get("job") else None
            if not self._is_recently_down(state, corr, corr_filter):
                continue          # panne NON corroborée -> spoof, qualifié par inhibitor_isolation
            for tgt in state.alerts:
                if tgt.name not in model.SECURITY_RATE_ALERTS:
                    continue      # seule la classe sécurité compte : le garde protège ça
                if not any(ib.startswith(src.name) for ib in tgt.inhibited_by):
                    continue
                signal = model.ALERT_RULES.get(tgt.name, {}).get("signal")
                thr = model.ALERT_RULES.get(tgt.name, {}).get("threshold", 0.0)
                if not signal:
                    continue
                for _lbls, series in self._series(state, signal):
                    if self._sustained_above(series[-_RECENT:], thr):
                        return Verdict(True, scope=f"{src.name}->{tgt.name}",
                                       heuristic="guard_down_under_threat",
                                       reason=(f"{src.name} corroborée ({corr}=0) inhibe légitimement "
                                               f"{tgt.name}, mais la menace est RÉELLE et soutenue "
                                               f"(> {thr:.0f}) pendant la panne : le garde a été mis "
                                               f"hors service puis l'attaque a suivi — l'inhibition "
                                               f"sanctionnée sert de couverture (T1562.001)."))
        return None

    # -- interface ------------------------------------------------------------
    def detect(self, state: SupervisionState, trace: Trace) -> Verdict:
        for h in (self._h_inhibitor_isolation, self._h_rogue_inhibitor,
                  self._h_guard_down_under_threat,
                  self._h_notification_blackhole,
                  self._h_flapping, self._h_phantom_clear,
                  self._h_low_and_slow, self._h_silence_abuse, self._h_signal_blackout,
                  self._h_cardinality_flood, self._h_exporter_cutoff,
                  self._h_frozen_replay, self._h_spatial_incoherence,
                  self._h_watchdog_gap):
            verdict = h(state)
            if verdict is not None:
                return verdict
        return Verdict(False, reason="Aucun motif de masquage détecté.")
