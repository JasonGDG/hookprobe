# hookprobe — Spezifikation v0.1

Prüft, ob die Hooks von Claude Code **tatsächlich wirken** — nicht, ob sie konfiguriert sind.

> **Stand.** Dies ist die Entwurfsspezifikation vom 22.09.2026, bewusst unverändert gelassen, damit sich
> Entwurf und Ergebnis vergleichen lassen. Was seitdem dazukam und wo der Entwurf danebenlag, steht im
> README (`--watch`, `--record`, `--ask`, „Against other people's setups") und in KNOWN-ISSUES.md.
> Zwei Abweichungen vom Entwurf: jeder Handler wird im Standardlauf **fünfmal** ausgeführt, nicht einmal
> (Ablehnungsprobe, Determinismus, Köder); und die Effektivität wird nicht je Hook, sondern je Kanal
> gemessen (hookprobes eigener Deny-Hook gegen einen Kontrolllauf).

## Leitsatz
Konfiguriert und wirksam sind zwei verschiedene Eigenschaften; heute ist nur die erste beobachtbar
(anthropics/claude-code#82323). Fail-open ist dokumentiertes Verhalten: „a mistyped path in settings.json
leaves the gate silently disabled" und „Claude Code treats exit code 1 as a non-blocking error and proceeds
with the action". In #81458 blieben 6 865 Fehlstarts in einer Sitzung unbemerkt.

## Zwei Stufen
1. **Standardlauf (offline, kostenlos, deterministisch)** — führt jeden konfigurierten Hook genau so aus,
   wie der Harness es täte, und misst, ob er startet, antwortet und blockieren KÖNNTE. Kein API-Schlüssel,
   keine Tokens, kein Netz.
2. **`--live` (opt-in, kostet zwei echte Sitzungen)** — Kanarienlauf gegen `claude -p` plus Kontrolllauf
   ohne Hooks; misst über **Nebenwirkungen**, ob das Verdikt den Aufruf verändert hat.

## Warum Nebenwirkungen und nicht Harness-Ereignisse
Gemessen über 36 `claude -p`-Läufe (#94275): `hook_started`/`hook_response` erscheinen im stream-json **nur**
für SessionStart. Die Wirksamkeit muss deshalb an einer Spur gemessen werden, die der Hook selbst hinterlässt
(Markerdatei) bzw. am ausgebliebenen Ergebnis des Werkzeugaufrufs. Verlässlichster Zusatzkanal: `--debug-file`.

## Prüfungen (Standardlauf)
- **P01 Startbarkeit** (höchste Priorität, 11 belegte Fälle). Für jeden Hook-Befehl: Datei vorhanden?
  Ausführungsrecht? Shebang vorhanden und Interpreter existiert? Pfad mit Leerzeichen, den `/bin/sh`
  wortspaltet (#39478, Exit 127)? Relativer Pfad, der vom Arbeitsverzeichnis abhängt?
  Ausführung mit realistischem stdin-Objekt und kurzem Timeout. Ergebnis: startet / startet nicht (= Tor offen)
  / startet und bricht ab.
- **P08 Exit-Code-Semantik.** Nur Exit 2 blockiert. Ein Hook, der bei Ablehnung `exit 1` benutzt, blockiert nie
  (dokumentiert). Statisch (Quelltext-Heuristik) plus Ausführung mit einem Payload, der eine Ablehnung auslösen soll.
- **P09 JSON-Form.** stdout muss ein einzelnes JSON-Objekt sein. Vorlauf aus dem Shell-Profil (Begrüßungstext)
  zerstört die Auswertung — erkennen und melden.
- **P07 Ausgabekappung.** `additionalContext`, `systemMessage`, `initialUserMessage` und einfaches stdout werden
  bei 10 000 Zeichen gekappt (Datei + 2 000 Zeichen Vorschau, und Claude liest die Datei nicht). Länge messen, warnen.
- **P03 Schema-Wächter.** Ein einziger schemawidriger Matcher schaltet **alle** settings.json-Hooks ab (#75071).
  Ereignisnamen gegen die 33 dokumentierten prüfen; unbekannte Ereignisse als kritisch melden.
- **P04 Matcher.** Ereignisse ohne Matcher-Unterstützung: UserPromptSubmit, PostToolBatch, Stop, TeammateIdle,
  TaskCreated, TaskCompleted, WorktreeCreate, WorktreeRemove, MessageDisplay, CwdChanged. Ein Matcher dort ist
  wirkungslos. Sonst: trifft der Matcher überhaupt einen bekannten Werkzeugnamen?
- **P05 Ablageort.** Herkunft je Hook ausweisen (managed / user / project / local / plugin / agent-frontmatter /
  skill-frontmatter) und die belegt schwachen Orte markieren: Agent-Frontmatter (#95650 tot), Skill-Frontmatter
  (#95280 `once:true` wirkungslos), Desktop-Tab (#95833 feuert nie).
- **P10 Timeout.** Hook, der auf stdin blockiert, läuft ins Timeout — und ein ins Timeout gelaufener PreToolUse-Hook
  blockiert laut Doku **nicht**. Mit leerem stdin ausführen und Laufzeit messen.

## Prüfungen (--live)
- **P02 Schlägt deny durch?** Kanarienlauf in einem leeren Wegwerfverzeichnis: ein Hook, der einen harmlosen,
  eindeutig markierten Befehl blockieren soll; Kontrolllauf ohne Hooks. Wirksam = im Kontrolllauf passiert die
  Nebenwirkung, im Hook-Lauf nicht.
- **P06 Kanal.** Denselben Kanarienlauf in den verfügbaren Betriebsarten (interaktiv nicht nötig für v0.1;
  `-p` und `--output-format stream-json`) und vergleichen. Beleg: #95726 (ask wird headless still zu deny).

## Ausgabe
Tabelle je Hook: Ereignis · Matcher · Quelle · **startet** · **antwortet** · **kann blockieren** · (mit `--live`) **wirksam**.
Darunter die Zusammenfassung „N von M Hooks schützen nichts" und je Fund eine Zeile mit Ursache und Reparatur.
`--explain <hook>` zeigt den vollständigen Befund samt Belegnummer. `--json` für Maschinen. Exit-Code 1, wenn ein
Hook als wirkungslos erkannt wurde (damit man es vor den Start hängen kann).

## Ehrliche Grenzen (gehören in README und in die Ausgabe)
Ein Testlauf beweist den Moment des Tests, nicht die Zukunft. Nicht erkennbar: zeitabhängige Ausfälle
(#16047 — ein auf 48 GB gewachsenes Log; #76322 — Hook hört mitten in der Sitzung auf), Zustandswechsel nach dem
Test (#95440 — ein `cd` beendet den FileChanged-Watcher für die Restsitzung), Nebenläufigkeit (#95474 last-write-wins),
ein Hook, der sich selbst löscht (#32990), intermittierende Ausfälle (#90296 — 30 Minuten weg, dann von selbst wieder da).
Und: Die Sonde misst ihre eigene Umgebung, nicht die des Nutzers (#85613 — der Ablageort entscheidet).

## Abgrenzung zu vorhandenen Werkzeugen (alle MIT, alle 0 Sterne, Stand 22.09.2026)
- `kVadrum/hookprobe` — führt Hooks mit synthetischen Eingaben aus (Mock). Keine Verdrahtung, keine Wirksamkeit.
- `drakeo338/hookprobe` — statischer Konfigurations-Linter. Kein Lauf.
- `Tomdachs/agent-hook-probe` — Wegwerf-Arbeitsverzeichnisse gegen echte Laufzeiten, Claude-Adapter auf einem
  Branch. Prüft, **dass** Hooks feuern; kein Kontrolllauf, kein blockierender Kanarien.
- Anthropic `plugin-dev/skills/hook-development/scripts/test-hook.sh` — „Tests a hook with sample input",
  wertet den Matcher nie aus. `/hooks` ist „a read-only browser".
hookprobe deckt als einziges die Wirksamkeit ab.

## Technik
Python 3.11+, **nur Standardbibliothek**. Start über `uvx hookprobe` bzw. `pipx`/`pip install hookprobe`.
Konsolenskript `hookprobe`. Tests mit `unittest`. Kein Netz im Standardlauf. Keine Schreibzugriffe außerhalb
eines temporären Verzeichnisses. Lizenz MIT.
