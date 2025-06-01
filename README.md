# 🔍 Hash Check Tool

Ein einfaches Python-Skript zur Analyse von Hashes mit:
- [VirusTotal](https://www.virustotal.com/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)

## Voraussetzungen

- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -U pip`
- `pip install -r requirements.txt`

## Eingabe

Erstelle eine Datei `hashes.txt` mit einem Hash pro Zeile, z. B.:

```bash
04ab716eacfefbe5dc41cf04d169ea0e745c6baafd731d800f7c257ac01696fa
2546359770f46f8cc28b614ecf18387bb5c07c635e4ddd9211740a82eb01ce99
f70d8b4f3d1fb28c15dee04858d0e7c5b656f17c6588ed5fad52855181680653
59792aeb530bcd19011933f1b7c597c139920040794d24cee75e7c3114fbabf8
```


## Verwendung

1. Erstelle eine `.env` Datei im Projektverzeichnis und trage API-Keys sowie weitere Variablen ein (siehe `.env.template`).
2. Führe das Skript aus: `python3 hash_check.py`
3. Die Ergebnisse werden in zwei Formaten gespeichert:
   - `output-hash-check.txt`: gut lesbare Analyse
   - `output-hash-check.csv`: strukturierte Übersicht für z. B. Excel

## Hinweise

- Das Skript beachtet das Rate-Limit von VirusTotal (4 Anfragen/Minute). 
- Links zu den Plattformen werden angezeigt, sofern der Hash dort vorhanden ist. 
- Bei unbekannten Hashes erfolgt ein entsprechender Hinweis, ohne Analyseinhalt.