# Forensics Toolkit

Dette prosjektet er et modulært verktøysett for digital forensics. Målet er å gi et praktisk rammeverk for analyse av filer, metadata, logger og hendelser – strukturert på samme måte som profesjonelle DFIR-miljøer arbeider.  

Toolkit'et består av flere selvstendige moduler, som kan brukes hver for seg eller kombineres i større analyser.

---

## Innhold

- **signature_checker.py** — analyserer filsignaturer og avdekker mismatch mellom filtype og innhold.
- **hash_verifier.py** — beregner og sammenligner SHA-256-hash for å avdekke modifikasjoner.
- **metadata_extractor.py** — henter ut EXIF-metadata fra bilder og støtter videre utvidelser.
- **log_parser.py** — regex-basert analyse av loggfiler (IP-adresser, tidsstempler, mistenkelige linjer).
- **timeline_builder.py** — kombinerer hendelser fra flere analyser i en strukturert tidslinje.
- **utils/** — hjelpefunksjoner for hashing, filhåndtering m.m.
- **samples/** — eksempeldata som kan brukes for testing.

---

## Prosjektstruktur

    forensics_toolkit/
    │
    ├── signature_checker.py
    ├── hash_verifier.py
    ├── metadata_extractor.py
    ├── log_parser.py
    ├── timeline_builder.py
    │
    ├── utils/
    │ ├── file_utils.py
    │ └── hash_utils.py
    │
    ├── samples/
    │ ├── images/
    │ ├── documents/
    │ └── logs/
    │
    └── README.md

---

## Installasjon

Prosjektet bruker et virtuelt miljø (`venv`) for å installere eksterne avhengigheter trygt.

### 1. Opprett og aktiver venv
    python3 -m venv venv
    source venv/bin/activate


### 2. Installer avhengigheter
    pip install -r requirements.txt


Avhengigheter:
- `Pillow` — nødvendig for metadata-extractor
- `scapy` — brukes i nettverksmoduler (ren sandbox-integrasjon)

---

## Bruk

### Filtypeanalyse (signature_checker)
    python3 signature_checker.py samples/images/test.png


Gir:
- rå headerbytes
- gjenkjent filsignatur
- indikasjon på om filen er maskert eller modifisert

### Hash-sammenligning
    python3 hash_verifier.py file1.bin file2.bin


Viser:
- SHA-256-hash for begge filer
- om filene er identiske eller endret

### Metadata-uttrekk
    python3 metadata_extractor.py samples/images/photo.jpg


Gir EXIF-metadata hvis tilgjengelig.

### Logganalyse
    python3 log_parser.py samples/logs/example.log

Identifiserer:
- tidsstempler
- IP-adresser
- mistenkelige eller relevante linjer

### Tidslinjebygger
Denne modulen kombinerer analyser i en kronologisk struktur når JSON-data foreligger.

---

## Videre arbeid

Prosjektet er designet for å kunne bygges ut videre med:

- deteksjon av embedded filer
- flere filsignaturer (MP4, DOCX, XLSX, APK, Mach-O, PE etc.)
- YARA-regler
- PDF- og DOCX-parser
- helautomatisert CLI for komplette analyser
- visuelt GUI for tidslinjeanalyse

---

## Formål

Dette verktøysettet er utviklet for å trene på praktisk digital forensics og gir erfaring med:

- filanalyse og identifikasjon
- hashing og integritetssjekker
- metadata og spor i filer
- logganalyse og hendelsesforståelse
- datastrukturering for sikkerhetsanalyser

Prosjektet gir et realistisk innblikk i hvordan hendelser og artefakter undersøkes i profesjonelle cyber- og etterretningsmiljøer.

---
