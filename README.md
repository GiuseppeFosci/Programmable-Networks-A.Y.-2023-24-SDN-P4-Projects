# P4 Distributed Consensus

Rete programmabile in P4 con meccanismo di consenso distribuito. Ogni switch esprime un voto (`ALLOW`, `DENY`, `ABSTAIN`) in base agli ultmini due bit meno significativi e al timestamp attuale. 
Il voto viene accumulato lungo il percorso, per poi determinare una decisione finale nell'ultimo nodo.

## Architettura

- Nodi: `S1`, `S2`, `S3`, `S4`
- Tutti eseguono lo stesso programma `ipv4.p4`, con logiche che cambiano a seconda del ruolo del nodo.
- I voti sono salvati in header custom e aggiornati a ogni hop.

## File principali

- `ipv4.p4`: logica P4 del voto presente in ogni hop
- `h1/send.py`: per inviare un singolo pacchetto con header custom in direzione h2 

## Esecuzione

1. Nella directory del progetto esegui  (`kathara lstart`)
2. Attendi avvio dei device katharà
4. Nel terminale di H1 esegui il comando  (`python3 send.py`)
5. Si creeranno 4 file di log nella cartella (`Shared`), dove in quella di S4 è possibile vedere l'esito della votazione.



