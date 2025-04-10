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



# SDN Mobility Management Project

Questo progetto implementa un meccanismo di **mobilità degli utenti** in una rete SDN, evitando il ricalcolo completo dei percorsi al gateway (con algoritmo Dijkstra) e minimizzando il numero di link modificati durante il cambio di access point.

## Architettura

- **Controller SDN (POX)**: gestisce la rete e coordina il cambiamento dei percorsi.
- **Switch (OpenFlow)**: configurabili per instradare i pacchetti in base alle regole decise dal controller.
- **Modulo `user_mobility`**: gestisce la logica del cambiamento di access point per ogni host.

## File principali

- `controller.py`: Si occupa di avviare tutti i moduli necessari.
- `user_mobility.py`: modulo per la gestione della mobilità degli host.
- `mobility.py`: Simula lo spostamento dell'host ogni 10 secondi viene attivata una interfaccia e disattivate tutte le altre.

## Esecuzione

1. Avvia katharà con (`kathara lstart`)
2. Nel terminale del controller andare sulla direcory (`cd home/pox`) e avviare il controller con (`./pox.py controller`)
3. Nel terminale di H1 avviare il programma python presente nella directory home (`python3 mobility`)
