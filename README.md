## 1. SDN User Mobility

### Descrizione
Questo progetto implementa un meccanismo di mobilità per gli host in una rete SDN, evitando il ricalcolo completo del percorso ogni volta che un host cambia Access Point. L’obiettivo è aggiornare la rete in modo minimale, modificando solo i link necessari tra il vecchio e il nuovo percorso, a partire dal gateway.


### Architettura
La rete è composta da:
- Switch S1-S2-S3-S4 
- Un gateway per l’accesso a Internet
- Host mobili che possono cambiare punto di accesso (Access Point) implementati come bridge

Il controller gestisce i flussi e monitora la posizione degli host. Quando un host si sposta, il modulo `user_mobility` aggiorna dinamicamente solo la parte finale del percorso, riutilizzando quanto più possibile il cammino precedente.

### Funzionalità principali
- Calcolo iniziale dei percorsi con Dijkstra, idea è quella di calcolare la prima volta l'intero percorso usando Djkstra, e le volte successive usando Djkstra ma solo nel subgraph.

### Avvio
- Nel terminale del controller eseguire `cd home/pox`
- Per avviare il controller, esegui `./controller.py` nel terminale.
- Nel terminale di H1 eseguire `cd home` e `moblity.py`

## 2. P4 Distributed Consensus

### Descrizione
Questo progetto dimostra come implementare un meccanismo di consenso distribuito nel piano dati usando P4. Ogni switch intermedio esprime un’opinione riguardo al trattamento di un pacchetto. L’opinione viene registrata nel pacchetto stesso, che accumula le decisioni lungo il percorso.
Alla fine il nodo di uscita decide se inoltrare o scartare il pacchetto in base ai voti esperessi.

### Obiettivo
Simulare un sistema in cui ciascuno switch vota sull’azione da intraprendere per un pacchetto. L’ultimo nodo del percorso aggrega le opinioni e prende la decisione finale.

### Avvio
-Nel terminale di H1 eseguire `cd home` e `send.py`

### Opinioni ammesse
- `1`: Permettere il transito del pacchetto
- `-1`: Bloccare il pacchetto
- `0`: Astenuto

### Funzionamento

- Ogni switch legge i campi del pacchetto e scrive la propria opinione.
- Il pacchetto trasporta le opinioni lungo il percorso.
- Alla fine, lo switch finale applica una logica di consenso basata sulle opinioni ricevute.

