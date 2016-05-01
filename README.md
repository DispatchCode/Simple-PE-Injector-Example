# README #

*InjMyPe* nasce dall'idea di un articolo dedicato interamente al PE Header. Lo scopo di questo codice è quello di verificare la correttezza dell'header, aggiungere poi una nuova SECTION al PE ed iniettare al suo interno del codice così da eseguirlo all'avvio. Fatto ciò modifica l'EP del programma (nel PE Header) e setta il nuovo codice iniettato come EP. Al termine del codice iniettato è presente un salto al vecchio EP.


**Linguaggio:** Assembly (MASM)

**Target OS:** Windows

**CPU:** >= i386


### Compilazione e Linking ###

```
#!

ml /c /coff file.asm
link /SUBSYSTEM:CONSOLE file.obj
```

Il file exe è incluso nella cartella **bin**.


### Funzionamento ###

Più dettagliatamente, il software svolge i seguenti controlli:
1. Lettura DOS Header e verifica validità; è valido se la signature è uguale a **MZ**;
2. Lettura dell'NT Header; se la signature dell'IMAGE_NT_HEADERS è uguale a **PE** è valido;
3. Aggiunta di una sezione (.injcode) di 1000byte;
4. Iniezione delle stringhe nella sezione .DATA (titolo e testo della MessageBox) e salvataggio dei relativi offset;
5. Ricerca dell'indirizzo della funzione, e se presente nella IAT verrà salvato l'offset;
6. Code injection dello shellcode

Il codice macchina iniettato è il seguente:

```
#!assembly

; 90h                              NOP
; 90h                              NOP
; 90h                              NOP
; 68h      00h 00h 00h 00h         PUSH 00000000h
; 68h      xxh xxh xxh xxh         PUSH [xxxxxxxx]         ; Indirizzo titolo
; 68h      xxh xxh xxh xxh         PUSH [xxxxxxxx]         ; Indirizzo testo
; 68h      00h 00h 00h 00h         PUSH 00000000h
; 0FFh 15h xxh xxh xxh xxh         CALL [xxxxxxxx]         ; (MessageBoxA)
; 0E8h     xxh xxh xxh xxh         CALL [ModuleEntryPoint] ; (EP Originale)
; 90h                              NOP
```

La parima parte è il codice macchina, quella a seguire la relativa corrispondenza con assembly. Le *x* indicano che quell'indirizzo non è ancora presente; infatti viene calcolato dal software prima dell'iniziezione, così come l'indirizzo della MessageBoxA che non è conosciuto sino al momento della lettura della tabella delle JMP.

E' importante osservare che l'indirizzo della MessageBoxA utilizzato non è quello della posizione in memoria della medesima, ma l'offset in VA interno al file. Questo perchè ad un prossimo avvio della macchina quella libreria si troverà (con buonissime probabilità) ad un altro indirizzo. Il codice salta quindi all'interno della *jump table*.

### Funziona con qualsiasi exe? ###
**No.** Funziona su molti software, anche commerciali. Tuttavia dipende da alcuni fattori: uno di essi ad esempio è la rilocazione. Un altro è la sezione CERTIFICATE.

### Avvertenze ###
Prima di utilizzarlo su un exe, è raccomandato fare prima un backup dello stesso. Non mi assumo nessuna responsabilità su usi scorretti o danni causati (per evitarli, è appunto bene backuppare prima l'exe).

## Screenshot ##

*Ecco l'esempio su un software (ne censuro il nome)*
![2016-05-01_174725.png](https://bitbucket.org/repo/ok947j/images/3398532942-2016-05-01_174725.png)