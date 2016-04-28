; ###############################################################################;
; DESCRIPTION: Il codice seguente e' un esempio di Injection utilizzando Assembly.
;            : Al momento il programma inietta due stringhe (titolo e testo della
;            : MessageBoxA) più uno shellcode per far apparire la MessageBoxA.
;            :
;            :     IL CODICE E' ALLEGATO ALL'ARTICOLO SUL PE HEADER
;            :
;            : Ho pensato di distribuirlo come source/programma in quanto con
;            : qualche modifica puo' diventare qualcosa di più di un semplice
;            : esempio. Infatti l'idea sarebbe questa...
;            : Costituirebbe inoltre una versione 2 di "PE Analyzer"
; -------------------------------------------------------------------------------;
; COMPILATION: ml /c /coff file.asm
; LINKING    : link /SUBSYSTEM:CONSOLE file.obj
; -------------------------------------------------------------------------------;
; AUTHOR     : Marco 'RootkitNeo' C.
; -------------------------------------------------------------------------------;
; LANGUAGE   : MASM32 (CUI Application)
; -------------------------------------------------------------------------------;
; NAME       : InjMyPE
; -------------------------------------------------------------------------------;
; VERSION    : 1.0.1 
; -------------------------------------------------------------------------------;
; LICENSE    : GNU/GPL V.3
; ###############################################################################;


include        c:\masm32\include\masm32rt.inc

.const
FILE_NAME_LENGTH      =        20
MODULE_NAME_STRING    =        20

.data

; Codice macchina:
; ========================================================================
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
; =======================================================================
dbShellcode                db        90h,90h,90h,68h,00h,00h,00h,00h,68h,00h,00h,00h,00h,68h,00h,00h,00h,00h,68h,00h,00h,00h,00h,0FFh, 15h, 00h,00h,00h,00h,0E8h,00h, 00h, 00h, 00h,90h

; CALL E8: indirizzo a cui vuoi saltare - indirizzo attuale - 5

szMenu0               db        9,"***************************************************************",13,10,
                                9,"*     MessageBox Injection [Example] | Marco 'RootkitNeo'     *",13,10,
                                9,"*-------------------------------------------------------------*",13,10,0
szMenu1               db        9,"*  Al momento il source e' allegato all'articolo relativo al  *",13,10,
                                9,"*  PE header, ma in futuro penso di continuare lo sviluppo    *",13,10,
                                9,"*  al fine di renderlo magari piu' interessante ed utile...   *",13,10,
                                9,"***************************************************************",13,10,0

szFileInput           db        9,"Inserisci il nome del file exe (completo di estensione): ",0

szDllLibraryName      db        "user32.dll",0
szFunctionName        db        "MessageBoxA",0

szSectionName         db        ".injcode",0
ddSectionSize         dd        1000

dbFileReadString      db        9,"File letto con successo!",13,10,0
dbValidDosString      db        9,"MZ - DOS Header Valido!",13,10,0
dbValidNtString       db        9,"Signature - NT Header Valido!",13,10,0
szSectionAdded        db        9,"Aggiunta della sezione .injcode. Size: 1000byte",0

szTextMessage         db        "Testo iniettato della MessageBoxA.",0
szTitleMessage        db        "Injection di Esempio",0

szAddressTitle        db        9,"VA all'indirizzo del titolo: 0x",0
szAddressText         db        9,"VA all'indirizzo del testo: 0x",0
szAddressFunc         db        9,"VA all'indirizzo della funzione: 0x",0


crlf                  db        13,10,0

counter1              db        0

.data?

dbTempBuffer          db            16           dup(?)
  
dbBuffer              db            8            dup(?)
dbSectionName         db            9            dup(?)

dbFileName            db    FILE_NAME_LENGTH     dup(?)
dbModuleName          db    MODULE_NAME_STRING   dup(?)

dwFileSize            DWORD               ?
dwByteRead            DWORD               ?

dwBaseAddress         DWORD               ?

hFile                 DWORD               ?

dwOriginalEP          DWORD               ?
dwImageBase           DWORD               ?
dwPointerToData       DWORD               ?
dwPointerToCode       DWORD               ?
dwSizeOfData          DWORD               ?
dwSizeOfCode          DWORD               ?
dwRvaToData           DWORD               ?
dwRvaToCode           DWORD               ?

dwTextAddress         DWORD               ?   ; VA al testo della finestra
dwTitleAddress        DWORD               ?   ; VA al titolo della finestra
dwFunctionAddress     DWORD               ?   ; VA all'indirizzo della finestra (MessageBox)

.code


start:


call main

print  offset  crlf

inkey

invoke         ExitProcess,0

; -------------------------------------------------------

; Main Procedure
; -------------------------------------------------------
main      proc
  call          ClearScreenAndColor
  
  print  offset szMenu0
  print  offset szMenu1
  
  print  offset crlf
  print  offset crlf
  
  print  offset szFileInput
  invoke        StdIn, offset dbFileName, FILE_NAME_LENGTH
_go_back:

  ; Apertura del file su disco
  call          loadFile
  
  .IF eax != 0
    jmp         _exit
  .ENDIF
    
  print  offset   crlf
  print  offset   dbFileReadString
  
  ; Verifica validita' DOS Header
  call          readDosHeader
  
  .IF eax != 0
    jmp         _exit
  .ENDIF
  
  print         offset   dbValidDosString
  
  ; Verifica validita' NT Header
  call          readNtHeader
  
  .IF eax != 0
    jmp         _exit
  .ENDIF
  
  print         offset   dbValidNtString
  print         offset   crlf
  
  ; Al primo avvio devo inserire una nuova sezione.
  ; Per non richiedere il file di nuovo, chiudo gli
  ; handle saltando ad _exit e poi salto nuovamente
  ; in cima
  .IF counter1 == 0
    call          addSection
    
    print  offset crlf
    print  offset szSectionAdded
    print  offset crlf
    jmp           _exit
  .ENDIF
  
  ; Giunti a questo punto, possiamo iniziare a leggere le informazioni dall'header
  ; e soprattutto a salvare le informazioni che dovranno essere utilizzate in seguito
  ; come ad esempio l'entry point originale del programma (AddressOfEntryPoint)
  call          storeHeaderInformation
  
  ; Iniezione delle due stringhe in .DATA
  call          injectCodeInData
  
  print         offset szAddressText
  ; VA al titolo della finestra
  invoke        RtlZeroMemory,addr dbTempBuffer,16
  invoke        dw2hex, dwTextAddress, addr dbTempBuffer
  print         offset dbTempBuffer

  print  offset crlf
  
  print offset  szAddressTitle
  ; VA all testo della finestra
  invoke        RtlZeroMemory,addr dbTempBuffer,16
  invoke        dw2hex, dwTitleAddress, addr dbTempBuffer
  print  offset dbTempBuffer
  print  offset crlf
  
  ; Indirizzo funzione
  mov           eax, offset szDllLibraryName
  mov           edx, offset szFunctionName
  call          findFunctionAddress
  
  ; Se la variabile e' a 0 la funzione non e' presente nella IAT
  .IF dword ptr [dwFunctionAddress] == 0
    print         "Funzione non presente, impossibile procedere.",0
    jmp           _exit
  .ENDIF
  
  print  offset szAddressFunc
  
  invoke        RtlZeroMemory,addr dbTempBuffer,16
  invoke        dw2hex,dwFunctionAddress, addr dbTempBuffer
  print offset  dbTempBuffer
  
  ; Shellcode!
  call          injectCode
  
  print offset  crlf
  print offset  crlf
  
  .IF  eax == 0
    print         "Si sono verificati problemi con il salvataggio.",0
  .ELSE
    print         "Salvataggio andato a buon fine!",0
  .ENDIF    
  
_exit:
  invoke        GetProcessHeap
  invoke        HeapFree, eax, 0, dwBaseAddress
  invoke        CloseHandle, hFile
  
  .IF counter1 == 0
    inc           counter1
    jmp           _go_back
  .ENDIF
  
  ret
main      endp
; ---------------------------------------------------------------------------------------------
;


; Apertura del file
; In caso di errori EAX contiene un valore > 0
; ---------------------------------------------------------------------------------------------
loadFile   proc
  
  invoke        CreateFile, addr dbFileName, GENERIC_READ or GENERIC_WRITE ,FILE_SHARE_READ OR FILE_SHARE_WRITE,0, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
  
  .IF   eax == INVALID_HANDLE_VALUE
    mov         eax, 1
    ret
  .ENDIF
  
  mov           hFile, eax
  
  invoke        GetFileSize, eax, 0
  mov           dwFileSize, eax
  
  invoke        GetProcessHeap
  invoke        HeapAlloc, eax, HEAP_NO_SERIALIZE + HEAP_ZERO_MEMORY, dwFileSize
  
  .IF   eax == NULL
    mov         eax, 2
    ret
  .ENDIF
  
  mov           dwBaseAddress, eax
  
  invoke        ReadFile, hFile, dwBaseAddress, dwFileSize, addr dwByteRead,0
  
  .IF   eax == 0
    mov         eax, 3
    ret
  .ENDIF
  
  mov           eax, 0
  ret

loadFile   endp
; -----------------------------------------------------------------------------------------------
;


; Read the DOS header
; ; ---------------------------------------------------------------------------------------------
readDosHeader   proc
  xor           esi, esi
  
  mov           esi, dwBaseAddress
  assume        esi:ptr IMAGE_DOS_HEADER
  
  .IF [esi].e_magic != IMAGE_DOS_SIGNATURE
    mov         eax, 1
    ret
  .ENDIF
 
  mov           eax, 0
  
  ret

readDosHeader   endp
; ---------------------------------------------------------------------------------------------
;
 
; Read NT Header
; --------------------------------------------------------------------------------------------- 
readNtHeader    proc 
  call          readDosHeader
  add           esi, [esi].e_lfanew
  assume        esi:ptr IMAGE_NT_HEADERS
  
  .IF  [esi].Signature != IMAGE_NT_SIGNATURE
    mov           eax, 1
    ret
  .ENDIF
  
  mov           eax, 0
  
  ret
  
readNtHeader    endp
; ---------------------------------------------------------------------------------------------

; Aggiunta di una nuova sezione chiamata ".injcode", con relativa dimensione di 1000byte
; La dimensione e' esagerata per i nostri scopi... ma potrebbe servire anche in futuro
; ---------------------------------------------------------------------------------------------
addSection      proc  uses   esi eax
  LOCAL         dwAlignment:DWORD
  LOCAL         dwFileAlignment:DWORD

  call          readNtHeader
  add           esi, 4
  assume        esi:ptr IMAGE_FILE_HEADER
  
  ; Incremento il numero delle sezioni
  mov           cx, [esi].NumberOfSections
  inc           cx
  mov           [esi].NumberOfSections, cx
  movzx         ecx, cx
  dec           ecx
  
  add           esi, sizeof IMAGE_FILE_HEADER
  assume        esi:ptr IMAGE_OPTIONAL_HEADER
  ; Qui dobbiamo calcolare l'allineamento
  push          [esi].SectionAlignment
  pop           dwAlignment
  push          [esi].FileAlignment
  pop           dwFileAlignment
  
  mov           eax, [esi].SectionAlignment 
  mov           edx, ddSectionSize
  call          Alignment
  add           [esi].SizeOfImage, eax
  
  ; Punto all'ultima sezione
  add           esi, sizeof IMAGE_OPTIONAL_HEADER
  mov           eax, sizeof IMAGE_SECTION_HEADER
  mul           ecx
  add           esi, eax
  assume        esi:ptr IMAGE_SECTION_HEADER

  invoke        RtlZeroMemory, esi,IMAGE_SIZEOF_SECTION_HEADER

  ; Copio il nome della sezione
  invoke        RtlMoveMemory, addr [esi].Name1, addr szSectionName,8
  mov           edi, esi
  ; Punto alla penultima sezione (quella precedente a quella che sto inserendo)
  sub           edi, sizeof IMAGE_SECTION_HEADER
  assume        edi:ptr IMAGE_SECTION_HEADER
  
  mov           eax, dwAlignment
  mov           edx, [edi].VirtualAddress
  add           edx, [edi].Misc.VirtualSize
  call          Alignment
  mov           [esi].VirtualAddress, eax
  ; Dimensione della sezione
  push          ddSectionSize
  pop           [esi].Misc.VirtualSize
  
  ; Verifico l'allineamento della sezione precedente...
  xor           edx, edx
  mov           eax, [edi].SizeOfRawData
  mov           ebx, dwFileAlignment
  div           ebx
  
  ; Se la divisione ha dato resto, devo allineare
  .IF    edx != 0
    mov           eax, dwFileAlignment
    mov           edx, [edi].SizeOfRawData
    call          Alignment
    mov           [edi].SizeOfRawData, eax
    
    mov           eax, [edi].PointerToRawData
    add           eax, [edi].SizeOfRawData
    
    invoke        SetFilePointer, hFile, eax, NULL, FILE_BEGIN
    
    invoke        SetEndOfFile, hFile
  .ENDIF
  
  ; Indirizzo ai dati 
  invoke        GetFileSize, hFile, NULL
  mov           [esi].PointerToRawData, eax
  
  ; Dimensione dei dati
  mov           eax, dwFileAlignment
  mov           edx, ddSectionSize
  call          Alignment
  
  mov           [esi].SizeOfRawData, eax
  
  ; Salvo le info sul codice che utilizzero' piu' avanti
  push          [esi].PointerToRawData
  pop           dwPointerToCode
  push          [esi].SizeOfRawData
  pop           dwSizeOfCode
  push          [esi].VirtualAddress
  pop           dwRvaToCode
  
  ; Settiamo le caratteristiche
  ; IMAGE_SCN_MEM_READ       (lettura)
  ; IMAGE_SCN_MEM_EXECUTE    (esecuzione)
  ; IMAGE_SCN_MEM_WRITE      (scrittura)
  mov           [esi].Characteristics, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE  or IMAGE_SCN_CNT_CODE
  
  invoke        SetFilePointer, hFile, [esi].SizeOfRawData, NULL, FILE_END
  invoke        SetEndOfFile, hFile
  
  invoke        SetFilePointer, hFile, 0, NULL, FILE_BEGIN
  invoke        WriteFile, hFile, dwBaseAddress,dwFileSize, addr dwByteRead, NULL

  
  
  ret

addSection      endp
; ---------------------------------------------------------------------------------------------





; Salvo le informazioni che utilizzero' nel resto del programma
; ---------------------------------------------------------------------------------------------
storeHeaderInformation  proc uses edx esi
  ; Cerco la sezione ai dati inizializzati    IMAGE_SCN_CNT_INITIALIZED_DATA
  mov            edx, IMAGE_SCN_MEM_WRITE
  call           offsetToSection
  
  .IF eax != 0
    mov            dwPointerToData, eax
    mov            dwSizeOfData, edx
    mov            dwRvaToData, ebx
  .ENDIF
  
  call           readNtHeader
  add            esi, 4 + sizeof IMAGE_FILE_HEADER
  assume         esi:ptr IMAGE_OPTIONAL_HEADER
  
  push          [esi].ImageBase
  pop           dwImageBase
  
  push          [esi].AddressOfEntryPoint
  pop           dwOriginalEP
  
  ret
  
storeHeaderInformation   endp
; ----------------------------------------------------------------------
;

;
; Prendo l'IMAGE_SECTION_HEADER
; cercando quello corrispondente alla costante passata
; PARAMETRO:
;            EDX (costante)
; ----------------------------------------------------------------------
offsetToSection        proc uses esi ecx
  call          readNtHeader
  add           esi, 4
  assume        esi:ptr IMAGE_FILE_HEADER
  
  ; Leggo il numero delle sezioni
  movzx         ecx, [esi].NumberOfSections
  
  add           esi, sizeof IMAGE_FILE_HEADER + sizeof IMAGE_OPTIONAL_HEADER
  assume        esi:ptr IMAGE_SECTION_HEADER
  
  ; Cerco la sezione desiderata e ne restituisco (in eax e edx rispettivamente),
  ; un puntatore ai dati e la dimensione dei dati Raw
  .WHILE ecx > 0
    
    ; Caratteristiche della sezione
    ; applicando quel valore ad un bitwise and ottengo
    ; il valore stesso come risultato, SOLO SE Characteristics
    ; possiede anche quel valore
    mov         eax, [esi].Characteristics
    and         eax, edx
    
    .IF  eax == edx
      mov         eax, [esi].PointerToRawData
      mov         edx, [esi].SizeOfRawData
      mov         ebx, [esi].VirtualAddress
      ret
    .ENDIF
    
    dec         ecx
    add         esi, sizeof IMAGE_SECTION_HEADER
  .ENDW

  mov           eax, 0
  ret
offsetToSection        endp



; 
; Read data section and inject code in it
; ----------------------------------------------------------------------
injectCodeInData        proc uses esi eax ebx

  ; Punto alla fine del blocco dati
  mov            esi, dwBaseAddress
  add            esi, dwPointerToData
  add            esi, dwSizeOfData
  
  dec            esi
  ; Trovo la posizione piu' vicina al resto delle stringhe
  ; risalendo il blocco dati dal termine
  xor            ecx, ecx
  .WHILE byte ptr [esi] == 0
    dec            esi
    inc            ecx
  .ENDW
  
  add            esi, 2
  
  ; OFFSET stringa nel file exe in memoria: dwTextAddress + (dwTextAddress-dwPointerToData)

  mov             eax, dwRvaToData
  mov             ebx, dwSizeOfData
  sub             ebx, ecx
  add             eax, ebx
  add             eax, dwImageBase
  inc             eax
  
  push            eax
  pop             dwTextAddress
  
  mov             ebx, eax
  invoke          szLen, offset szTextMessage
  add             eax, ebx
  inc             eax
  
  push            eax
  pop             dwTitleAddress
  

 
  ; ESI punta ora 1byte dopo al termine dell'ultima stringa
  ; quindi possiamo copiare i nostri byte nella sezione
  invoke         szLen, offset szTextMessage
  invoke         RtlMoveMemory, addr [esi], addr szTextMessage ,eax
  
  ; Incremento il puntatore, ed inserisco la nuova stringa (titolo della MessageBox);
  ; L'incremento dipende dalla dimensione della stringa appena inserita, + NULL
  invoke         szLen, offset szTextMessage
  inc            eax
  add            esi, eax
  
  invoke         szLen, offset szTitleMessage
  invoke         RtlMoveMemory, addr [esi], addr szTitleMessage, eax
  
  invoke         SetFilePointer, hFile, 0, NULL, FILE_BEGIN
  invoke         WriteFile, hFile, dwBaseAddress,dwFileSize, addr dwByteRead, NULL

  ; EAX contiene 0 in caso di errori di WriteFile

  ret
  
injectCodeInData        endp
; ----------------------------------------------------------------------
;


;
; Questa parte si fa ancora piu' interessante. La funzione riceve come parametri
; il nome della libreria DLL ed il nome della funzione da cercare.
; Restituisce come valore l'indirizzo della libreria (in memoria, sotto forma di VA),
; che verra' poi utilizzato per ottenere l'indirizzo a cui saltare (in seguito sara' piu' chiaro)
; PARAMETRI:
;            EAX (nome DLL)
;            EDX (nome funzione)
; ----------------------------------------------------------------------
findFunctionAddress     proc uses esi
  LOCAL          dllName:DWORD
  LOCAL          funcName:DWORD
  LOCAL          counter:DWORD

  mov            dllName, eax
  mov            funcName, edx
  
  call           readNtHeader
  add            esi, 4
  add            esi, sizeof IMAGE_FILE_HEADER
  assume         esi:ptr IMAGE_OPTIONAL_HEADER
  ; Come in C, si tratta della seconda directory, ovvero la IMPORT
  mov            eax, [esi].DataDirectory[sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
  call           RVAToOffset
  
  .IF  eax != 0
    mov            esi, dwBaseAddress
    add            esi, eax
    assume         esi:ptr IMAGE_IMPORT_DESCRIPTOR
    
    .IF [esi].FirstThunk == 0
      mov            eax, 1
      ret
    .ENDIF

    .WHILE [esi].FirstThunk != 0
      mov            eax, [esi].Name1
      call           RVAToOffset
      add            eax, dwBaseAddress

      invoke         lstrcpyn, addr dbModuleName,eax, MODULE_NAME_STRING    

      ; Se la lib e' quella cercata, ne prendo le funzioni
      invoke         szCmp, offset dbModuleName, dllName
      
      .IF  eax != 0
        invoke  RtlZeroMemory, addr dbModuleName, MODULE_NAME_STRING+1
        
        ; Devo verificare come fatto in linguaggio C, se OriginalFirstThunk
        ; e' a 0 oppure no; se non lo e', lo utilizzo
        .IF [esi].OriginalFirstThunk == 0
          mov          eax, [esi].FirstThunk
        .ELSE
          mov          eax, [esi].OriginalFirstThunk
        .ENDIF
        
        mov            edi, [esi].FirstThunk

        push           esi
        
        ; Come sempre... si tratta di un RVA, e quindi
        ; visto che operiamo su file, e' da convertire
        call           RVAToOffset
        add            eax, dwBaseAddress
        mov            esi, eax
        
        ; Ora dobbiamo solo cercare la funzione che corrisponde
        ; e poi prenderne il relativo indirizzo
        mov   counter, 0
        .WHILE  dword ptr [esi] != 0
          ; Ricordiamoci che [esi] e' comunque
          ; un puntatore ad IMAGE_IMPORT_BY_NAME, ed e' un RVA
          ; ed e' quindi sempre da convertire...
          mov            eax, dword ptr [esi]
          call           RVAToOffset
          add            eax, dwBaseAddress
          assume         eax:ptr IMAGE_IMPORT_BY_NAME
          
          invoke         lstrcpyn, addr dbModuleName, addr [eax].Name1, MODULE_NAME_STRING
          
          invoke         szCmp, offset dbModuleName, funcName
          
          .IF eax != 0
            
            ; (pImageImportDescriptor[index].FirstThunk+index1*4)+pImageOptionalHeader->ImageBase)

            ; EDI contiene l'indirizzo della func
            push           eax
            mov            ebx, 4
            mov            eax, counter
            mul            ebx
            add            edi, eax
            add            edi, dwImageBase
            
            push           edi
            pop            dwFunctionAddress
         
            pop            eax
            
         .ENDIF
          
          add            esi, 4
          inc            counter
        .ENDW
        pop              esi
      .ENDIF
      
      add            esi, sizeof IMAGE_IMPORT_DESCRIPTOR
    .ENDW
  .ENDIF
  
  ret
findFunctionAddress     endp
; ----------------------------------------------------------------------


; Procedura incaricata al code injection nella nuova sezione
; creata in precedenza.
; Codice macchina iniettato:
; ========================================================================
; 90h                             NOP
; 90h                             NOP
; 90h                             NOP
; 68h 00h 00h 00h 00h             PUSH 00000000h
; 68h xxh xxh xxh xxh             PUSH xxxxxxxxh          ; Offset titolo MessageBoxA
; 68h xxh xxh xxh xxh             PUSH xxxxxxxxh          ; Offset testo MessageBoxA
; 68h 00h 00h 00h 00h             PUSH 00000000h
; 0FFh 15h xxh xxh xxh xxh        CALL [xxxxxxxx]         ;(MessageBoxA)
; 0E8h xxh xxh xxh xxh            CALL [ModuleEntryPoint] ;(EP Originale)
; 90h                             NOP
; =========================================================================
; La funzione prima di iniettare il codice, inserisce gli indirizzi corretti
; della CALL e della 2nd CALL
; ----------------------------------------------------------------------
injectCode   proc  uses  esi edi eax
  ; Punto alla nostra sezione codice 
  mov            esi, dwBaseAddress
  add            esi, dwPointerToCode

  ; Si tratta di sostituire in primis i 4 byte della CALL
  ; con l'indirizzo precedentemente ottenuto (dwFunctionAddress)
  xor            ecx, ecx

  .WHILE ecx < 35
    .IF byte ptr [dbShellcode+ecx] == 0FFh && byte ptr [dbShellcode+ecx+1] == 15h
      add            ecx, 2
      xor            eax, eax
      
      mov            al, byte ptr [dwFunctionAddress]
      or byte ptr    [dbShellcode+ecx], al
      mov            al, byte ptr [dwFunctionAddress+1]
      or byte ptr    [dbShellcode+ecx+1], al
      mov            al, byte ptr [dwFunctionAddress+2]
      or byte ptr    [dbShellcode+ecx+2], al
      mov            al, byte ptr [dwFunctionAddress+3]
      or byte ptr    [dbShellcode+ecx+3], al
      
      add            ecx, 4
    .ENDIF
    
    .IF byte ptr [dbShellcode+ecx] == 0E8h
      
      ; Il calcolo dell'indirizzo della JMP e' da fare a mano
      ; In generale lo si calcola facendo:
      ;      IndirizzoDestinazione - IndirizzoAttuale - ByteIstruzioneAttuale
      mov            ebx, [dwImageBase]
      add            ebx, [dwRvaToCode]
      add            ebx, ecx
      
      mov            eax, [dwOriginalEP]
      add            eax, [dwImageBase]
      sub            eax, ebx
      sub            eax, 5
      
      inc            ecx
      or byte ptr    [dbShellcode+ecx], al
      shr            eax, 8
      or byte ptr    [dbShellcode+ecx+1], al
      shr            eax, 8
      or byte ptr    [dbShellcode+ecx+2], al
      shr            eax, 8
      or byte ptr    [dbShellcode+ecx+3], al
      
      add            ecx, 4

    .ENDIF
    
    inc            ecx
  .ENDW
  
  ; Setto anche gli Offset al testo iniettato nella sezione .DATA
  mov            eax, 68h
  mov            edx, 1
  mov            ebx, dword ptr [dwTitleAddress]
  call           injectMessageBoxText
  
  mov            eax, 68h
  mov            edx, 2
  mov            ebx, dword ptr [dwTextAddress]
  call           injectMessageBoxText
  
  
  
  ; Copio lo shellcode in memoria
  invoke         RtlMoveMemory, addr [esi], addr dbShellcode ,35
  
  ; Setto l'EP nuovo, sovrascrivendo AddressOfEntryPoint
  call           readNtHeader
  add            esi, 4
  add            esi, sizeof IMAGE_FILE_HEADER
  assume         esi:ptr IMAGE_OPTIONAL_HEADER
  
  invoke         RtlMoveMemory, addr [esi].AddressOfEntryPoint, addr dwRvaToCode ,4
  
  invoke         SetFilePointer, hFile, 0, NULL, FILE_BEGIN
  invoke         WriteFile, hFile, dwBaseAddress,dwFileSize, addr dwByteRead, NULL
  
  
  ret

injectCode   endp
; -----------------------------------------------------------------------
;



; Inserimento degli indirizzi del titolo e del testo della MessageBox
; PARAMETRI: 
;            EAX: OPCODE da cercare
;            EDX: N. OPCODE da skippare
;            EBX: offset all'indirizzo del testo
; RETURN:
;            VOID
; -----------------------------------------------------------------------
injectMessageBoxText     proc  uses ecx
  xor            ecx, ecx
  
  ; Scorro tutto lo shellcode (array di byte)
  .WHILE ecx < 35
    
    ; Se il byte e' quello cercato
    .IF byte ptr [dbShellcode+ecx] == al
      ; EDX contiene i byte da saltare, e se vale
      ; 0 devo considerare quello attuale
      .IF edx == 0
        inc            ecx
        
        ; Come nel caso precedente copio la DWORD
        or   byte ptr  [dbShellcode+ecx], bl
        shr            ebx, 8
        or   byte ptr  [dbShellcode+ecx+1], bl
        shr            ebx, 8
        or   byte ptr  [dbShellcode+ecx+2], bl
        shr            ebx, 8
        or   byte ptr  [dbShellcode+ecx+3], bl
        
        jmp            _exit_inj
      .ELSE
        dec            edx
      .ENDIF
    .ENDIF
    
    inc            ecx
    
  .ENDW
  
_exit_inj:

  ret
injectMessageBoxText     endp

; -----------------------------------------------------------------------
;



; Si tratta di fatto di una conversione in assembly
; del codice precedentemente visto in C
; PARAMETRO: 
;           EAX (indirizzo RVA da convertire)
; ---------------------------------------------------------------
RVAToOffset             proc  uses esi edi ebx ecx
  LOCAL          dwRva:DWORD
  
  mov            dwRva, eax

  call           readNtHeader
  mov            edi, esi
  add            edi, 4
  assume         edi:ptr IMAGE_FILE_HEADER
  ; Numero di sezioni dell'header
  movzx          ecx, [edi].NumberOfSections
  
  call           readNtHeader
  add            esi,sizeof IMAGE_OPTIONAL_HEADER
  add            esi,sizeof IMAGE_FILE_HEADER
  add            esi,4
  assume         esi:ptr IMAGE_SECTION_HEADER
  
  mov            eax, dwRva
  
  .IF eax < [esi].PointerToRawData
    ret
  .ENDIF
  

  .WHILE ecx > 0
    .IF eax >= [esi].VirtualAddress
      mov          edx, [esi].VirtualAddress
      add          edx, [esi].SizeOfRawData
      
      ; L'entrata nell'IF indica che l'offset
      ; e' nella sezione che stiamo analizzando
      .IF  eax  <  edx
        mov          edx, [esi].VirtualAddress
        sub          eax, edx
        mov          edx, [esi].PointerToRawData
        add          edx, eax
        mov          eax, edx
        
        ret
      .ENDIF
    .ENDIF
    dec              ecx
    add              esi, sizeof IMAGE_SECTION_HEADER
  .ENDW
  
  ret

RVAToOffset             endp
; ----------------------------------------------------------------

; 
; PARAMETRI: eax, edx
; Return: eax
; ----------------------------------------------------------------
Alignment        proc uses ebx
  mov            ebx, eax
  
  .WHILE edx > eax
    add            eax, ebx
  .ENDW

  ret
  
Alignment        endp
; -----------------------------------------------------------------





  ; #############################################
  ; #           UTILITY FUNCTION                #
  ; #############################################

  
;
; Funzione copiata dal mio "Base64".
; Cancella la schermata, e setta lo sfondo bianco ed il testo nero
; ---------------------------------------------------------------------------------
ClearScreenAndColor      proc

  LOCAL          coordScreen:COORD
  LOCAL          cCharsWritten:DWORD
  LOCAL          csbi:CONSOLE_SCREEN_BUFFER_INFO
  LOCAL          dwConSize:DWORD
  LOCAL          hStdout:HANDLE
  
  pushad

  
  invoke         GetStdHandle, STD_OUTPUT_HANDLE
  mov            hStdout, eax

  invoke         GetConsoleScreenBufferInfo, hStdout, addr csbi
  
  .IF eax == 0
    print       "Error 1"
    jmp          _exit_clear
  .ENDIF
  
  movzx          ebx, word ptr csbi.dwSize.y
  movzx          eax, word ptr csbi.dwSize.x
  mul            ebx
  
  mov            dwConSize, eax
  
  invoke         FillConsoleOutputCharacter, hStdout, ' ', dwConSize, 0, addr cCharsWritten
  
  .IF eax == 0
    print       "Error 2"
    jmp          _exit_clear
  .ENDIF
  
  
  invoke         GetConsoleScreenBufferInfo, hStdout, addr csbi
  
  .IF eax == 0
    print       "Error 3"
    jmp          _exit_clear
  .ENDIF


  ; Setta lo sfondo bianco ed il testo nero
  invoke         FillConsoleOutputAttribute, hStdout, (BACKGROUND_RED or BACKGROUND_BLUE or BACKGROUND_GREEN or BACKGROUND_INTENSITY or 0), 65535, 0, addr cCharsWritten
  invoke         SetConsoleTextAttribute, hStdout, (BACKGROUND_RED or BACKGROUND_BLUE or BACKGROUND_GREEN or BACKGROUND_INTENSITY or 0 )
  
  .IF eax == 0
    print       "Error 4"
    invoke       GetLastError
    jmp          _exit_clear
  .ENDIF
  
  invoke         SetConsoleCursorPosition, hStdout, 0
  
_exit_clear:
  popad
  
  ret
ClearScreenAndColor      endp


end start