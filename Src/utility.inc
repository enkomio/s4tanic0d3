strlen macro input
	push edi
	push eax
	mov ecx, 0ffffh
	mov edi, input
	xor eax, eax
	repnz scasb 
	sub edi, input
	dec edi
	mov ecx, edi
	pop eax
	pop edi	
endm

;
; Unprotect all program memory
;
unprotect_code proc
	push ebp
	mov ebp, esp

	; get base address
	assume fs:nothing
	mov eax, dword ptr [fs:30h]
	assume fs:error
	mov eax, dword ptr [eax+8h]	

	; get size of image
	mov ebx, dword ptr [eax+3ch]
	add ebx, eax
	mov ebx, dword ptr [ebx+50h]

	; unprotect code in order to be easibly modifiable	
	; yes this is extremly inefficient I know :)
	sub esp, 4
	push esp
	push PAGE_EXECUTE_READWRITE
	push ebx
	push eax
	call VirtualProtect

	pop eax
	mov esp, ebp
	pop ebp
	ret
unprotect_code endp

;
; initialize the global vars containing the start and end address of protected code
;
find_protected_code proc
	push ebp
	mov ebp, esp

	assume fs:nothing
	mov eax, dword ptr [fs:30h]
	assume fs:error
	mov eax, dword ptr [eax+8h]	
	push eax
		
@@: ; find start
	inc eax
	mov ebx, dword ptr [eax]
	cmp ebx, marker_1
	jne @b
	add eax, sizeof dword
	mov ebx, dword ptr [eax]
	cmp ebx, marker_2
	jne @b
	add eax, sizeof dword
	mov ebx, dword ptr [eax]
	cmp ebx, marker_3
	jne @b
	add eax, sizeof dword
	mov ebx, dword ptr [eax]
	cmp ebx, marker_4
	jne @b
	add eax, sizeof dword
	mov dword ptr [g_saved_start_protected_code], eax
	
	pop eax
@@: ; find end
	inc eax
	mov ebx, dword ptr [eax]
	cmp ebx, marker_4
	jne @b
	add eax, sizeof dword
	mov ebx, dword ptr [eax]
	cmp ebx, marker_3
	jne @b
	add eax, sizeof dword
	mov ebx, dword ptr [eax]
	cmp ebx, marker_2
	jne @b
	add eax, sizeof dword
	mov ebx, dword ptr [eax]
	cmp ebx, marker_1
	jne @b
	sub eax, sizeof dword
	mov [g_saved_end_protected_code], eax

	mov esp, ebp
	pop ebp
	ret
find_protected_code endp

;
; Copy memory buffer
; Parameters: src address, dest addr, size
;
mem_copy macro src, dest, size
	mov esi, src
	mov edi, dest
	mov ecx, size
	rep movsb
endm

;
; RC4 decrypt the input buffer using the input key
; Input: key, buffer, buffer size
;
rc4_decrypt proc
	push ebp
	mov ebp, esp
	sub esp, 2 * sizeof dword

	; make space for S state
	sub esp, 0100h
	mov dword ptr [ebp+local0], esp
	mov esi, esp	

	; set initial S state
	mov ecx, 0100h
	xor eax, eax
@@:		
	mov byte ptr [esi], al
	inc al
	inc esi
	loop @b

	; KSA
	mov ecx, 0100h
	mov esi, dword ptr [ebp+local0]
	mov dword ptr [ebp+local1], 0h
	mov edx, dword ptr [ebp+arg0]	
@@:
	; add S[i]
	lea edi, dword ptr [ecx-0100h]
	neg edi
	lea edi, dword ptr [esi+edi]
	movzx eax, byte ptr [edi]
	mov ebx, eax

	; add key[i % key.Length] and rotate
	add bl, dl
	ror edx, 8

	; updated j
	add dword ptr [ebp+local1], ebx
	and dword ptr [ebp+local1], 0ffh

	; do swap S[i], S[j]
	; save S[i]
	movzx ebx, byte ptr [edi]	
	push ebx

	; S[i] = S[j]
	mov ebx, dword ptr [ebp+local1]
	lea ebx, dword ptr [esi+ebx]
	mov al, byte ptr [ebx]
	mov byte ptr [edi], al
	
	; S[j] = saved S[i]
	pop eax
	mov byte ptr [ebx], al

	loop @b

	; PRGA
	mov ecx, dword ptr [ebp+arg2]
	mov dword ptr [ebp+local0], 0h
	mov dword ptr [ebp+local1], 0h

@@:
	; i = (i + 1) % N
    ; j = (j + S[i]) % N
	inc dword ptr [ebp+local0]
	and dword ptr [ebp+local0], 0ffh
	mov eax, dword ptr [ebp+local0]
	lea eax, dword ptr [esi + eax]
	movzx eax, byte ptr [eax]
	add dword ptr [ebp+local1], eax
	and dword ptr [ebp+local1], 0ffh
	
	; do swap S[i], S[j]
	; save S[i]
	mov edi, dword ptr [ebp+local0]
	lea edi, dword ptr [esi+edi]
	movzx eax, byte ptr [edi] 
	push eax

	; S[i] = S[j]
	mov ebx, dword ptr [ebp+local1]
	lea ebx, dword ptr [esi+ebx]
	mov al, byte ptr [ebx]
	mov byte ptr [edi], al
	
	; S[j] = saved S[i]
	pop eax
	mov byte ptr [ebx], al

	; int rnd = S[(S[i] + S[j]) % N]
	mov eax, dword ptr [ebp+local0]
	lea eax, dword ptr [esi+eax]
	movzx eax, byte ptr [eax]

	mov ebx, dword ptr [ebp+local1]
	lea ebx, dword ptr [esi+ebx]
	mov bl, byte ptr [ebx] 

	add al, bl	
	and eax, 0ffh
	lea ebx, dword ptr [esi+eax]
	mov bl, byte ptr [ebx]

	; ciphertext[n] = rnd ^ plaintext[n]
	mov eax, dword ptr [ebp+arg1]
	xor byte ptr [eax], bl
	inc dword ptr [ebp+arg1]

	loop @b

	mov esp, ebp
	pop ebp
	ret
rc4_decrypt endp

;
; LRESULT CALLBACK IOProc(LPMMIOINFO lpMMIOInfo, UINT uMessage, LPARAM lParam1, LPARAM lParam2)
;
IOProc proc
	push ebp
	mov ebp, esp

	; save non volatile registers, see: https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019#register-usage
	push esi
	push edi

	assume edx:ptr MMIOINFO
	mov edx, dword ptr [ebp+arg0]
	mov eax, dword ptr [ebp+arg1]	

	; MMIOM_OPEN
	cmp eax, 3h
	jnz @mmiom_close
	mov eax, dword ptr [g_already_opened]
	test eax, eax
	jnz @ok
	mov dword ptr [g_already_opened], 1h
	mov dword ptr [edx].lDiskOffset, 0h
	jmp @ok

	; MMIOM_CLOSE
@mmiom_close:
	cmp eax, 4h
	jnz @mmiom_read
	jmp @ok

	; MMIOM_READ
@mmiom_read:
	cmp eax, 0h
	jnz @mmiom_seek
	mov edi, dword ptr [ebp+arg2]
	mov esi, offset [g_sound]
	add esi, dword ptr [edx].lDiskOffset
	mov ecx, dword ptr [ebp+arg3]
	rep movsb
	mov eax, dword ptr [ebp+arg3]
	add dword ptr [edx].lDiskOffset, eax
	jmp @finish

	; MMIOM_SEEK
@mmiom_seek:
	cmp eax, 2h
	jnz @default
	mov eax, dword ptr [ebp+arg3]
	; SEEK_SET
	cmp eax, 0h
	jne @f
	mov eax, dword ptr [ebp+arg2]
	mov dword ptr [edx].lDiskOffset, eax
@@:
	mov eax, dword ptr [edx].lDiskOffset
	jmp @finish

@default:
	mov eax, -1h
	jmp @finish
	
@ok:
	xor eax, eax

@finish:	
	; restore non volatile registers
	pop edi
	pop esi

	mov esp, ebp
	pop ebp
	ret 10h
IOProc endp

;
; Try to play the wave content
; Returns 1 if the content if played successfully
;
play_sound proc
	push ebp
	mov ebp, esp

	; allocate space for vars and zero out
	sub esp, 2 * sizeof dword
	xor eax, eax
	
	sub esp, sizeof MCI_OPEN_PARMS
	mov dword ptr [ebp+local0], esp
	mov ecx, sizeof MCI_OPEN_PARMS
	mov edi, esp
	rep stosb

	sub esp, sizeof MCI_PLAY_PARMS
	mov dword ptr [ebp+local1], esp
	mov ecx, sizeof MCI_PLAY_PARMS
	mov edi, esp
	rep stosb

	; Install a custom I/O procedure
	push 010010000h ; MMIO_INSTALLPROC | MMIO_GLOBALPROC
	push offset IOProc
	push 020543453h
	call mmioInstallIOProcA
	test eax, eax
	jz @error

	; open WAV device
	assume esi:ptr MCI_OPEN_PARMS
	mov esi, dword ptr [ebp+local0]
	mov dword ptr [esi].lpstrDeviceType, 020ah ; MCI_DEVTYPE_WAVEFORM_AUDIO
	mov ebx, offset [g_element_name]
	mov dword ptr [esi].lpstrElementName, ebx
	
	push dword ptr [ebp+local0]	
	push 03200h ; MCI_OPEN, MCI_OPEN_TYPE | MCI_OPEN_ELEMENT | MCI_OPEN_TYPE_ID
	push 803h ; MCI_OPEN
	push 0
	call mciSendCommandA
	test eax, eax
	jnz @error

	; play content
	lea eax, dword ptr [ebp+local1]
	push eax
	push 1h ; MCI_NOTIFY
	push 0806h ; MCI_PLAY
	push dword ptr [esi].wDeviceID
	call mciSendCommandA
	test eax, eax
	jnz @error

	mov eax, 1h
	jmp @finish
@error:
	xor eax, eax

@finish:
	
	mov ecx, 0ffffffffh
@@:
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	xor eax, eax
	xor eax, eax
	cpuid
	loop @b
	

	mov esp, ebp
	pop ebp
	ret
play_sound endp