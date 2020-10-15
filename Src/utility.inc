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