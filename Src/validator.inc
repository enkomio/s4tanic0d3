;
; Compute the initialization key to set the start state of rubik cube
; Parameter: expanded username
;
compute_initialization_key proc
	push ebp
	mov ebp, esp

	mov esi, dword ptr [ebp+arg0]

	; expand result
	vmovdqu xmm0, xmmword ptr [esi]
	vpsllw xmm1, xmm0, 4
	vpabsb xmm1, xmm1
	vpor xmm0, xmm1, xmm0
	vpbroadcastb xmm2, byte ptr [g_ascii_lower]
	vpxor xmm0, xmm0, xmm2

	; compute max, min and sum
	vpxor xmm1, xmm1, xmm1
	vpunpcklbw xmm2, xmm0, xmm1
	vpunpckhbw xmm3, xmm0, xmm1
	vpmaxuw xmm4, xmm3, xmm2
	vpminuw xmm5, xmm3, xmm2
	vpaddusw xmm6, xmm3, xmm2

	vpsrldq xmm2, xmm4, 8
	vpsrldq xmm3, xmm5, 8
	vpsrldq xmm1, xmm6, 8
	vpmaxuw xmm4, xmm4, xmm2
	vpminuw xmm5, xmm5, xmm3
	vpaddusw xmm6, xmm6, xmm1

	vpsrldq xmm2, xmm4, 4
	vpsrldq xmm3, xmm5, 4
	vpsrldq xmm1, xmm6, 4
	vpmaxuw xmm4, xmm4, xmm2
	vpminuw xmm5, xmm5, xmm3
	vpaddusw xmm6, xmm6, xmm1

	vpsrldq xmm2, xmm4, 2
	vpsrldq xmm3, xmm5, 2
	vpsrldq xmm1, xmm6, 2
	vpmaxuw xmm4, xmm4, xmm2
	vpminuw xmm5, xmm5, xmm3
	vpaddusw xmm6, xmm6, xmm1

	; extract info
	vpextrb ebx, xmm4, 0
	vpextrb ecx, xmm5, 0
	vpextrw eax, xmm6, 0
	shl eax, 8
	or eax, ecx
	shl eax, 8
	or eax, ebx
	rol eax, 13h

	mov esp, ebp
	pop ebp
	ret 
compute_initialization_key endp

;
; generate a random number used to initialize rubik cube. 
; This function update the value of the seed
; Parameters: seed address
;
gen_cube_random proc
	push ebp
	mov ebp, esp
	
	mov edi, dword ptr [ebp+arg0]
	mov eax, dword ptr [edi]

	mov edx, 0f1h
	mul edx
	add eax, 5a74c0d3h
	mov ebx, 12h
	xor edx, edx
	div ebx

	mov dword ptr [edi], eax
	mov eax, edx
	inc eax

	mov esp, ebp
	pop ebp
	ret
gen_cube_random endp

;
; Shuffle the cube faces
; Parameter: init seed, cube faces buffer
;
shuffle_cube proc
	push ebp
	mov ebp, esp
	sub esp, sizeof dword
	
	; initialize loop counter
	mov dword ptr [ebp+local0], 01000h

@@:
	; generate the random move to execute
	lea edi, [ebp+arg0]
	push edi
	call gen_cube_random

	; execute the move
	mov esi, dword ptr [ebp+arg1]	
	push eax
	execute_move esi, eax
	pop eax

	dec dword ptr [ebp+local0]
	cmp dword ptr [ebp+local0], 0h
	ja @b

	mov esp, ebp
	pop ebp
	ret
shuffle_cube endp

;
; Verify if the cube is in a completation state
; Parameter: the cube state
; Return: a DWORD representing the state of the cube
;
verify_cube_result proc
	push ebp
	mov ebp, esp	
	sub esp, sizeof dword
		
	xor ebx, ebx
	mov dword ptr [ebp+local0], 1h
	mov esi, dword ptr [ebp+arg0]
	mov ecx, 36h

@@:
	mov eax, ecx
	xor edx, edx
	mov edi, 9h
	div edi
	test edx, edx
	jnz @do_computation
	test bl, bl
	jz @do_computation
	mov eax, dword ptr [ebp+local0]
	mul bl
	mov dword ptr [ebp+local0], eax

@do_computation:	
	mov al, byte ptr [esi]
	inc esi
	xor bl, al
	loop @b

	mov eax, dword ptr [ebp+local0]
	mov ebx, eax
	rol eax, 10h
	neg bx
	mov ax, bx
	xor eax, 02d66483ah
	mov esp, ebp
	pop ebp
	ret
verify_cube_result endp

;
; Check the received username and license key
; Parameters: Username and license key
;
check_input proc
	push ebp
	mov ebp, esp	
	sub esp, sizeof dword	

	; space for cube faces
	sub esp, 36h
	mov dword ptr [ebp+local0], esp

	; set cube initial state
	mov ecx, 36h
	mov ebx, 0ffffffffh
@@:
	; compute current color
	mov eax, ecx
	xor edx, edx
	mov edi, 9h
	div edi
	test edx, edx
	jnz @write_color
	inc ebx

@write_color:
	mov esi, ecx
	lea esi, [esi+esp-1]
	mov al, byte ptr [g_cube_color + ebx]
	mov byte ptr [esi], al
	loop @b

	; compute initialization key
	push dword ptr [ebp+arg0]
	call compute_initialization_key
	add esp, 4

	; generate random cube state
	push dword ptr [ebp+local0]
	push eax
	call shuffle_cube

	; the cube is in its initial state. Execute the input moves
	mov eax, dword ptr [ebp+arg1]
	mov dword ptr [g_cube_moves], eax
	execute_next_move dword ptr [ebp+local0]

	; check result and compute the decryption key
	push dword ptr [ebp+local0]
	call verify_cube_result

	mov esp, ebp
	pop ebp
	ret
check_input endp