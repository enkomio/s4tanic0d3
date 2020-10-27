.code

main proc
	; do check with ESI register
	mov rax, gs:[30h]
	mov rax, [rax+60h]
	movzx rax, byte ptr [rax+2h]
	test rax, rax
	mov rbx, 0baadc0deh
	mov rax, 0cafebabeh
	cmove rbx, rax
	xor rsi, rbx

	; move back to 32 bit
	call $+5
	mov DWORD PTR [rsp+4h], 23h
	add DWORD PTR [rsp], 0Dh
	retf
main endp

end