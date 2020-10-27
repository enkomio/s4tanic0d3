comment !

-=[ s4tanic0d3 ]=-

After more than 10 years I decided to create another crackme, the third one. Enjoy :)

You can find my previous crackme at:
- http://crackmes.cf/users/s4tan/crackme1_s4tan/ (2009)
- http://crackmes.cf/users/s4tan/s4tanic0de/ (2009)

2020 (C) Antonio 's4tan' Parata
!

.686
.model flat, stdcall
.stack 4096
.xmm

.data 

; specify if the program must be traced
g_is_trace_enabled dword 0h

; bytes containing the content that is encrypted and temporary decrypted for execution
g_saved_encrypted_code_address dword 0h
g_saved_encrypted_code byte 0Fh dup(0h)
g_restore_address dword 0h

; constants used to mark the encrypted code
g_saved_start_protected_code dword 0h
g_saved_end_protected_code dword 0h

; console strings
g_insert_license db "Please enter your license key: ", 0h
g_insert_username db "Please enter your ID: ", 0h
g_wrong_result db "The inserted license is not valid!", 0h
g_wait db "License validation in process...", 0ah, 0dh, 0h
g_license_separator db "-", 0h

g_ascii_num word 030h
g_ascii_upper word 037h
g_ascii_lower word 057h

; rubik cube vars
g_cube_color db "ywobrg"
g_cube_moves dword 0h
g_cube_moves_length dword 0h
g_verification_magic dword 0b554a050h

; play wave vars
g_element_name db 's4tanic0d3.S4T+',0h
g_already_opened dword 0h
g_device_id dword 0h

include <media.inc>

.code

include <model.inc>
include <utility.inc>
include <obfuscation.inc>
include <console.inc>
includelib <Winmm>

; start protected code. The code running under this mode, cannot read "code" or "data"
; from addresses that are in the encrypted space.
start_protected_code_marker
include <rubik_cube.inc>
include <validator.inc>
end_protected_code_marker

@function_table:
	dword offset compute_initialization_key
	dword offset gen_cube_random
	dword offset shuffle_cube
	dword offset verify_cube_result
	dword offset move_F
	dword offset move_F_prime
	dword offset move_R
	dword offset move_R_prime
	dword offset move_U
	dword offset move_U_prime
	dword offset move_L
	dword offset move_L_prime
	dword offset move_D
	dword offset move_D_prime
	dword offset move_B
	dword offset move_B_prime
	dword offset move_S
	dword offset move_S_prime
	dword offset move_M
	dword offset move_M_prime
	dword offset move_E
	dword offset move_E_prime

;
; restore bytes previously overwritten by decrypted code
;
restore_bytes proc
	push ebp
	mov ebp, esp

	mov edi, dword ptr [g_saved_encrypted_code_address]
	test edi, edi
	jz @exit

	; restore bytes temporarly decrypted
	mem_copy offset g_saved_encrypted_code, dword ptr [g_saved_encrypted_code_address], sizeof g_saved_encrypted_code
	mov dword ptr [g_saved_encrypted_code_address], 0h
	
@exit:
	mov esp, ebp
	pop ebp
	ret
restore_bytes endp

;
; handle the trap exception
; Parameter: CONTEXT
;
trap_handler proc
	push ebp
	mov ebp, esp
		
	; obtains the instruction address causing the fault
	assume  ebx: ptr CONTEXT
	mov ebx, [ebp+arg0]	
	mov eax, [ebx].rEip	

@@:
	; verify that the faulty EIP is inside the protected range, if not does not decrypt	
	cmp eax, dword ptr [g_saved_start_protected_code]
	jb @exit
	cmp eax, dword ptr [g_saved_end_protected_code]
	ja @exit		

	; decrypt the code that must be executed
	push eax
	call decrypt_code
			
@exit:	
	mov esp, ebp
	pop ebp
	ret
trap_handler endp

;
; call a specific function that was invoked via obfuscation
; Parameter: CONTEXT
;
call_nano_handler proc
	push ebp
	mov ebp, esp

	mov esi, [ebp+arg0]
	assume  esi: ptr CONTEXT

	; adjust stack
	mov ebx, [esi].rEsp
	sub ebx, sizeof dword
	mov dword ptr [esi].rEsp, ebx
	
	; get function	
	mov eax, [esi].rEip	
	inc eax	
	movzx eax, byte ptr [eax]
	lea eax, dword ptr [@function_table + eax * sizeof dword]
	mov edx, dword ptr [eax]

	; set return address
	mov eax, [esi].rEip	
	add eax, 2
	mov dword ptr [ebx], eax

	; set new EIP
	mov [esi].rEip, edx

	xor eax, eax
	mov esp, ebp
	pop ebp
	ret
call_nano_handler endp

; 
; See https://docs.microsoft.com/en-us/windows/win32/devnotes/--c-specific-handler2
;
exception_handler proc
	push ebp
	mov ebp, esp	

	; verify if it is a nano call		
	mov ebx, [ebp+arg0]
	cmp dword ptr [ebx], EXCEPTION_PRIVILEGED_INSTRUCTION
	jne @f
	push [ebp+arg2]
	call call_nano_handler

	; replace previous instructions if necessary
	call restore_bytes

	; invoke trap handler
	push [ebp+arg2]
	call trap_handler
	xor eax, eax
	jmp @set_trap_flag
	
@@:
	; verify that the exception is due to single step	
	cmp dword ptr [ebx], EXCEPTION_SINGLE_STEP
	jne @not_handled

	; replace previous instructions if necessary
	call restore_bytes

	; invoke trap handler
	push [ebp+arg2]
	call trap_handler
	xor eax, eax
	jmp @set_trap_flag	

@not_handled:
	mov eax, 1
	mov dword ptr [g_is_trace_enabled], 0h
	jmp @exit

@set_trap_flag:
	; check if single step is enabled
	cmp dword ptr [g_is_trace_enabled], 0h
	jz @exit

	; set trap flag in CONTEXT again
	mov ebx, [ebp+arg2]
	assume ebx: ptr CONTEXT
	or dword ptr [ebx].EFlags, 100h	

@exit:
	mov esp, ebp
	pop ebp
	ret
exception_handler endp

;
; Verify is a debugger is attached and if so modify then number to
; initialize the cube
;
check_debugger proc
	push ebp
	mov ebp, esp	

	; load to ESI the value
	mov esi, dword ptr [g_verification_magic]

	; transit to 64-bit world
	push 33h
	call $+5
	add dword ptr [esp], 5h
	retf

	; check debugger and return to 32-bit
	db 065h, 048h, 08bh, 004h, 025h, 030h, 000h, 000h, 000h
	db 048h, 08bh, 040h, 060h
	db 048h, 00fh, 0b6h, 040h, 002h
	db 048h, 085h, 0c0h
	db 048h, 0bbh, 0deh, 0c0h, 0adh, 0bah, 000h, 000h, 000h, 000h
	db 048h, 0b8h, 0beh, 0bah, 0feh, 0cah, 000h, 000h, 000h, 000h
	db 048h, 00fh, 044h, 0d8h
	db 048h, 033h, 0f3h
	db 0e8h, 000h, 000h, 000h, 000h
	db 0c7h, 044h, 024h, 004h, 023h, 000h, 000h, 000h
	db 083h, 004h, 024h, 00dh
	db 0cbh

	; save back the result, the correct value should be 7faa1aeeh
	mov dword ptr [g_verification_magic], esi

	mov esp, ebp
	pop ebp
	ret
check_debugger endp

main proc
	push ebp
	mov ebp, esp

	max_input_length equ 60h
	sub esp, sizeof dword * 2

	; make space for username and license
	sub esp, max_input_length
	mov dword ptr [ebp+local0], esp

	sub esp, max_input_length
	mov dword ptr [ebp+local1], esp

	; initialize console
	call init_console

	; print username
	push offset [g_insert_username]
	call print_line

	; read username
	push max_input_length
	sub dword ptr [esp], 1
	push dword ptr [ebp+local0]
	call read_username
	
	; print license key
	push offset [g_insert_license]
	call print_line

	; read license key	
	push max_input_length
	sub dword ptr [esp], 1
	push dword ptr [ebp+local1]
	call read_lincese
	test eax, eax
	jz @license_not_valid
	mov dword ptr [g_cube_moves_length], eax
		
	; unprotect all program memory
	call unprotect_code

	; fill global vars with start and end addresses of protected code
	call find_protected_code

	; print wait message
	push offset [g_wait]
	call print_line

	; check debugger
	call check_debugger

	; set the exception handler
	push offset exception_handler
	assume fs:nothing
	push dword ptr [fs:0]
	mov [fs:0], esp
	assume fs:error

	; enable trap flag and execute obfuscated code that is inside marks
	mov dword ptr [g_is_trace_enabled], 1h
	pushfd
	or word ptr [esp], 100h
	popfd

	; check the username/license values
	push dword ptr [ebp+local1]
	push dword ptr [ebp+local0]
	call check_input

	; disable tracing
	mov dword ptr [g_is_trace_enabled], 0h

	; save key
	push eax

	; use the result to decrypt the data
	push dword ptr [g_sound_size]
	push offset [g_sound]
	push eax
	call rc4_decrypt
	add esp, 0ch
	
	; play the sound
	call play_sound
	test eax, eax
	jz @license_not_valid

	; decrypt congratz
	pop eax
	push dword ptr [g_success_size]
	push offset [g_success]
	push eax
	call rc4_decrypt

	; print the congratz text
	push 1fh
	push dword ptr [g_success_size]
	push offset [g_success]
	call print_slow

	push 7d0h
	call sleep

	; stop the sound
	call stop_sound
	xor eax, eax
	jmp @exit

@license_not_valid:
	push offset [g_wrong_result]
	call print_line 
	mov eax, 1h
	jmp @exit

@exit:
	push eax
	call ExitProcess

	mov esp, ebp
	pop ebp
	ret
main endp
end main