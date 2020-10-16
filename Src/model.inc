
; import
VirtualProtect proto, lpAddress:ptr dword, dwSize:dword, flNewProtect:dword, lpflOldProtect:ptr dword
CloseHandle proto, nStdHandle:dword
GetStdHandle proto, nStdHandle:dword
WriteConsoleA proto, hConsoleInput:dword, lpBuffer:ptr byte, nNumberOfCharsToWrite:dword, lpNumberOfCharsWritten:ptr dword, lpReserved:dword
ReadConsoleA proto, hConsoleInput:dword, lpBuffer:ptr byte, nNumberOfCharsToRead:dword, lpNumberOfCharsRead:ptr dword, pInputControl:ptr dword
SetConsoleMode proto, hConsoleHandle:dword, dwMode:dword
GetConsoleMode proto, hConsoleHandle:dword, lpMode:ptr dword
GetLastError proto
mciSendCommandA proto, IDDevice:dword, uMsg:dword, fdwCommand:ptr dword, dwParam:ptr dword
mmioInstallIOProcA proto fccIOProc:dword, pIOProc:ptr dword, dwFlags:dword

EXCEPTION_SINGLE_STEP equ 80000004h
PAGE_EXECUTE_READWRITE equ 00000040h
STD_INPUT_HANDLE equ -10
STD_OUTPUT_HANDLE equ -11

; helpful constants
arg0 equ 8h
arg1 equ 0Ch
arg2 equ 10h
arg3 equ 14h

local0 equ -4h
local1 equ -8h
local2 equ -0Ch
local3 equ -10h
local4 equ -14h
local5 equ -18h
local6 equ -1Ch
local7 equ -20h

; marker to identify protected code
marker_1 equ 1ce1c3bbh
marker_2 equ 0c0deca05h
marker_3 equ 0deadc0deh
marker_4 equ 0cafebabeh
shuffle_mark equ <dword marker_2, marker_2>
start_protected_code_marker equ <dword marker_1, marker_2, marker_3, marker_4>
end_protected_code_marker equ <dword marker_4, marker_3, marker_2, marker_1>

CONTEXT struct
	ContextFlags		DWORD  ?	
	rDr0			DWORD  ?
	rDr1			DWORD  ?
	rDr2			DWORD  ?
	rDr3			DWORD  ?
	rDr6			DWORD  ?
	rDr7			DWORD  ?
	ControlWord		DWORD  ?
	StatusWord		DWORD  ?
	TagWord 		DWORD  ?
	ErrorOffset		DWORD  ?
	ErrorSelector	DWORD  ?
	DataOffset		DWORD  ?
	DataSelector	DWORD  ?
	RegisterArea	dt 8 dup (?)
	Cr0NpxState		DWORD  ?

	SegGs			DWORD  ?
	SegFs			DWORD  ?
	SegEs			DWORD  ?
	SegDs			DWORD  ?

	rEdi			DWORD  ?	
	rEsi			DWORD  ?
	rEbx			DWORD  ?
	rEdx			DWORD  ?
	rEcx			DWORD  ?
	rEax			DWORD  ?

	rEbp			DWORD  ?	
	rEip			DWORD  ?
	SegCs			DWORD  ?
	EFlags			DWORD  ?
	rEsp			DWORD  ?
	SegSs			DWORD  ?

	ExtendedRegisters	db 512 dup (?)
CONTEXT ends

MCI_OPEN_PARMS struct
	dwCallback			dword ptr ?
	wDeviceID			dword ?
	lpstrDeviceType		dword ptr?
	lpstrElementName	dword ptr ?
	lpstrAlias			dword ptr ?
MCI_OPEN_PARMS ends

MCI_PLAY_PARMS struct
	dwCallback	dword ptr ?
	dwFrom		dword ?
	dwTo		dword ?
MCI_PLAY_PARMS ends

MMIOINFO struct
	dwFlags			dword ?
	fccIOProc		dword ?
	pIOProc			dword ptr ?
	wErrorRet		dword ?
	htask			dword ptr ?
	cchBuffer		dword ?
	pchBuffer		dword ptr ?
	pchNext			dword ptr ?
	pchEndRead		dword ptr ?
	pchEndWrite		dword ptr ?
	lBufOffset		dword ?
	lDiskOffset		dword ?
	adwInfo			dword 3 dup (?)
	dwReserved1		dword ?
	dwReserved2		dword ?
	hmmio			dword ptr ?
MMIOINFO ends