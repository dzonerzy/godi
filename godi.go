package godi

/*
#cgo CFLAGS: -I./includes/
#cgo linux LDFLAGS: -L${SRCDIR}/libs -ldistorm3-linux
#cgo windows LDFLAGS: -L${SRCDIR}/libs -ldistorm3-windows
#include <distorm.h>
#include <mnemonics.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char * alloc_code(void * buffer, int size) {
	void * buf = malloc(size);
	memcpy(buf, buffer, size);
	return buf;
}

void destroy_code(unsigned char * buf) {
	free(buf);
}

_DecodeResult wrap_distorm_decode64(unsigned long codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount) {
	return distorm_decode64((_OffsetType)codeOffset, code, codeLen, dt, result,  maxInstructions, usedInstructionsCount);
}
*/
import "C"
import "unsafe"

const (
	// Decode types
	Decode16Bits = C.Decode16Bits
	Decode32Bits = C.Decode32Bits
	Decode64Bits = C.Decode64Bits
	// Decode Results
	DECRES_NONE      = C.DECRES_NONE
	DECRES_SUCCESS   = C.DECRES_SUCCESS
	DECRES_MEMORYERR = C.DECRES_MEMORYERR
	DECRES_INPUTERR  = C.DECRES_INPUTERR

	// Registers
	RM_AX  = C.RM_AX  /* AL, AH, AX, EAX, RAX */
	RM_CX  = C.RM_CX  /* CL, CH, CX, ECX, RCX */
	RM_DX  = C.RM_DX  /* DL, DH, DX, EDX, RDX */
	RM_BX  = C.RM_BX  /* BL, BH, BX, EBX, RBX */
	RM_SP  = C.RM_SP  /* SPL, SP, ESP, RSP */
	RM_BP  = C.RM_BP  /* BPL, BP, EBP, RBP */
	RM_SI  = C.RM_SI  /* SIL, SI, ESI, RSI */
	RM_DI  = C.RM_DI  /* DIL, DI, EDI, RDI */
	RM_FPU = C.RM_FPU /* ST(0) - ST(7) */
	RM_MMX = C.RM_MMX /* MM0 - MM7 */
	RM_SSE = C.RM_SSE /* XMM0 - XMM15 */
	RM_AVX = C.RM_AVX /* YMM0 - YMM15 */
	RM_CR  = C.RM_CR  /* CR0, CR2, CR3, CR4, CR8 */
	RM_DR  = C.RM_DR  /* DR0, DR1, DR2, DR3, DR6, DR7 */
	RM_R8  = C.RM_R8  /* R8B, R8W, R8D, R8 */
	RM_R9  = C.RM_R9  /* R9B, R9W, R9D, R9 */
	RM_R10 = C.RM_R10 /* R10B, R10W, R10D, R10 */
	RM_R11 = C.RM_R11 /* R11B, R11W, R11D, R11 */
	RM_R12 = C.RM_R12 /* R12B, R12W, R12D, R12 */
	RM_R13 = C.RM_R13 /* R13B, R13W, R13D, R13 */
	RM_R14 = C.RM_R14 /* R14B, R14W, R14D, R14 */
	RM_R15 = C.RM_R15 /* R15B, R15W, R15D, R15 */
	RM_SEG = C.RM_SEG /* CS, SS, DS, ES, FS, GS */

	// Operands
	O_NONE = C.O_NONE
	O_REG  = C.O_REG
	O_IMM  = C.O_IMM
	O_IMM1 = C.O_IMM1
	O_IMM2 = C.O_IMM2
	O_DISP = C.O_DISP
	O_SMEM = C.O_SMEM
	O_MEM  = C.O_MEM
	O_PC   = C.O_PC
	O_PTR  = C.O_PTR

	OPERANDS_NO = C.OPERANDS_NO

	// Features
	DF_NONE                 = C.DF_NONE
	DF_MAXIMUM_ADDR16       = C.DF_MAXIMUM_ADDR16
	DF_MAXIMUM_ADDR32       = C.DF_MAXIMUM_ADDR32
	DF_RETURN_FC_ONLY       = C.DF_RETURN_FC_ONLY
	DF_STOP_ON_CALL         = C.DF_STOP_ON_CALL
	DF_STOP_ON_RET          = C.DF_STOP_ON_RET
	DF_STOP_ON_SYS          = C.DF_STOP_ON_SYS
	DF_STOP_ON_UNC_BRANCH   = C.DF_STOP_ON_UNC_BRANCH
	DF_STOP_ON_CND_BRANCH   = C.DF_STOP_ON_CND_BRANCH
	DF_STOP_ON_INT          = C.DF_STOP_ON_INT
	DF_STOP_ON_CMOV         = C.DF_STOP_ON_CMOV
	DF_STOP_ON_HLT          = C.DF_STOP_ON_HLT
	DF_STOP_ON_PRIVILEGED   = C.DF_STOP_ON_PRIVILEGED
	DF_STOP_ON_UNDECODEABLE = C.DF_STOP_ON_UNDECODEABLE
	DF_SINGLE_BYTE_STEP     = C.DF_SINGLE_BYTE_STEP
	DF_FILL_EFLAGS          = C.DF_FILL_EFLAGS
	DF_USE_ADDR_MASK        = C.DF_USE_ADDR_MASK
	DF_STOP_ON_FLOW_CONTROL = (DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS | DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT | DF_STOP_ON_CMOV | DF_STOP_ON_HLT)
)

type DecodeType C._DecodeType
type DecodeResult C._DecodeResult
type OffsetType uint64

type CodeInfo struct {
	CodeOffset OffsetType
	AddrMask   OffsetType
	NextOffset OffsetType
	Code       *C.uchar
	CodeLen    int32
	Dt         DecodeType
	Features   uint32
}

func (c *CodeInfo) Destroy() {
	C.destroy_code(c.Code)
}

type Value struct {
	Mem [8]uint8
}

type Operand struct {
	Type  uint8
	Index uint8
	Size  uint16
}

type DInst struct {
	Imm                Value
	Disp               uint64
	Addr               OffsetType
	Flags              uint16
	UnusedPrefixesMask uint16
	UsedRegistersMask  uint32
	Opcode             uint16
	Ops                [OPERANDS_NO]Operand
	OpsNo              uint8
	Size               uint8
	Segment            uint8
	Base               uint8
	Scale              uint8
	DispSize           uint8
	Meta               uint16
	ModifiedFlagsMask  uint16
	TestedFlagsMask    uint16
	UndefinedFlagsMask uint16
}

type WString struct {
	Lenght uint32
	Ptr    [48]uint8
}

func (w *WString) String() string {
	data := w.Ptr[:w.Lenght]
	return string(data)
}

type DecodedInstruction struct {
	Offset         OffsetType
	Size           uint32
	Mnemonics      WString
	Operands       WString
	InstructionHex WString
}

func NewCodeInfo(Offset int, Code []byte, Dt DecodeType) *CodeInfo {
	ci := &CodeInfo{
		CodeOffset: OffsetType(Offset),
		// Code:       (*C.uchar)(unsafe.Pointer(C.CString(string(Code)))), works
		CodeLen:  int32(len(Code)),
		Dt:       Dt,
		Features: 0,
	}
	ci.Code = C.alloc_code(unsafe.Pointer(&Code[0]), C.int(len(Code)))
	return ci
}

func Version() int {
	return int(C.distorm_version())
}

func DistormDecompose64(Info *CodeInfo, Inst []DInst, MaxInstructions uint, UsedInstructionsCount *uint) DecodeResult {
	return DecodeResult(C.distorm_decompose64((*C._CodeInfo)(unsafe.Pointer(Info)), (*C._DInst)(unsafe.Pointer(&Inst[0])), C.uint(MaxInstructions), (*C.uint)(unsafe.Pointer(UsedInstructionsCount))))
}

func DistormDecode64(CodeOffset OffsetType, Code []byte, CodeLen int, Dt DecodeType, Result []DecodedInstruction, MaxInstructions uint, UsedInstructionsCount *uint) DecodeResult {
	return DecodeResult(C.wrap_distorm_decode64(C.ulong(CodeOffset), (*C.uchar)(unsafe.Pointer(&Code[0])), C.int(CodeLen), C._DecodeType(Dt), (*C._DecodedInst)(unsafe.Pointer(&Result[0])), C.uint(MaxInstructions), (*C.uint)(unsafe.Pointer(UsedInstructionsCount))))
}
