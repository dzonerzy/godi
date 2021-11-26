package main

import (
	"fmt"

	"github.com/dzonerzy/godi"
)

func main() {
	fmt.Printf("Using distorm version: %d\n", godi.Version())
	code := []byte("\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05")
	instructions := make([]godi.DecodedInstruction, 20)
	var usedinstructions uint = 0
	res := godi.DistormDecode64(0x10000, code, len(code), godi.Decode64Bits, instructions, 20, &usedinstructions)
	switch res {
	case godi.DECRES_SUCCESS:
		fmt.Println("Decode success got", usedinstructions, "instructions")
		for i := 0; i < int(usedinstructions); i++ {
			fmt.Printf("0x%x %d %s %s\n", instructions[i].Offset, instructions[i].Size, instructions[i].Mnemonics.String(), instructions[i].Operands.String())
		}
	default:
		fmt.Println("Decode failed:", res)
	}
	instlist := make([]godi.DInst, 20)
	info := godi.NewCodeInfo(0x10000, code, godi.Decode64Bits)
	res = godi.DistormDecompose64(info, instlist, 20, &usedinstructions)
	switch res {
	case godi.DECRES_SUCCESS:
		fmt.Println("Decompose success got", usedinstructions, "instructions")
		for i := 0; i < int(usedinstructions); i++ {
			fmt.Printf("0x%x Opcode: 0x%x Opcode String: %s | ", instlist[i].Addr, instlist[i].Opcode, godi.MnemonicString(instlist[i].Opcode))
			for k := 0; k < int(instlist[0].OpsNo); k++ {
				ops := instlist[i].Ops[k]
				fmt.Printf("Ops[%d] Type: %x ", k, ops.Type)
				if ops.Type == godi.O_REG {
					fmt.Printf("%s ", godi.RegisterString(ops.Index))
				}
			}
			fmt.Println()
		}
	default:
		fmt.Println("Decompose failed:", res)
	}
	info.Destroy()
}
