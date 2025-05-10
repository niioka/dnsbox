package util

import "fmt"

func PrintHex(data []byte) {
	stop := len(data)
	for i := 0; i < stop; i += 16 {
		end := min(i+16, stop)
		line := data[i:end]
		fmt.Printf("%04x: ", i)
		for j, b := range line {
			fmt.Printf("%02x ", b)
			if j == 7 {
				fmt.Printf(" ")
			}
		}
		for j := 0; j < 16-len(line); j++ {
			fmt.Printf("   ")
			if len(line)+j == 8 {
				fmt.Printf(" ")
			}
		}
		fmt.Print("| ")
		for _, b := range line {
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}
}
