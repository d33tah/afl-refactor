package main
/*
#include "afl-fuzz.h"
#cgo LDFLAGS: -ldl
int afl_main(int argc, char* argv[]);
*/
import "C"

import "os"

func main() {
    argc := C.int(len(os.Args))
    argv := make([]*C.char, argc)
    for i, arg := range os.Args {
            argv[i] = C.CString(arg)
    }
    C.afl_main(argc, &argv[0])
}
