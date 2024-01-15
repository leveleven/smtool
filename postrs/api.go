package postrs

// #cgo LDFLAGS: -lpost
// #include <stdlib.h>
// #include "post.h"
import "C"

func CPUProviderID() uint32 {
	return C.CPU_PROVIDER_ID
}
