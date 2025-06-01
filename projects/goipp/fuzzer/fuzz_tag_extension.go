/*  
 * Fuzz target for goipp's TagExtension handling
 */  
package fuzzer  
  
import (  
	"testing"  
	"github.com/OpenPrinting/goipp"  
)  
  
func FuzzTagExtension(f *testing.F) {  
	f.Fuzz(func(t *testing.T, data []byte) {  
		var m goipp.Message  
		if err := m.DecodeBytes(data); err != nil {  
			t.Skip()  
		}  
		// Test that TagExtension values can be accessed without panics
		// and that binary data is handled correctly
		for _, group := range m.AttrGroups() {  
			for _, attr := range group.Attrs {  
				for _, val := range attr.Values {  
					if val.T == goipp.TagExtension {  
						if binary, ok := val.V.(goipp.Binary); ok {  
							_ = binary.String()  
							if len(binary) >= 4 {  
								_ = binary[:4]  
							}  
						}  
					}  
				}  
			}  
		}  
	})  
}