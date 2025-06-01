/*  
 * Fuzz target for goipp's attribute unpacking functionality.  
 */  
package fuzzer  
  
import (  
	"strings"  
	"testing"  
	"github.com/OpenPrinting/goipp"  
)  
  
func FuzzAttributeUnpacking(f *testing.F) {  
	f.Fuzz(func(t *testing.T, tag goipp.Tag, data []byte) {  
		attr := goipp.Attribute{Name: "test-attr"}  
		err := attr.unpack(tag, data)
		// if unpack returns an error, ensure it mentions the tag in the message  
		if err != nil {  
			if !strings.Contains(err.Error(), tag.String()) {  
				t.Errorf("Error should contain tag information: %v", err)  
			}  
		}  
	})  
}