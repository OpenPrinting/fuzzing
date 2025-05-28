/*
 * Fuzz target for goipp's `DecodeBytesEx` function.
 */


package fuzzer  
  
import (  
    "testing"  
    "github.com/OpenPrinting/goipp"  
)  
  
func FuzzDecodeBytesEx(f *testing.F) {  
    f.Fuzz(func(t *testing.T, data []byte, enableWorkarounds bool) {  
        var m goipp.Message  
        opt := goipp.DecoderOptions{EnableWorkarounds: enableWorkarounds}  
        if err := m.DecodeBytesEx(data, opt); err != nil {  
            t.Skip()  
        }  
          
        // Test message properties
        if !m.Equal(m) {  
            t.Error("Message should be equal to itself")  
        }  
    })  
}