/*
 * Fuzz target for goipp's handling of Collection attributes.
 */


package fuzzer

import (
	"testing"
	"github.com/OpenPrinting/goipp"
)


func FuzzCollections(f *testing.F) {  
    f.Fuzz(func(t *testing.T, data []byte) {  
        var m goipp.Message  
        if err := m.DecodeBytes(data); err != nil {  
            t.Skip()  
        }  
          
        // Test that collections can be accessed without panics  
        for _, group := range m.AttrGroups() {  
            for _, attr := range group.Attrs {  
                for _, val := range attr.Values {  
                    if collection, ok := val.V.(goipp.Collection); ok {  
                        _ = collection.String()   
                    }  
                }  
            }  
        }  
    })  
} 