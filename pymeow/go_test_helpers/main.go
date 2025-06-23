package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"unsafe"

	"go.mau.fi/whatsmeow/binary"
)

//export call_method
func call_method(methodPtr *C.char, argsPtr *C.char) *C.char {
	method := C.GoString(methodPtr)
	argsJson := C.GoString(argsPtr)

	var args map[string]interface{}
	json.Unmarshal([]byte(argsJson), &args)

	switch method {
	case "binary.encoder.writeNodeGetData":
		nodeData := args["node"].(map[string]interface{})
		node := jsonToNode(nodeData)
		// Use binary.Marshal which internally uses newEncoder().writeNode().getData()
		data, err := binary.Marshal(node)
		if err != nil {
			return toJson(map[string]interface{}{"error": err.Error()})
		}
		return toJson(map[string]interface{}{"data": hex.EncodeToString(data)})

	default:
		return toJson(map[string]interface{}{"error": "unknown method"})
	}
}

func jsonToNode(data map[string]interface{}) binary.Node {
	node := binary.Node{
		Tag: data["tag"].(string),
	}

	if attrs, ok := data["attrs"].(map[string]interface{}); ok {
		node.Attrs = make(binary.Attrs)
		for k, v := range attrs {
			node.Attrs[k] = v
		}
	}

	if content, ok := data["content"]; ok {
		node.Content = content
	}

	return node
}

func toJson(data interface{}) *C.char {
	jsonData, _ := json.Marshal(data)
	return C.CString(string(jsonData))
}

//export free_cstring
func free_cstring(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}
