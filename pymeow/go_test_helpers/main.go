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

	case "binary.decoder.unmarshal":
		hexData := args["data"].(string)
		data, err := hex.DecodeString(hexData)
		if err != nil {
			return toJson(map[string]interface{}{"error": "invalid hex data: " + err.Error()})
		}
		// Use binary.Unmarshal which internally uses newDecoder().readNode()
		node, err := binary.Unmarshal(data)
		if err != nil {
			return toJson(map[string]interface{}{"error": err.Error()})
		}
		// Dereference the pointer to get the Node value
		return toJson(map[string]interface{}{"node": nodeToJson(*node)})

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

func nodeToJson(node binary.Node) map[string]interface{} {
	result := map[string]interface{}{
		"tag": node.Tag,
	}

	if node.Attrs != nil && len(node.Attrs) > 0 {
		result["attrs"] = node.Attrs
	} else {
		result["attrs"] = make(map[string]interface{})
	}

	if node.Content != nil {
		result["content"] = node.Content
	} else {
		result["content"] = nil
	}

	return result
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
