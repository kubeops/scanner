package trivy

import jsoniter "github.com/json-iterator/go"

var JSON = jsoniter.Config{
	EscapeHTML:             true,
	SortMapKeys:            true,
	ValidateJsonRawMessage: true,
	TagKey:                 "tv",
}.Froze()
