package api

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func sendResponse(w http.ResponseWriter, status int, payload interface{}) {
	w.WriteHeader(status)
	if payload != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}
}
