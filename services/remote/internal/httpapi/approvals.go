package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

type approvalDecisionRequest struct {
	ConnectionID string `json:"connection_id"`
	DecisionJWS  string `json:"decision_jws"`
}

func (input *approvalDecisionRequest) UnmarshalJSON(raw []byte) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != 2 {
		return errors.New("approval: invalid admission request")
	}
	for name, value := range object {
		if (name != "connection_id" && name != "decision_jws") || string(value) == "null" {
			return errors.New("approval: invalid admission request")
		}
	}
	type fields approvalDecisionRequest
	var decoded fields
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*input = approvalDecisionRequest(decoded)
	return nil
}

func (api *API) decideApproval(response http.ResponseWriter, request *http.Request) {
	var input approvalDecisionRequest
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) || !decodeBody(response, request, &input) || !uuidPattern.MatchString(input.ConnectionID) || len(input.DecisionJWS) == 0 || len(input.DecisionJWS) > 16*1024 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	ctx, cancel := context.WithTimeout(request.Context(), 8*time.Second)
	defer cancel()
	status, delivery, err := api.realtime.DecideApproval(ctx, principal, deviceID, input.ConnectionID, id, input.DecisionJWS)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"status": status, "delivery": delivery})
}
