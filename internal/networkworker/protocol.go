package networkworker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

func (service *Service) Serve(input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, MaxJobBytes+1))
	if err != nil {
		return encodeResponse(output, Response{Untrusted: true, Error: "network worker could not read job"})
	}
	if len(data) > MaxJobBytes {
		return encodeResponse(output, Response{Untrusted: true, Error: "network worker job exceeds limit"})
	}
	var job Job
	if err := decodeStrict(data, &job); err != nil {
		return encodeResponse(output, Response{Untrusted: true, Error: "network worker job is invalid"})
	}
	return encodeResponse(output, service.Execute(context.Background(), job))
}

func encodeResponse(output io.Writer, response Response) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(encoded) > MaxWorkerResponseBytes {
		encoded, err = json.Marshal(Response{TokenID: response.TokenID, WorkerID: response.WorkerID, Untrusted: true, Error: "network worker response exceeds limit"})
		if err != nil {
			return err
		}
	}
	_, err = io.Copy(output, bytes.NewReader(append(encoded, '\n')))
	return err
}
