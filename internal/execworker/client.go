package execworker

import (
	"context"
	"errors"
	"net"
	"time"
)

type Client struct {
	SocketPath string
	Cookie     string
	Timeout    time.Duration
}

func (c Client) Do(ctx context.Context, job Job) (Response, error) {
	var response Response
	if c.SocketPath == "" || c.Cookie == "" {
		return response, errors.New("exec supervisor client is not configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return response, err
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopCancellation()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := WriteFrame(connection, Request{Cookie: c.Cookie, Job: job}); err != nil {
		if ctx.Err() != nil {
			return response, ctx.Err()
		}
		return response, err
	}
	if err := ReadFrame(connection, &response); err != nil {
		if ctx.Err() != nil {
			return response, ctx.Err()
		}
		return response, err
	}
	if response.CapabilityID != job.CapabilityID {
		return response, errors.New("exec supervisor response identity mismatch")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}
