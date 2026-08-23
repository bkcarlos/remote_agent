// Package networkworker implements a single-job, short-lived HTTP worker.
//
// Jobs contain only explicit network data. The package has no workspace root or
// local-path API, and upload bodies must be supplied inline by the caller.
package networkworker
