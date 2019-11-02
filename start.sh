#!/bin/bash
set -e
trap 'kill $(jobs -p)' EXIT

go run cmd/auth/main.go &
go run cmd/client/main.go &
go run cmd/resource/main.go &
go run cmd/gateway/main.go &
go run cmd/ca/main.go &

sleep 1
go run example/caflow/main.go
go run example/token/main.go |:

wait
