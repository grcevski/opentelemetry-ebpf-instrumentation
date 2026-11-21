// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	_ "embed"
	"encoding/json"
	"sync"

	"go.opentelemetry.io/obi/internal/rustexec"
)

//go:embed rust_offsets.json
var rustOffsetData []byte

// The embedded database never changes, and layout selection only reads it,
// so every attachment shares one decoded copy.
var rustOffsetDatabase = sync.OnceValues(func() (rustexec.Database, error) {
	var database rustexec.Database
	err := json.Unmarshal(rustOffsetData, &database)
	return database, err
})

func resolveRustProtocolLayouts(f *elf.File, channels ...string) (*BpfRustProtocolConfigT, error) {
	build, err := rustexec.ReadBuild(f)
	if err != nil {
		return nil, err
	}
	database, err := rustOffsetDatabase()
	if err != nil {
		return nil, err
	}
	return selectRustProtocolLayouts(build, database, channels...)
}

func selectRustProtocolLayouts(build rustexec.Build, database rustexec.Database, channels ...string) (*BpfRustProtocolConfigT, error) {
	config, err := rustexec.SelectLayouts(build, database, channels...)
	if config == nil {
		return nil, err
	}
	return &BpfRustProtocolConfigT{
		VecPtr:           config.VecPtr,
		VecLen:           config.VecLen,
		VecCap:           config.VecCap,
		RequestHeaders:   config.RequestHeaders,
		HeaderEntries:    config.HeaderEntries,
		HeaderCount:      config.HeaderCount,
		BucketSize:       config.BucketSize,
		NamePtr:          config.NamePtr,
		NameLen:          config.NameLen,
		ValuePtr:         config.ValuePtr,
		ValueLen:         config.ValueLen,
		ListHead:         config.ListHead,
		ListIndex:        config.ListIndex,
		SlotMask:         config.SlotMask,
		MessageTxTag:     config.MessageTxTag,
		MessageTxSome:    config.MessageTxSome,
		MessageTxPointer: config.MessageTxPointer,
		MessageRxTag:     config.MessageRxTag,
		MessageRxSome:    config.MessageRxSome,
		MessageRxPointer: config.MessageRxPointer,
		MessageRxHeaders: config.MessageRxHeaders,
		Http1:            config.HTTP1,
		Inject:           config.Inject,
		Message:          config.Message,
	}, err
}
