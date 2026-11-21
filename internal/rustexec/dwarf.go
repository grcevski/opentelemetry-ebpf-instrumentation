// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// dwarf.go extracts private Rust field, enum, protocol, and channel layouts
// from OBI's DWARF-enabled fixtures during offset generation.

package rustexec // import "go.opentelemetry.io/obi/internal/rustexec"

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"strings"
)

func (d *rustDwarfTypes) typeOffset(t dwarf.Type) (dwarf.Offset, error) {
	name := t.Common().Name
	if s, ok := t.(*dwarf.StructType); ok {
		name = s.StructName
	}

	for _, offset := range d.names[name] {
		candidate, err := d.data.Type(offset)
		if err == nil && candidate == t {
			return offset, nil
		}
	}

	return 0, fmt.Errorf("rust DWARF offset missing for %s", t)
}

func (d *rustDwarfTypes) variant(t dwarf.Type, name string) (uint32, dwarf.Type, error) {
	offset, err := d.typeOffset(t)
	if err != nil {
		return 0, nil, err
	}

	r := d.data.Reader()
	r.Seek(offset)
	depth := 0

	for {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}

		if e.Tag == 0 {
			depth--
			if depth == 0 {
				break
			}
			continue
		}

		if e.Tag == dwarf.TagMember && e.Val(dwarf.AttrName) == name {
			off, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
			if !ok {
				return 0, nil, errors.New("rust variant type is missing")
			}

			base, ok := e.Val(dwarf.AttrDataMemberLoc).(int64)
			if !ok || base < 0 || base > 1<<20 {
				return 0, nil, errors.New("rust variant offset is invalid")
			}

			t, err := d.data.Type(off)
			return uint32(base), t, err
		}

		if e.Children {
			depth++
		}
	}

	return 0, nil, fmt.Errorf("rust variant %s is missing", name)
}

func (d *rustDwarfTypes) path(t dwarf.Type, path ...string) (uint32, dwarf.Type, error) {
	var total uint32

	for _, name := range path {
		offset, field, err := rustDwarfField(t, name)
		if err != nil {
			offset, field, err = d.variant(t, name)
		}

		if err != nil {
			return 0, nil, err
		}

		total += offset
		t = field
	}

	return total, t, nil
}

func (d *rustDwarfTypes) discriminant(t dwarf.Type) (uint32, error) {
	offset, err := d.typeOffset(t)
	if err != nil {
		return 0, err
	}

	r := d.data.Reader()
	r.Seek(offset)
	for range 8 {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}

		if e.Tag != dwarf.TagVariantPart {
			continue
		}

		discr, ok := e.Val(dwarf.AttrDiscr).(dwarf.Offset)
		if !ok {
			break
		}

		r.Seek(discr)

		member, err := r.Next()
		if err != nil || member == nil {
			break
		}

		typeOffset, ok := member.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			break
		}

		discrType, err := d.data.Type(typeOffset)
		if err != nil || discrType.Size() != 8 {
			break
		}

		base, ok := member.Val(dwarf.AttrDataMemberLoc).(int64)
		if !ok || base < 0 || base > 1<<20 {
			break
		}

		return uint32(base), nil
	}

	return 0, errors.New("rust message discriminant must be a validated u64")
}

func (d *rustDwarfTypes) callback(t dwarf.Type, path ...string) (uint32, uint32, uint32, error) {
	base, callback, err := d.path(t, path...)
	if err != nil {
		return 0, 0, 0, err
	}

	tag, err := d.discriminant(callback)
	if err != nil {
		return 0, 0, 0, err
	}

	option, sender, err := d.path(callback, "Retry", "__0")
	if err != nil {
		return 0, 0, 0, err
	}

	some, err := d.discriminant(sender)

	pointerPath := []string{"inner", "Some", "__0", "ptr", "pointer"}
	if err == nil {
		some += base + option
		pointerPath = append([]string{"Some", "__0"}, pointerPath...)
	} else {
		some = 0
	}

	pointer, ptrType, err := d.path(sender, pointerPath...)
	if err != nil || ptrType.Size() != 8 {
		return 0, 0, 0, errors.New("rust oneshot pointer is not validated")
	}

	other, _, err := d.path(callback, append([]string{"NoRetry", "__0"}, pointerPath...)...)
	if err != nil || other != option+pointer {
		return 0, 0, 0, errors.New("rust callback variants have different pointer locations")
	}

	return base + tag, some, base + option + pointer, nil
}

func inspectRustMessages(f *elf.File) (map[string]MessageLayout, error) {
	d, err := readRustDwarfTypes(f)
	if err != nil {
		return nil, err
	}

	channels := map[string]MessageLayout{}
	for name, offset := range d.types {
		if !strings.HasPrefix(name, "hyper::client::dispatch::Envelope<") {
			continue
		}

		t, err := d.data.Type(offset)
		if err != nil {
			return nil, err
		}

		var layout MessageLayout
		rx, err := d.data.Type(d.types["tokio::sync::mpsc::list::Rx<"+name+">"])
		if err != nil {
			return nil, err
		}

		layout.ListHead, _, err = rustDwarfField(rx, "head")
		if err != nil {
			return nil, err
		}

		layout.ListIndex, _, err = rustDwarfField(rx, "index")
		if err != nil {
			return nil, err
		}

		block, err := d.data.Type(d.types["tokio::sync::mpsc::block::Block<"+name+">"])
		if err != nil {
			return nil, err
		}

		_, values, err := rustDwarfField(block, "values", "__0")
		if err != nil {
			return nil, err
		}

		array, ok := values.(*dwarf.ArrayType)
		if !ok || array.Count != 32 {
			return nil, errors.New("rust channel block capacity is not validated")
		}

		layout.SlotMask = uint32(array.Count - 1)
		layout.TxTag, layout.TxSome, layout.TxPointer, err = d.callback(t, "__0", "Some", "__0", "__1")
		if err != nil {
			return nil, err
		}

		poll, ok := d.types["core::task::poll::Poll<core::option::Option<"+name+">>"]
		if !ok {
			continue
		}

		t, err = d.data.Type(poll)
		if err != nil {
			return nil, err
		}

		layout.RxTag, layout.RxSome, layout.RxPointer, err = d.callback(t, "Ready", "__0", "Some", "__0", "__0", "Some", "__0", "__1")
		if err != nil {
			return nil, err
		}

		discr, err := d.discriminant(t)
		if err != nil || discr != layout.RxTag {
			return nil, errors.New("rust receive result uses a different message discriminant")
		}

		layout.RxHeaders, _, err = d.path(t, "Ready", "__0", "Some", "__0", "__0", "Some", "__0", "__0", "head", "headers")
		if err != nil {
			return nil, err
		}

		layout.Request = true
		channels[name] = layout
	}

	return channels, nil
}

type rustDwarfTypes struct {
	data  *dwarf.Data
	types map[string]dwarf.Offset
	names map[string][]dwarf.Offset
}

func readRustDwarfTypes(f *elf.File) (*rustDwarfTypes, error) {
	d, err := f.DWARF()
	if err != nil {
		return nil, err
	}

	index := &rustDwarfTypes{data: d, types: map[string]dwarf.Offset{}, names: map[string][]dwarf.Offset{}}
	reader := d.Reader()
	var scopes []string
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			return index, err
		}

		if entry.Tag == 0 {
			if len(scopes) > 0 {
				scopes = scopes[:len(scopes)-1]
			}
			continue
		}

		name, _ := entry.Val(dwarf.AttrName).(string)
		if entry.Tag == dwarf.TagStructType && entry.Val(dwarf.AttrDeclaration) != true {
			var parts []string

			for _, scope := range scopes {
				if scope != "" {
					parts = append(parts, scope)
				}
			}

			parts = append(parts, name)
			index.types[strings.Join(parts, "::")] = entry.Offset
			index.names[name] = append(index.names[name], entry.Offset)
		}

		if entry.Children {
			scope := ""
			if entry.Tag == dwarf.TagNamespace {
				scope = name
			}
			scopes = append(scopes, scope)
		}
	}
}

func rustDwarfField(t dwarf.Type, path ...string) (uint32, dwarf.Type, error) {
	var offset int64
	for _, name := range path {
		for {
			alias, ok := t.(*dwarf.TypedefType)
			if !ok {
				break
			}

			t = alias.Type
		}
		s, ok := t.(*dwarf.StructType)
		if !ok {
			return 0, nil, fmt.Errorf("rust field %s is not a struct", name)
		}

		found := false
		for _, field := range s.Field {
			if field.Name == name {
				if field.ByteOffset < 0 || field.Type.Size() < 0 || field.ByteOffset+field.Type.Size() > s.ByteSize {
					return 0, nil, fmt.Errorf("rust field %s exceeds its containing type", name)
				}

				offset += field.ByteOffset
				t = field.Type
				found = true
				break
			}
		}

		if !found || offset < 0 || offset > 1<<20 {
			return 0, nil, fmt.Errorf("rust field %s has no validated offset", name)
		}
	}

	return uint32(offset), t, nil
}

func (d *rustDwarfTypes) field(name string, size int64, path ...string) (uint32, error) {
	offset, ok := d.types[name]
	if !ok {
		return 0, fmt.Errorf("rust DWARF type %s is missing", name)
	}

	t, err := d.data.Type(offset)
	if err != nil {
		return 0, err
	}

	field, leaf, err := rustDwarfField(t, path...)
	if err == nil && size != 0 && leaf.Size() != size {
		return 0, fmt.Errorf("rust field %s has size %d, expected %d", strings.Join(path, "."), leaf.Size(), size)
	}

	return field, err
}

func (d *rustDwarfTypes) customHeaderName() (uint32, uint32, error) {
	offset, ok := d.types["http::header::name::Repr<http::header::name::Custom>"]
	if !ok {
		return 0, 0, errors.New("rust HeaderName variant metadata is missing")
	}

	reader := d.data.Reader()
	reader.Seek(offset)
	depth := 0

	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			return 0, 0, errors.New("rust HeaderName custom variant is missing")
		}

		if entry.Tag == 0 {
			depth--
			if depth == 0 {
				return 0, 0, errors.New("rust HeaderName custom variant is missing")
			}
			continue
		}

		if entry.Tag == dwarf.TagMember && entry.Val(dwarf.AttrName) == "Custom" {
			typeOffset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
			if !ok {
				return 0, 0, errors.New("rust HeaderName custom type is missing")
			}

			t, err := d.data.Type(typeOffset)
			if err != nil {
				return 0, 0, err
			}

			ptr, ptrType, err := rustDwarfField(t, "__0", "__0", "bytes", "ptr")
			if err != nil {
				return 0, 0, err
			}

			if ptrType.Size() != 8 {
				return 0, 0, errors.New("rust HeaderName pointer size is unsupported")
			}

			length, lenType, err := rustDwarfField(t, "__0", "__0", "bytes", "len")
			if err == nil && lenType.Size() != 8 {
				return 0, 0, errors.New("rust HeaderName length size is unsupported")
			}

			base, _ := entry.Val(dwarf.AttrDataMemberLoc).(int64)
			return uint32(base) + ptr, uint32(base) + length, err
		}

		if entry.Children {
			depth++
		}
	}
}

func inspectRustProtocolLayouts(f *elf.File) (Layouts, error) {
	var config Layouts
	d, err := readRustDwarfTypes(f)
	if err != nil {
		return config, err
	}

	const vec = "alloc::vec::Vec<u8, alloc::alloc::Global>"
	fields := []struct {
		dst      *uint32
		typeName string
		path     []string
	}{
		{&config.VecPtr, vec, []string{"buf", "inner", "ptr", "pointer"}},
		{&config.VecLen, vec, []string{"len"}},
		{&config.VecCap, vec, []string{"buf", "inner", "cap", "__0"}},
		{&config.HeaderEntries, "http::header::map::HeaderMap<http::header::value::HeaderValue>", []string{"entries", "buf", "inner", "ptr", "pointer"}},
		{&config.HeaderCount, "http::header::map::HeaderMap<http::header::value::HeaderValue>", []string{"entries", "len"}},
		{&config.ValuePtr, "http::header::map::Bucket<http::header::value::HeaderValue>", []string{"value", "inner", "ptr"}},
		{&config.ValueLen, "http::header::map::Bucket<http::header::value::HeaderValue>", []string{"value", "inner", "len"}},
	}

	config.RequestHeaders, err = d.field("http::request::Request<()>", 0, "head", "headers")
	if err != nil {
		return config, err
	}

	config.HTTP1 = 1
	for _, field := range fields {
		*field.dst, err = d.field(field.typeName, 8, field.path...)
		if err != nil {
			return config, err
		}
	}

	const bucket = "http::header::map::Bucket<http::header::value::HeaderValue>"
	bucketType, err := d.data.Type(d.types[bucket])
	if err != nil {
		config.HTTP1 = 0
		return config, nil
	}

	config.BucketSize = uint32(bucketType.Size())

	nameBase, err := d.field(bucket, 0, "key", "inner")
	if err != nil {
		config.HTTP1 = 0
		return config, nil
	}

	ptr, length, err := d.customHeaderName()
	if err != nil {
		config.HTTP1 = 0
		return config, nil
	}

	config.NamePtr = nameBase + ptr
	config.NameLen = nameBase + length
	return config, nil
}
