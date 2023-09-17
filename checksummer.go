// Copyright: Jostein Stuhaug
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fletcher4 // import go.solidsystem.no/fletcher4

import (
	"encoding/binary"
	"fmt"
	"hash"
)

// Extension of common Hash interface to easily get 4 computed checksum words
type Fletcher64x4 interface {
	hash.Hash
	Sum64x4() [4]uint64
}

// The size of a fletcher4 checksum in bytes
const Size = 32

// Must be the same as size of uint32 with the current implementation. Not entirely sure it's the correct value to return as blocksize, but think so.
const BlockSize = 4

// digest represents the partial evaluation of a fletcher4 checksum.
type digest [4]uint64

func (d *digest) Reset() {
	*d = [4]uint64{0, 0, 0, 0}
}

// New returns a new Fletcher64x4 (hash.Hash) computing the fletcher4 checksum.
func New() Fletcher64x4 {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int {
	return BlockSize
}

// Add p to the running checksum d.
func update(dig digest, p []byte) digest {
	a := dig[0]
	b := dig[1]
	c := dig[2]
	d := dig[3]

	// Incase input is not padded to 4 bytes
	if len(p)%BlockSize != 0 {
		panic(fmt.Sprintf("Write to Fletcher64x4 checksummer must be a multiple of %v bytes.", BlockSize))
	}

	/*  This fix was deactivated, not sure this would be correct to do, if repeated writes to the checksummer are done with too few
		bytes the checksum would probably be wrong at the end. All writes must be a multiple of BlockSize, else we panic
	var p []byte
	if remainder := len(p) % BlockSize; remainder != 0 {
		p = make([]byte, len(p)+remainder)
		copy(p, add)
	} else {
		p = add
	}
	*/

	for i := 0; i < len(p); i += BlockSize {
		a += uint64(binary.LittleEndian.Uint32(p[i : i+BlockSize]))
		b += a
		c += b
		d += c
	}

	return digest{a, b, c, d}
}

func (d *digest) Write(p []byte) (n int, err error) {
	*d = update(*d, p)
	return len(p), nil
}

func (d *digest) Sum(in []byte) []byte {
	add := make([]byte, 8)
	binary.LittleEndian.PutUint64(add, d[0])
	ret := append(in, add...)
	binary.LittleEndian.PutUint64(add, d[1])
	ret = append(ret, add...)
	binary.LittleEndian.PutUint64(add, d[2])
	ret = append(ret, add...)
	binary.LittleEndian.PutUint64(add, d[3])
	ret = append(ret, add...)

	return ret
}

// Returns the current checksum
func (d *digest) Sum64x4() [4]uint64 {
	return [4]uint64(*d)
}
