package sortpem

import "encoding/pem"

// DecodeAll decodes all PEM blocks in data, leaving all non-PEM data in rest.
func DecodeAll(data []byte) (blocks []*pem.Block, rest []byte) {
	rest = data
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	return
}
