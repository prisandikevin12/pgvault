package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

const (
	// DefaultChunkSize is the default plaintext chunk size (64 KiB).
	DefaultChunkSize = 64 * 1024
	// MaxChunkSize bounds the maximum allowed chunk size (64 MiB) to prevent excessive memory allocation.
	MaxChunkSize = 64 * 1024 * 1024

	// StreamMagic identifies the PGVault v1 streaming encryption format.
	StreamMagic = "PGV1"
	// StreamHeaderSize is the fixed 15-byte header size: 4B magic + 4B chunkSize + 7B noncePrefix.
	StreamHeaderSize = 15

	noncePrefixSize = 7
	flagNotFinal    = byte(0x00)
	flagFinal       = byte(0x01)
)

var (
	// ErrInvalidChunkSize is returned when chunkSize is negative or exceeds MaxChunkSize.
	ErrInvalidChunkSize = errors.New("crypto: invalid chunk size")
	// ErrInvalidHeader is returned when the stream header magic or parameters are invalid.
	ErrInvalidHeader = errors.New("crypto: invalid stream header")
	// ErrTruncatedStream is returned when EOF is encountered before the final authenticated chunk.
	ErrTruncatedStream = errors.New("crypto: truncated stream")
	// ErrTrailingData is returned when unexpected bytes appear after the final authenticated chunk.
	ErrTrailingData = errors.New("crypto: trailing data after final chunk")
	// ErrStreamTooLarge is returned when a stream exceeds the 32-bit chunk index space.
	ErrStreamTooLarge = errors.New("crypto: stream exceeds maximum chunk count")
)

// StreamStats holds byte counts and the hex-encoded SHA-256 digest of the
// encrypted output stream computed on-the-fly during EncryptStream.
type StreamStats struct {
	PlaintextBytes   int64
	CiphertextBytes  int64
	CiphertextSHA256 string
}

type countingHashWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (cw *countingHashWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.n += int64(n)
		_, _ = cw.h.Write(p[:n])
	}
	return n, err
}

// EncryptStream encrypts data from r into w using chunked AES-256-GCM.
// If chunkSize is 0, DefaultChunkSize (64 KiB) is used.
// Even a 0-byte input emits 1 authenticated final chunk so truncation is detectable.
func EncryptStream(r io.Reader, w io.Writer, dek []byte, chunkSize int) (StreamStats, error) {
	if len(dek) != KeySize {
		return StreamStats{}, fmt.Errorf("%w: got DEK length %d", ErrInvalidKeySize, len(dek))
	}
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < 0 || chunkSize > MaxChunkSize {
		return StreamStats{}, fmt.Errorf("%w: %d", ErrInvalidChunkSize, chunkSize)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return StreamStats{}, fmt.Errorf("crypto: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return StreamStats{}, fmt.Errorf("crypto: create GCM: %w", err)
	}

	// Build 15-byte header: magic "PGV1" (4B) + chunkSize uint32 BE (4B) + random noncePrefix (7B).
	var header [StreamHeaderSize]byte
	copy(header[0:4], StreamMagic)
	binary.BigEndian.PutUint32(header[4:8], uint32(chunkSize))
	if _, err := io.ReadFull(rand.Reader, header[8:15]); err != nil {
		return StreamStats{}, fmt.Errorf("crypto: generate nonce prefix: %w", err)
	}

	cw := &countingHashWriter{
		w: w,
		h: sha256.New(),
	}
	if _, err := cw.Write(header[:]); err != nil {
		return StreamStats{}, fmt.Errorf("crypto: write header: %w", err)
	}

	// Use a chunkSize+1 read buffer so we have 1-byte lookahead to identify the exact
	// final chunk without emitting an unnecessary extra empty chunk on exact boundaries.
	buf := make([]byte, chunkSize+1)
	frameBuf := make([]byte, 4, 4+chunkSize+aead.Overhead())

	var nonce [gcmNonceSize]byte
	copy(nonce[0:noncePrefixSize], header[8:15])

	var (
		carry          int
		chunkIndex     uint32
		plaintextBytes int64
	)

	for {
		n, readErr := io.ReadFull(r, buf[carry:])
		total := carry + n

		switch {
		case readErr == nil:
			// Buffer is full (chunkSize+1 bytes): at least 1 more byte follows, so this chunk is not final.
			binary.BigEndian.PutUint32(nonce[7:11], chunkIndex)
			nonce[11] = flagNotFinal

			ct := aead.Seal(frameBuf[4:4], nonce[:], buf[:chunkSize], header[:])
			binary.BigEndian.PutUint32(frameBuf[0:4], uint32(len(ct)))
			if _, err := cw.Write(frameBuf[:4+len(ct)]); err != nil {
				return StreamStats{}, fmt.Errorf("crypto: write chunk %d: %w", chunkIndex, err)
			}

			plaintextBytes += int64(chunkSize)
			if chunkIndex == math.MaxUint32 {
				return StreamStats{}, ErrStreamTooLarge
			}
			chunkIndex++
			buf[0] = buf[chunkSize]
			carry = 1

		case errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF):
			// Reached EOF: emit the final chunk (total may be 0 for a 0-byte stream).
			binary.BigEndian.PutUint32(nonce[7:11], chunkIndex)
			nonce[11] = flagFinal

			ct := aead.Seal(frameBuf[4:4], nonce[:], buf[:total], header[:])
			binary.BigEndian.PutUint32(frameBuf[0:4], uint32(len(ct)))
			if _, err := cw.Write(frameBuf[:4+len(ct)]); err != nil {
				return StreamStats{}, fmt.Errorf("crypto: write final chunk %d: %w", chunkIndex, err)
			}

			plaintextBytes += int64(total)
			return StreamStats{
				PlaintextBytes:   plaintextBytes,
				CiphertextBytes:  cw.n,
				CiphertextSHA256: hex.EncodeToString(cw.h.Sum(nil)),
			}, nil

		default:
			return StreamStats{}, fmt.Errorf("crypto: read plaintext: %w", readErr)
		}
	}
}

// DecryptStream verifies the PGV1 stream header and decrypts chunks from r to w
// using constant O(chunkSize) memory. It detects bit-flips, truncation, chunk
// reordering, and rejects any trailing bytes after the final chunk.
func DecryptStream(r io.Reader, w io.Writer, dek []byte) error {
	if len(dek) != KeySize {
		return fmt.Errorf("%w: got DEK length %d", ErrInvalidKeySize, len(dek))
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return fmt.Errorf("crypto: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("crypto: create GCM: %w", err)
	}

	var header [StreamHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: incomplete header", ErrTruncatedStream)
		}
		return fmt.Errorf("crypto: read header: %w", err)
	}

	if string(header[0:4]) != StreamMagic {
		return fmt.Errorf("%w: bad magic %q", ErrInvalidHeader, header[0:4])
	}

	chunkSize := binary.BigEndian.Uint32(header[4:8])
	if chunkSize == 0 || chunkSize > MaxChunkSize {
		return fmt.Errorf("%w: invalid chunk size %d", ErrInvalidHeader, chunkSize)
	}

	overhead := uint32(aead.Overhead())
	maxFrameLen := chunkSize + overhead

	ctBuf := make([]byte, maxFrameLen)
	ptBuf := make([]byte, 0, chunkSize)

	var lenBuf [4]byte
	var nonce [gcmNonceSize]byte
	copy(nonce[0:noncePrefixSize], header[8:15])

	var chunkIndex uint32

	for {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: missing final chunk", ErrTruncatedStream)
			}
			return fmt.Errorf("crypto: read frame length: %w", err)
		}

		ctLen := binary.BigEndian.Uint32(lenBuf[:])
		if ctLen < overhead || ctLen > maxFrameLen {
			return fmt.Errorf("%w: invalid frame length %d", ErrDecryptionFailed, ctLen)
		}

		if _, err := io.ReadFull(r, ctBuf[:ctLen]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: incomplete frame body", ErrTruncatedStream)
			}
			return fmt.Errorf("crypto: read frame body: %w", err)
		}

		binary.BigEndian.PutUint32(nonce[7:11], chunkIndex)

		// Full-size frames are typically non-final; short frames are typically final.
		firstFlag, secondFlag := flagNotFinal, flagFinal
		if ctLen < maxFrameLen {
			firstFlag, secondFlag = flagFinal, flagNotFinal
		}

		nonce[11] = firstFlag
		pt, openErr := aead.Open(ptBuf[:0], nonce[:], ctBuf[:ctLen], header[:])
		isFinal := firstFlag == flagFinal
		if openErr != nil {
			nonce[11] = secondFlag
			pt, openErr = aead.Open(ptBuf[:0], nonce[:], ctBuf[:ctLen], header[:])
			if openErr != nil {
				return fmt.Errorf("%w: chunk %d authentication failed", ErrDecryptionFailed, chunkIndex)
			}
			isFinal = secondFlag == flagFinal
		}

		if isFinal {
			// Verify no trailing bytes exist after the final chunk before flushing final plaintext.
			var extra [1]byte
			n, trailErr := io.ReadFull(r, extra[:])
			if n > 0 || trailErr == nil {
				return ErrTrailingData
			}
			if !errors.Is(trailErr, io.EOF) {
				return fmt.Errorf("crypto: check trailing data: %w", trailErr)
			}

			if len(pt) > 0 {
				if _, err := w.Write(pt); err != nil {
					return fmt.Errorf("crypto: write final plaintext: %w", err)
				}
			}
			return nil
		}

		if len(pt) > 0 {
			if _, err := w.Write(pt); err != nil {
				return fmt.Errorf("crypto: write plaintext: %w", err)
			}
		}

		if chunkIndex == math.MaxUint32 {
			return ErrStreamTooLarge
		}
		chunkIndex++
	}
}
