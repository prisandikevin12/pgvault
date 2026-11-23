package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"
	"testing/iotest"
)

func TestGenerateDEK(t *testing.T) {
	dek1, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() unexpected error: %v", err)
	}
	if len(dek1) != KeySize {
		t.Fatalf("GenerateDEK() length = %d, want %d", len(dek1), KeySize)
	}

	dek2, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() second call unexpected error: %v", err)
	}
	if bytes.Equal(dek1, dek2) {
		t.Fatalf("GenerateDEK() produced identical keys twice")
	}
}

func TestWrapUnwrapDEK_Success(t *testing.T) {
	kek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK(kek) error: %v", err)
	}
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK(dek) error: %v", err)
	}

	wrapped1, err := WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK() unexpected error: %v", err)
	}
	// 12-byte nonce + 32-byte DEK + 16-byte GCM tag = 60 bytes
	const wantWrappedLen = 12 + KeySize + 16
	if len(wrapped1) != wantWrappedLen {
		t.Fatalf("len(wrapped) = %d, want %d", len(wrapped1), wantWrappedLen)
	}

	wrapped2, err := WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK() second call unexpected error: %v", err)
	}
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatalf("WrapDEK() produced identical ciphertexts; expected random nonce")
	}

	unwrapped, err := UnwrapDEK(kek, wrapped1)
	if err != nil {
		t.Fatalf("UnwrapDEK() unexpected error: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("UnwrapDEK() mismatch: got %x, want %x", unwrapped, dek)
	}
}

func TestWrapUnwrapDEK_WrongKEKAndTampering(t *testing.T) {
	kek1, _ := GenerateDEK()
	kek2, _ := GenerateDEK()
	dek, _ := GenerateDEK()

	wrapped, err := WrapDEK(kek1, dek)
	if err != nil {
		t.Fatalf("WrapDEK() error: %v", err)
	}

	// Wrong KEK
	if _, err := UnwrapDEK(kek2, wrapped); err == nil {
		t.Fatalf("UnwrapDEK() with wrong KEK succeeded, want error")
	}

	// Tampered byte in wrapped DEK
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := UnwrapDEK(kek1, tampered); err == nil {
		t.Fatalf("UnwrapDEK() with tampered ciphertext succeeded, want error")
	}

	// Truncated wrapped DEK
	for _, length := range []int{0, 11, 12, 27, len(wrapped) - 1} {
		if _, err := UnwrapDEK(kek1, wrapped[:length]); err == nil {
			t.Fatalf("UnwrapDEK() with truncated length %d succeeded, want error", length)
		}
	}

	// Valid AES-GCM ciphertext but wrong DEK plaintext length (16 bytes instead of 32)
	block, err := aes.NewCipher(kek1)
	if err != nil {
		t.Fatalf("aes.NewCipher() error: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("rand error: %v", err)
	}
	shortWrapped := gcm.Seal(nonce, nonce, make([]byte, 16), nil)
	if _, err := UnwrapDEK(kek1, shortWrapped); err == nil {
		t.Fatalf("UnwrapDEK() with 16-byte plaintext DEK succeeded, want error")
	}
}

func TestWrapUnwrapDEK_InvalidKeySize(t *testing.T) {
	validKey, _ := GenerateDEK()
	wrapped, err := WrapDEK(validKey, validKey)
	if err != nil {
		t.Fatalf("WrapDEK() setup error: %v", err)
	}

	invalidSizes := []int{0, 1, 16, 24, 31, 33, 64}
	for _, sz := range invalidSizes {
		badKey := make([]byte, sz)
		if _, err := WrapDEK(badKey, validKey); err == nil {
			t.Errorf("WrapDEK() with KEK size %d succeeded, want error", sz)
		}
		if _, err := WrapDEK(validKey, badKey); err == nil {
			t.Errorf("WrapDEK() with DEK size %d succeeded, want error", sz)
		}
		if _, err := UnwrapDEK(badKey, wrapped); err == nil {
			t.Errorf("UnwrapDEK() with KEK size %d succeeded, want error", sz)
		}
	}
}

func TestEncryptDecryptStream_RoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}

	cases := []struct {
		name      string
		size      int
		chunkSize int
	}{
		{name: "0_bytes", size: 0, chunkSize: 0},
		{name: "1_byte", size: 1, chunkSize: 0},
		{name: "exact_64KiB", size: 64 * 1024, chunkSize: 0},
		{name: "64KiB_plus_1", size: 64*1024 + 1, chunkSize: 0},
		{name: "approx_2.5MiB", size: 2*1024*1024 + 512*1024 + 137, chunkSize: 0},
		{name: "exact_2.5MiB", size: 2*1024*1024 + 512*1024, chunkSize: 0},
		{name: "custom_chunk_size_1KiB", size: 5000, chunkSize: 1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.size)
			if tc.size > 0 {
				if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
					t.Fatalf("rand read error: %v", err)
				}
			}

			var encrypted bytes.Buffer
			stats, err := EncryptStream(bytes.NewReader(plaintext), &encrypted, dek, tc.chunkSize)
			if err != nil {
				t.Fatalf("EncryptStream() error: %v", err)
			}

			// Verify stats
			if stats.PlaintextBytes != int64(tc.size) {
				t.Errorf("PlaintextBytes = %d, want %d", stats.PlaintextBytes, tc.size)
			}
			if stats.CiphertextBytes != int64(encrypted.Len()) {
				t.Errorf("CiphertextBytes = %d, want %d", stats.CiphertextBytes, encrypted.Len())
			}
			sum := sha256.Sum256(encrypted.Bytes())
			wantHash := hex.EncodeToString(sum[:])
			if stats.CiphertextSHA256 != wantHash {
				t.Errorf("CiphertextSHA256 = %q, want %q", stats.CiphertextSHA256, wantHash)
			}

			// Verify 15-byte header format
			raw := encrypted.Bytes()
			if len(raw) < 15 {
				t.Fatalf("encrypted output too short: %d bytes", len(raw))
			}
			if string(raw[:4]) != "PGV1" {
				t.Errorf("header magic = %q, want %q", string(raw[:4]), "PGV1")
			}
			wantChunkSize := uint32(DefaultChunkSize)
			if tc.chunkSize > 0 {
				wantChunkSize = uint32(tc.chunkSize)
			}
			if gotChunkSize := binary.BigEndian.Uint32(raw[4:8]); gotChunkSize != wantChunkSize {
				t.Errorf("header chunkSize = %d, want %d", gotChunkSize, wantChunkSize)
			}

			// 0-byte input must still emit 1 final chunk: 15B header + 4B len + 16B tag = 35B
			if tc.size == 0 && len(raw) != 15+4+16 {
				t.Errorf("0-byte encrypted length = %d, want %d", len(raw), 15+4+16)
			}

			// Round-trip decrypt
			var decrypted bytes.Buffer
			if err := DecryptStream(bytes.NewReader(raw), &decrypted, dek); err != nil {
				t.Fatalf("DecryptStream() error: %v", err)
			}
			if !bytes.Equal(decrypted.Bytes(), plaintext) {
				t.Fatalf("decrypted output does not match plaintext (got %d bytes, want %d bytes)", decrypted.Len(), len(plaintext))
			}
		})
	}
}

func TestEncryptDecryptStream_PartialReader(t *testing.T) {
	dek, _ := GenerateDEK()
	plaintext := make([]byte, 3000)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatalf("rand error: %v", err)
	}

	var encrypted bytes.Buffer
	_, err := EncryptStream(iotest.OneByteReader(bytes.NewReader(plaintext)), &encrypted, dek, 1024)
	if err != nil {
		t.Fatalf("EncryptStream() with OneByteReader error: %v", err)
	}

	var decrypted bytes.Buffer
	if err := DecryptStream(iotest.OneByteReader(bytes.NewReader(encrypted.Bytes())), &decrypted, dek); err != nil {
		t.Fatalf("DecryptStream() with OneByteReader error: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("decrypted output mismatch with OneByteReader")
	}
}

func TestDecryptStream_StreamsIncrementally(t *testing.T) {
	dek, _ := GenerateDEK()
	const chunkSize = 1024
	plaintext := make([]byte, chunkSize*3+100)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatalf("rand error: %v", err)
	}

	var encrypted bytes.Buffer
	if _, err := EncryptStream(bytes.NewReader(plaintext), &encrypted, dek, chunkSize); err != nil {
		t.Fatalf("EncryptStream() error: %v", err)
	}
	raw := encrypted.Bytes()

	// Feed only header + first frame into pipe; DecryptStream must emit chunk 0 before receiving the rest.
	firstFrameLen := binary.BigEndian.Uint32(raw[15:19])
	splitAt := 15 + 4 + int(firstFrameLen)

	pr, pw := io.Pipe()
	outR, outW := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		err := DecryptStream(pr, outW, dek)
		_ = outW.CloseWithError(err)
		errCh <- err
	}()

	// Write only the first frame
	go func() {
		if _, err := pw.Write(raw[:splitAt]); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
	}()

	// Read first decrypted chunk BEFORE writing remaining encrypted bytes
	firstChunk := make([]byte, chunkSize)
	if _, err := io.ReadFull(outR, firstChunk); err != nil {
		t.Fatalf("expected first chunk to stream out before EOF, got error: %v", err)
	}
	if !bytes.Equal(firstChunk, plaintext[:chunkSize]) {
		t.Fatalf("first streamed chunk mismatch")
	}

	// Now write remaining encrypted bytes and close pipe
	go func() {
		_, err := pw.Write(raw[splitAt:])
		_ = pw.CloseWithError(err)
	}()

	rest, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("reading remaining decrypted bytes failed: %v", err)
	}
	if !bytes.Equal(rest, plaintext[chunkSize:]) {
		t.Fatalf("remaining decrypted bytes mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("DecryptStream() returned error: %v", err)
	}
}

func TestEncryptDecryptStream_InvalidArgs(t *testing.T) {
	dek, _ := GenerateDEK()
	var buf bytes.Buffer

	if _, err := EncryptStream(bytes.NewReader(nil), &buf, make([]byte, 16), 0); err == nil {
		t.Errorf("EncryptStream() with 16-byte DEK succeeded, want error")
	}
	if _, err := EncryptStream(bytes.NewReader(nil), &buf, dek, -1); err == nil {
		t.Errorf("EncryptStream() with negative chunkSize succeeded, want error")
	}
	if err := DecryptStream(bytes.NewReader(nil), &buf, make([]byte, 16)); err == nil {
		t.Errorf("DecryptStream() with 16-byte DEK succeeded, want error")
	}
}

func encryptHelper(t *testing.T, size, chunkSize int) ([]byte, []byte, []byte) {
	t.Helper()
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}
	plaintext := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
			t.Fatalf("rand error: %v", err)
		}
	}
	var encrypted bytes.Buffer
	if _, err := EncryptStream(bytes.NewReader(plaintext), &encrypted, dek, chunkSize); err != nil {
		t.Fatalf("EncryptStream() error: %v", err)
	}
	return dek, plaintext, encrypted.Bytes()
}

func parseFrames(t *testing.T, stream []byte) [][]byte {
	t.Helper()
	if len(stream) < 15 {
		t.Fatalf("stream shorter than header: %d", len(stream))
	}
	var frames [][]byte
	off := 15
	for off < len(stream) {
		if off+4 > len(stream) {
			t.Fatalf("truncated frame length at offset %d", off)
		}
		ctLen := int(binary.BigEndian.Uint32(stream[off : off+4]))
		end := off + 4 + ctLen
		if end > len(stream) {
			t.Fatalf("truncated frame body at offset %d", off)
		}
		frame := append([]byte(nil), stream[off:end]...)
		frames = append(frames, frame)
		off = end
	}
	return frames
}

func TestDecryptStream_BitFlipCiphertext(t *testing.T) {
	dek, _, raw := encryptHelper(t, 3000, 1024)

	positions := []struct {
		name string
		pos  int
	}{
		{"header_chunkSize", 7},
		{"header_noncePrefix", 10},
		{"frame0_len", 18},
		{"frame0_ciphertext", 25},
		{"frame0_tag", 15 + 4 + 1024 + 8},
		{"last_frame_ciphertext", len(raw) - 20},
		{"last_frame_tag", len(raw) - 1},
	}

	for _, tc := range positions {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := append([]byte(nil), raw...)
			corrupted[tc.pos] ^= 0x01
			var out bytes.Buffer
			if err := DecryptStream(bytes.NewReader(corrupted), &out, dek); err == nil {
				t.Fatalf("DecryptStream() succeeded despite bit-flip at %s (offset %d)", tc.name, tc.pos)
			}
		})
	}
}

func TestDecryptStream_TruncatedStream(t *testing.T) {
	dek, _, raw := encryptHelper(t, 2500, 1024)
	frames := parseFrames(t, raw)
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}

	afterFrame0 := 15 + len(frames[0])
	afterFrame1 := afterFrame0 + len(frames[1])

	cases := []struct {
		name   string
		cutLen int
	}{
		{"empty_stream", 0},
		{"partial_header", 10},
		{"header_only_no_frames", 15},
		{"mid_frame0_len", 17},
		{"mid_frame0_body", 15 + 4 + 500},
		{"missing_last_two_chunks", afterFrame0},
		{"missing_final_chunk", afterFrame1},
		{"mid_final_chunk", len(raw) - 100},
		{"missing_last_byte", len(raw) - 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := DecryptStream(bytes.NewReader(raw[:tc.cutLen]), &out, dek); err == nil {
				t.Fatalf("DecryptStream() succeeded on truncated stream (%s, len=%d)", tc.name, tc.cutLen)
			}
		})
	}
}

func TestDecryptStream_SwappedChunks(t *testing.T) {
	dek, _, raw := encryptHelper(t, 2500, 1024)
	header := raw[:15]
	frames := parseFrames(t, raw)
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}

	t.Run("swap_chunk0_and_chunk1", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(header)
		buf.Write(frames[1])
		buf.Write(frames[0])
		buf.Write(frames[2])

		var out bytes.Buffer
		if err := DecryptStream(bytes.NewReader(buf.Bytes()), &out, dek); err == nil {
			t.Fatalf("DecryptStream() succeeded with chunk 0 and chunk 1 swapped")
		}
	})

	t.Run("swap_chunk1_and_final_chunk", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(header)
		buf.Write(frames[0])
		buf.Write(frames[2])
		buf.Write(frames[1])

		var out bytes.Buffer
		if err := DecryptStream(bytes.NewReader(buf.Bytes()), &out, dek); err == nil {
			t.Fatalf("DecryptStream() succeeded with chunk 1 and final chunk swapped")
		}
	})

	t.Run("duplicate_chunk0", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(header)
		buf.Write(frames[0])
		buf.Write(frames[0])
		buf.Write(frames[2])

		var out bytes.Buffer
		if err := DecryptStream(bytes.NewReader(buf.Bytes()), &out, dek); err == nil {
			t.Fatalf("DecryptStream() succeeded with duplicated chunk 0")
		}
	})
}

func TestDecryptStream_TrailingGarbageBytes(t *testing.T) {
	for _, size := range []int{0, 2500} {
		dek, _, raw := encryptHelper(t, size, 1024)

		for _, suffix := range [][]byte{{0x00}, []byte("trailing-garbage")} {
			corrupted := append(append([]byte(nil), raw...), suffix...)
			var out bytes.Buffer
			if err := DecryptStream(bytes.NewReader(corrupted), &out, dek); err == nil {
				t.Fatalf("DecryptStream() succeeded with %d trailing bytes (input size %d)", len(suffix), size)
			}
		}
	}
}

func TestDecryptStream_InvalidMagicAndWrongDEK(t *testing.T) {
	dek, _, raw := encryptHelper(t, 2500, 1024)

	t.Run("wrong_magic", func(t *testing.T) {
		corrupted := append([]byte(nil), raw...)
		copy(corrupted[:4], "PGV2")
		var out bytes.Buffer
		if err := DecryptStream(bytes.NewReader(corrupted), &out, dek); err == nil {
			t.Fatalf("DecryptStream() succeeded with wrong magic header")
		}
	})

	t.Run("zero_chunkSize_in_header", func(t *testing.T) {
		corrupted := append([]byte(nil), raw...)
		binary.BigEndian.PutUint32(corrupted[4:8], 0)
		var out bytes.Buffer
		if err := DecryptStream(bytes.NewReader(corrupted), &out, dek); err == nil {
			t.Fatalf("DecryptStream() succeeded with zero chunkSize in header")
		}
	})

	t.Run("wrong_DEK", func(t *testing.T) {
		wrongDEK, _ := GenerateDEK()
		var out bytes.Buffer
		if err := DecryptStream(bytes.NewReader(raw), &out, wrongDEK); err == nil {
			t.Fatalf("DecryptStream() succeeded with wrong DEK")
		}
	})
}
