package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	// MaxPasswordInputBytes stops a client from turning password hashing into
	// an unbounded allocation or CPU request.
	MaxPasswordInputBytes       = 4096
	maxEncodedPasswordHashBytes = 1024
	maxArgonMemoryKiB           = 128 * 1024
	maxArgonIterations          = 6
	maxArgonParallelism         = 4
)

var passwordWorkers = make(chan struct{}, 4)

type passwordParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var defaultPasswordParameters = passwordParameters{
	memory: 64 * 1024, iterations: 3, parallelism: 2, saltLength: 16, keyLength: 32,
}

// PasswordService owns the bounded password-verifier format. It has no
// database dependency, which keeps verification and rehash decisions easy to
// test and lets callers update credentials in their own transaction.
type PasswordService struct {
	parameters passwordParameters
}

// NewPasswordService returns the current Argon2id policy.
func NewPasswordService() *PasswordService {
	return &PasswordService{parameters: defaultPasswordParameters}
}

// Hash produces a versioned Argon2id verifier. The worker semaphore is shared
// process-wide so concurrent login and reset requests cannot multiply the
// memory budget beyond the configured maximum.
func (s *PasswordService) Hash(password string) (string, error) {
	if err := validatePasswordInput(password); err != nil {
		return "", err
	}
	params := s.parameters
	if err := validateParameters(params); err != nil {
		return "", err
	}
	salt := make([]byte, params.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := deriveArgon2id([]byte(password), salt, params)
	return fmt.Sprintf("$argon2id$v=1$m=%d,t=%d,p=%d$%s$%s",
		params.memory, params.iterations, params.parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyAndUpgrade verifies Argon2id or a legacy bcrypt verifier. A successful
// bcrypt verification returns a replacement Argon2id hash that callers must
// persist atomically with their authenticated state transition.
func (s *PasswordService) VerifyAndUpgrade(encodedHash, password string) (bool, string, error) {
	if err := validatePasswordInput(password); err != nil {
		return false, "", err
	}
	if len(encodedHash) == 0 || len(encodedHash) > maxEncodedPasswordHashBytes {
		return false, "", fmt.Errorf("password hash length is invalid")
	}
	if isBcryptHash(encodedHash) {
		err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, "", nil
		}
		if err != nil {
			return false, "", fmt.Errorf("verify legacy bcrypt password: %w", err)
		}
		upgrade, err := s.Hash(password)
		return err == nil, upgrade, err
	}
	params, salt, expected, err := decodeArgon2id(encodedHash)
	if err != nil {
		return false, "", err
	}
	actual := deriveArgon2id([]byte(password), salt, params)
	return subtle.ConstantTimeCompare(actual, expected) == 1, "", nil
}

// DummyVerify performs the same bounded Argon2id work used for a normal
// verifier without accepting any credential. Local login calls it for unknown
// or disabled accounts so account existence does not create a cheap timing
// oracle. Invalid client input is replaced with a fixed bounded value.
func (s *PasswordService) DummyVerify(password string) {
	if len(password) == 0 || len(password) > MaxPasswordInputBytes {
		password = "invalid-password-input"
	}
	_ = deriveArgon2id([]byte(password), make([]byte, defaultPasswordParameters.saltLength), defaultPasswordParameters)
}

func validatePasswordInput(password string) error {
	if len(password) == 0 || len(password) > MaxPasswordInputBytes {
		return fmt.Errorf("password must contain between 1 and %d bytes", MaxPasswordInputBytes)
	}
	return nil
}

func validateParameters(params passwordParameters) error {
	if err := validateArgonWork(params); err != nil || params.saltLength < 16 || params.keyLength < 16 || params.keyLength > 64 {
		return fmt.Errorf("argon2id parameters exceed supported bounds")
	}
	return nil
}

func validateArgonWork(params passwordParameters) error {
	if params.memory == 0 || params.memory > maxArgonMemoryKiB || params.iterations == 0 || params.iterations > maxArgonIterations ||
		params.parallelism == 0 || params.parallelism > maxArgonParallelism {
		return fmt.Errorf("argon2id work parameters exceed supported bounds")
	}
	return nil
}

func deriveArgon2id(password, salt []byte, params passwordParameters) []byte {
	passwordWorkers <- struct{}{}
	defer func() { <-passwordWorkers }()
	return argon2.IDKey(password, salt, params.iterations, params.memory, params.parallelism, params.keyLength)
}

func decodeArgon2id(encoded string) (passwordParameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=1" {
		return passwordParameters{}, nil, nil, fmt.Errorf("password hash format is invalid")
	}
	params, err := parseArgonParameters(parts[3])
	if err != nil {
		return passwordParameters{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return passwordParameters{}, nil, nil, fmt.Errorf("password hash salt is invalid")
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(hash) < 16 || len(hash) > 64 {
		return passwordParameters{}, nil, nil, fmt.Errorf("password hash digest is invalid")
	}
	params.saltLength = uint32(len(salt))
	params.keyLength = uint32(len(hash))
	if err := validateArgonWork(params); err != nil {
		return passwordParameters{}, nil, nil, err
	}
	return params, salt, hash, nil
}

func parseArgonParameters(value string) (passwordParameters, error) {
	fields := strings.Split(value, ",")
	if len(fields) != 3 {
		return passwordParameters{}, fmt.Errorf("password hash parameters are invalid")
	}
	values := map[string]uint64{}
	for _, field := range fields {
		key, raw, ok := strings.Cut(field, "=")
		if !ok || (key != "m" && key != "t" && key != "p") {
			return passwordParameters{}, fmt.Errorf("password hash parameters are invalid")
		}
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return passwordParameters{}, fmt.Errorf("password hash parameters are invalid")
		}
		values[key] = parsed
	}
	params := passwordParameters{memory: uint32(values["m"]), iterations: uint32(values["t"]), parallelism: uint8(values["p"])}
	if err := validateArgonWork(params); err != nil {
		return passwordParameters{}, err
	}
	return params, nil
}

func isBcryptHash(encoded string) bool {
	return strings.HasPrefix(encoded, "$2a$") || strings.HasPrefix(encoded, "$2b$") || strings.HasPrefix(encoded, "$2y$")
}
