package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
	"github.com/prisandikevin12/pgvault/internal/notify"
	"github.com/prisandikevin12/pgvault/internal/pgdump"
	"github.com/prisandikevin12/pgvault/internal/queue"
	"github.com/prisandikevin12/pgvault/internal/verifier"
)

const (
	maxRequestBodyBytes = 1 << 20 // 1 MiB
	defaultIntervalSec  = 86400
	defaultMaxAttempts  = 3
)

// Config configures the HTTP API server.
type Config struct {
	KEK            []byte
	APIKey         string
	AllowedOrigins []string
	Logger         *slog.Logger
}

// Server serves the PGVault REST API.
type Server struct {
	pool           *pgxpool.Pool
	kek            []byte
	apiKey         string
	allowedOrigins map[string]bool
	logger         *slog.Logger
	handler        http.Handler
}

// ParseCORSOrigins parses a comma-separated list of CORS origins, trimming whitespace
// and trailing slashes. When empty, it defaults to localhost:3000 and 127.0.0.1:3000.
func ParseCORSOrigins(raw string) []string {
	var origins []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimRight(strings.TrimSpace(part), "/")
		if p != "" {
			origins = append(origins, p)
		}
	}
	if len(origins) == 0 {
		return []string{"http://localhost:3000", "http://127.0.0.1:3000"}
	}
	return origins
}

// NewServer constructs a configured HTTP API Server.
func NewServer(pool *pgxpool.Pool, cfg Config) (*Server, error) {
	if len(cfg.KEK) != crypto.KeySize {
		return nil, fmt.Errorf("api: KEK must be %d bytes, got %d", crypto.KeySize, len(cfg.KEK))
	}

	origins := cfg.AllowedOrigins
	if len(origins) == 0 {
		origins = ParseCORSOrigins("")
	}
	originSet := make(map[string]bool, len(origins))
	for _, o := range origins {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" {
			originSet[o] = true
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	kekCopy := make([]byte, len(cfg.KEK))
	copy(kekCopy, cfg.KEK)

	s := &Server{
		pool:           pool,
		kek:            kekCopy,
		apiKey:         strings.TrimSpace(cfg.APIKey),
		allowedOrigins: originSet,
		logger:         logger,
	}
	s.handler = s.buildHandler()
	return s, nil
}

// Handler returns the root http.Handler with CORS and authentication middlewares attached.
func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /api/v1/targets", s.handleListTargets)
	apiMux.HandleFunc("POST /api/v1/targets", s.handleCreateTarget)
	apiMux.HandleFunc("GET /api/v1/targets/{id}", s.handleGetTarget)
	apiMux.HandleFunc("PATCH /api/v1/targets/{id}", s.handleUpdateTarget)
	apiMux.HandleFunc("DELETE /api/v1/targets/{id}", s.handleDeleteTarget)
	apiMux.HandleFunc("POST /api/v1/targets/{id}/backups", s.handleTriggerBackup)
	apiMux.HandleFunc("GET /api/v1/jobs", s.handleListJobs)
	apiMux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	apiMux.HandleFunc("GET /api/v1/artifacts", s.handleListArtifacts)
	apiMux.HandleFunc("GET /api/v1/alerts", s.handleListAlerts)
	apiMux.HandleFunc("PUT /api/v1/alerts/telegram", s.handleUpsertTelegramAlert)

	mux.Handle("/api/v1/", s.authMiddleware(apiMux))

	return s.corsMiddleware(mux)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if s.allowedOrigins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		provided := ""
		if authHeader := strings.TrimSpace(r.Header.Get("Authorization")); authHeader != "" {
			if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
				provided = strings.TrimSpace(authHeader[7:])
			}
		}
		if provided == "" {
			provided = strings.TrimSpace(r.Header.Get("X-API-Key"))
		}

		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(s.apiKey)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Request & Response DTOs (never include plaintext DSN, storage secret key, or bot token)

type CreateTargetRequest struct {
	Name                  string `json:"name"`
	TargetDSN             string `json:"target_dsn"`
	StorageEndpoint       string `json:"storage_endpoint"`
	StorageRegion         string `json:"storage_region"`
	StorageBucket         string `json:"storage_bucket"`
	StorageAccessKey      string `json:"storage_access_key"`
	StorageSecretKey      string `json:"storage_secret_key"`
	StorageForcePathStyle bool   `json:"storage_force_path_style"`
	SanityQuery           string `json:"sanity_query"`
	ScheduleCron          string `json:"schedule_cron"`
	IntervalSeconds       int    `json:"interval_seconds"`
	RetentionKeepLast     int    `json:"retention_keep_last"`
	RetentionMaxAgeDays   int    `json:"retention_max_age_days"`
}

// Validate checks CreateTargetRequest fields and sanity query safety.
func (r CreateTargetRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(r.TargetDSN) == "" {
		return errors.New("target_dsn is required")
	}
	if strings.TrimSpace(r.StorageRegion) == "" {
		return errors.New("storage_region is required")
	}
	if strings.TrimSpace(r.StorageBucket) == "" {
		return errors.New("storage_bucket is required")
	}
	if err := validateOptionalEndpoint(r.StorageEndpoint); err != nil {
		return err
	}
	if r.IntervalSeconds < 0 {
		return errors.New("interval_seconds must be non-negative")
	}
	if r.RetentionKeepLast < 0 {
		return errors.New("retention_keep_last must be non-negative")
	}
	if r.RetentionMaxAgeDays < 0 {
		return errors.New("retention_max_age_days must be non-negative")
	}
	if err := verifier.ValidateSanityQuery(r.SanityQuery); err != nil {
		return err
	}
	return nil
}

type UpdateTargetRequest struct {
	Name                  *string `json:"name"`
	TargetDSN             *string `json:"target_dsn"`
	StorageEndpoint       *string `json:"storage_endpoint"`
	StorageRegion         *string `json:"storage_region"`
	StorageBucket         *string `json:"storage_bucket"`
	StorageAccessKey      *string `json:"storage_access_key"`
	StorageSecretKey      *string `json:"storage_secret_key"`
	StorageForcePathStyle *bool   `json:"storage_force_path_style"`
	SanityQuery           *string `json:"sanity_query"`
	ScheduleCron          *string `json:"schedule_cron"`
	IntervalSeconds       *int    `json:"interval_seconds"`
	RetentionKeepLast     *int    `json:"retention_keep_last"`
	RetentionMaxAgeDays   *int    `json:"retention_max_age_days"`
}

type TriggerBackupRequest struct {
	MaxAttempts int `json:"max_attempts"`
}

type UpsertTelegramAlertRequest struct {
	TargetID        *int64 `json:"target_id"`
	BotToken        string `json:"bot_token"`
	ChatID          string `json:"chat_id"`
	NotifyOnFailure bool   `json:"notify_on_failure"`
	NotifyOnSuccess bool   `json:"notify_on_success"`
	Enabled         bool   `json:"enabled"`
}

type TargetResponse struct {
	ID                    int64     `json:"id"`
	Name                  string    `json:"name"`
	HasTargetDSN          bool      `json:"has_target_dsn"`
	StorageEndpoint       string    `json:"storage_endpoint"`
	StorageRegion         string    `json:"storage_region"`
	StorageBucket         string    `json:"storage_bucket"`
	StorageAccessKey      string    `json:"storage_access_key"`
	HasStorageSecretKey   bool      `json:"has_storage_secret_key"`
	StorageForcePathStyle bool      `json:"storage_force_path_style"`
	SanityQuery           string     `json:"sanity_query"`
	ScheduleCron          string     `json:"schedule_cron"`
	IntervalSeconds       int        `json:"interval_seconds"`
	RetentionKeepLast     int        `json:"retention_keep_last"`
	RetentionMaxAgeDays   int        `json:"retention_max_age_days"`
	LastScheduledAt       *time.Time `json:"last_scheduled_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

type ArtifactResponse struct {
	ID                 int64                  `json:"id"`
	JobID              int64                  `json:"job_id"`
	TargetID           int64                  `json:"target_id"`
	ObjectKey          string                 `json:"object_key"`
	PlaintextBytes     int64                  `json:"plaintext_bytes"`
	CiphertextBytes    int64                  `json:"ciphertext_bytes"`
	CiphertextSHA256   string                 `json:"ciphertext_sha256"`
	PGMajorVersion     int                    `json:"pg_major_version"`
	Tables             []pgdump.TableSnapshot `json:"tables"`
	VerificationPassed bool                   `json:"verification_passed"`
	RestoreDurationMs  int64                  `json:"restore_duration_ms"`
	VerificationError  string                 `json:"verification_error"`
	PrunedAt           *time.Time             `json:"pruned_at,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
}

type JobResponse struct {
	ID             int64             `json:"id"`
	TargetID       int64             `json:"target_id"`
	Status         string            `json:"status"`
	Attempts       int               `json:"attempts"`
	MaxAttempts    int               `json:"max_attempts"`
	RunAfter       time.Time         `json:"run_after"`
	LockedAt       *time.Time        `json:"locked_at,omitempty"`
	LockedBy       string            `json:"locked_by,omitempty"`
	LeaseExpiresAt *time.Time        `json:"lease_expires_at,omitempty"`
	StartedAt      *time.Time        `json:"started_at,omitempty"`
	FinishedAt     *time.Time        `json:"finished_at,omitempty"`
	ErrorMessage   string            `json:"error_message,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	Artifact       *ArtifactResponse `json:"artifact,omitempty"`
}

type AlertChannelResponse struct {
	ID              int64     `json:"id"`
	TargetID        *int64    `json:"target_id"`
	ChannelType     string    `json:"channel_type"`
	HasBotToken     bool      `json:"has_bot_token"`
	ChatID          string    `json:"chat_id"`
	NotifyOnFailure bool      `json:"notify_on_failure"`
	NotifyOnSuccess bool      `json:"notify_on_success"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func toTargetResponse(t db.BackupTarget) TargetResponse {
	return TargetResponse{
		ID:                    t.ID,
		Name:                  t.Name,
		HasTargetDSN:          t.TargetDSN != "",
		StorageEndpoint:       t.StorageEndpoint,
		StorageRegion:         t.StorageRegion,
		StorageBucket:         t.StorageBucket,
		StorageAccessKey:      t.StorageAccessKey,
		HasStorageSecretKey:   t.StorageSecretKey != "",
		StorageForcePathStyle: t.StorageForcePathStyle,
		SanityQuery:           t.SanityQuery,
		ScheduleCron:          t.ScheduleCron,
		IntervalSeconds:       t.IntervalSeconds,
		RetentionKeepLast:     t.RetentionKeepLast,
		RetentionMaxAgeDays:   t.RetentionMaxAgeDays,
		LastScheduledAt:       t.LastScheduledAt,
		CreatedAt:             t.CreatedAt,
		UpdatedAt:             t.UpdatedAt,
	}
}

func toArtifactResponse(a db.BackupArtifact) ArtifactResponse {
	tables := a.Tables
	if tables == nil {
		tables = []pgdump.TableSnapshot{}
	}
	return ArtifactResponse{
		ID:                 a.ID,
		JobID:              a.JobID,
		TargetID:           a.TargetID,
		ObjectKey:          a.ObjectKey,
		PlaintextBytes:     a.PlaintextBytes,
		CiphertextBytes:    a.CiphertextBytes,
		CiphertextSHA256:   a.CiphertextSHA256,
		PGMajorVersion:     a.PGMajorVersion,
		Tables:             tables,
		VerificationPassed: a.VerificationPassed,
		RestoreDurationMs:  a.RestoreDurationMs,
		VerificationError:  a.VerificationError,
		PrunedAt:           a.PrunedAt,
		CreatedAt:          a.CreatedAt,
	}
}

func toJobResponse(j queue.Job, art *db.BackupArtifact) JobResponse {
	resp := JobResponse{
		ID:             j.ID,
		TargetID:       j.TargetID,
		Status:         j.Status,
		Attempts:       j.Attempts,
		MaxAttempts:    j.MaxAttempts,
		RunAfter:       j.RunAfter,
		LockedAt:       j.LockedAt,
		LockedBy:       j.LockedBy,
		LeaseExpiresAt: j.LeaseExpiresAt,
		StartedAt:      j.StartedAt,
		FinishedAt:     j.FinishedAt,
		ErrorMessage:   j.ErrorMessage,
		CreatedAt:      j.CreatedAt,
	}
	if art != nil {
		a := toArtifactResponse(*art)
		resp.Artifact = &a
	}
	return resp
}

func toAlertChannelResponse(ch db.AlertChannel) AlertChannelResponse {
	return AlertChannelResponse{
		ID:              ch.ID,
		TargetID:        ch.TargetID,
		ChannelType:     ch.ChannelType,
		HasBotToken:     ch.BotToken != "",
		ChatID:          ch.ChatID,
		NotifyOnFailure: ch.NotifyOnFailure,
		NotifyOnSuccess: ch.NotifyOnSuccess,
		Enabled:         ch.Enabled,
		CreatedAt:       ch.CreatedAt,
		UpdatedAt:       ch.UpdatedAt,
	}
}

// Handlers

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	targets, err := db.ListTargets(r.Context(), s.pool)
	if err != nil {
		s.internalError(w, "list targets", err)
		return
	}
	out := make([]TargetResponse, 0, len(targets))
	for _, t := range targets {
		out = append(out, toTargetResponse(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": out})
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var req CreateTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := req.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	protectedDSN, err := db.ProtectSecret(s.kek, strings.TrimSpace(req.TargetDSN))
	if err != nil {
		s.internalError(w, "encrypt target DSN", err)
		return
	}
	protectedSecret, err := db.ProtectSecret(s.kek, strings.TrimSpace(req.StorageSecretKey))
	if err != nil {
		s.internalError(w, "encrypt storage secret key", err)
		return
	}

	interval := req.IntervalSeconds
	if interval == 0 {
		interval = defaultIntervalSec
	}

	created, err := db.CreateTarget(r.Context(), s.pool, db.BackupTarget{
		Name:                  strings.TrimSpace(req.Name),
		TargetDSN:             protectedDSN,
		StorageEndpoint:       strings.TrimSpace(req.StorageEndpoint),
		StorageRegion:         strings.TrimSpace(req.StorageRegion),
		StorageBucket:         strings.TrimSpace(req.StorageBucket),
		StorageAccessKey:      strings.TrimSpace(req.StorageAccessKey),
		StorageSecretKey:      protectedSecret,
		StorageForcePathStyle: req.StorageForcePathStyle,
		SanityQuery:           strings.TrimSpace(req.SanityQuery),
		ScheduleCron:          strings.TrimSpace(req.ScheduleCron),
		IntervalSeconds:       interval,
		RetentionKeepLast:     req.RetentionKeepLast,
		RetentionMaxAgeDays:   req.RetentionMaxAgeDays,
	})
	if err != nil {
		if isPGCode(err, "23505") {
			writeJSONError(w, http.StatusConflict, "target with this name already exists")
			return
		}
		s.internalError(w, "create target", err)
		return
	}
	writeJSON(w, http.StatusCreated, toTargetResponse(*created))
}

func (s *Server) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r, "id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	target, err := db.GetTarget(r.Context(), s.pool, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "target not found")
			return
		}
		s.internalError(w, "get target", err)
		return
	}
	writeJSON(w, http.StatusOK, toTargetResponse(*target))
}

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r, "id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req UpdateTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	existing, err := db.GetTarget(r.Context(), s.pool, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "target not found")
			return
		}
		s.internalError(w, "load target for update", err)
		return
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "name cannot be empty")
			return
		}
		existing.Name = name
	}
	if req.TargetDSN != nil && strings.TrimSpace(*req.TargetDSN) != "" {
		enc, err := db.ProtectSecret(s.kek, strings.TrimSpace(*req.TargetDSN))
		if err != nil {
			s.internalError(w, "encrypt updated target DSN", err)
			return
		}
		existing.TargetDSN = enc
	}
	if req.StorageEndpoint != nil {
		ep := strings.TrimSpace(*req.StorageEndpoint)
		if err := validateOptionalEndpoint(ep); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.StorageEndpoint = ep
	}
	if req.StorageRegion != nil {
		reg := strings.TrimSpace(*req.StorageRegion)
		if reg == "" {
			writeJSONError(w, http.StatusBadRequest, "storage_region cannot be empty")
			return
		}
		existing.StorageRegion = reg
	}
	if req.StorageBucket != nil {
		bucket := strings.TrimSpace(*req.StorageBucket)
		if bucket == "" {
			writeJSONError(w, http.StatusBadRequest, "storage_bucket cannot be empty")
			return
		}
		existing.StorageBucket = bucket
	}
	if req.StorageAccessKey != nil {
		existing.StorageAccessKey = strings.TrimSpace(*req.StorageAccessKey)
	}
	if req.StorageSecretKey != nil && strings.TrimSpace(*req.StorageSecretKey) != "" {
		enc, err := db.ProtectSecret(s.kek, strings.TrimSpace(*req.StorageSecretKey))
		if err != nil {
			s.internalError(w, "encrypt updated storage secret", err)
			return
		}
		existing.StorageSecretKey = enc
	}
	if req.StorageForcePathStyle != nil {
		existing.StorageForcePathStyle = *req.StorageForcePathStyle
	}
	if req.SanityQuery != nil {
		sq := strings.TrimSpace(*req.SanityQuery)
		if err := verifier.ValidateSanityQuery(sq); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.SanityQuery = sq
	}
	if req.ScheduleCron != nil {
		existing.ScheduleCron = strings.TrimSpace(*req.ScheduleCron)
	}
	if req.IntervalSeconds != nil {
		if *req.IntervalSeconds <= 0 {
			writeJSONError(w, http.StatusBadRequest, "interval_seconds must be positive")
			return
		}
		existing.IntervalSeconds = *req.IntervalSeconds
	}
	if req.RetentionKeepLast != nil {
		if *req.RetentionKeepLast < 0 {
			writeJSONError(w, http.StatusBadRequest, "retention_keep_last must be non-negative")
			return
		}
		existing.RetentionKeepLast = *req.RetentionKeepLast
	}
	if req.RetentionMaxAgeDays != nil {
		if *req.RetentionMaxAgeDays < 0 {
			writeJSONError(w, http.StatusBadRequest, "retention_max_age_days must be non-negative")
			return
		}
		existing.RetentionMaxAgeDays = *req.RetentionMaxAgeDays
	}

	updated, err := db.UpdateTarget(r.Context(), s.pool, *existing)
	if err != nil {
		if isPGCode(err, "23505") {
			writeJSONError(w, http.StatusConflict, "target with this name already exists")
			return
		}
		s.internalError(w, "update target", err)
		return
	}
	writeJSON(w, http.StatusOK, toTargetResponse(*updated))
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r, "id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	deleted, err := db.DeleteTarget(r.Context(), s.pool, id)
	if err != nil {
		s.internalError(w, "delete target", err)
		return
	}
	if !deleted {
		writeJSONError(w, http.StatusNotFound, "target not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTriggerBackup(w http.ResponseWriter, r *http.Request) {
	targetID, err := parsePathID(r, "id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	var req TriggerBackupRequest
	if r.Body != nil {
		if err := decodeOptionalJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.MaxAttempts < 0 {
		writeJSONError(w, http.StatusBadRequest, "max_attempts must be non-negative")
		return
	}
	if req.MaxAttempts == 0 {
		req.MaxAttempts = defaultMaxAttempts
	}

	if _, err := db.GetTarget(r.Context(), s.pool, targetID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "target not found")
			return
		}
		s.internalError(w, "verify target before backup trigger", err)
		return
	}

	job, err := queue.EnqueueJob(r.Context(), s.pool, targetID, req.MaxAttempts, time.Now().UTC())
	if err != nil {
		s.internalError(w, "enqueue backup job", err)
		return
	}
	writeJSON(w, http.StatusAccepted, toJobResponse(*job, nil))
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	targetID, err := parseQueryInt64(r, "target_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := parseQueryInt(r, "limit", 50)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))

	jobs, err := queue.ListJobs(r.Context(), s.pool, targetID, status, limit)
	if err != nil {
		s.internalError(w, "list jobs", err)
		return
	}

	// Fetch artifacts for jobs cleanly so UI can display verification badges inline
	out := make([]JobResponse, 0, len(jobs))
	for _, j := range jobs {
		var art *db.BackupArtifact
		if a, err := db.GetArtifactByJobID(r.Context(), s.pool, j.ID); err == nil {
			art = a
		}
		out = append(out, toJobResponse(j, art))
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := parsePathID(r, "id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	job, err := queue.GetJob(r.Context(), s.pool, jobID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "job not found")
			return
		}
		s.internalError(w, "get job", err)
		return
	}

	var art *db.BackupArtifact
	if a, err := db.GetArtifactByJobID(r.Context(), s.pool, job.ID); err == nil {
		art = a
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.internalError(w, "get artifact for job", err)
		return
	}

	writeJSON(w, http.StatusOK, toJobResponse(*job, art))
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	targetID, err := parseQueryInt64(r, "target_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := parseQueryInt(r, "limit", 50)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	artifacts, err := db.ListArtifacts(r.Context(), s.pool, targetID, limit)
	if err != nil {
		s.internalError(w, "list artifacts", err)
		return
	}
	out := make([]ArtifactResponse, 0, len(artifacts))
	for _, a := range artifacts {
		out = append(out, toArtifactResponse(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": out})
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	channels, err := db.ListAllAlertChannels(r.Context(), s.pool)
	if err != nil {
		s.internalError(w, "list alerts", err)
		return
	}
	out := make([]AlertChannelResponse, 0, len(channels))
	for _, ch := range channels {
		out = append(out, toAlertChannelResponse(ch))
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": out})
}

func (s *Server) handleUpsertTelegramAlert(w http.ResponseWriter, r *http.Request) {
	var req UpsertTelegramAlertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.ChatID) == "" {
		writeJSONError(w, http.StatusBadRequest, "chat_id is required")
		return
	}
	if s.pool == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	protectedToken := ""
	if strings.TrimSpace(req.BotToken) != "" {
		enc, err := db.ProtectSecret(s.kek, strings.TrimSpace(req.BotToken))
		if err != nil {
			s.internalError(w, "encrypt telegram bot token", err)
			return
		}
		protectedToken = enc
	}

	saved, err := db.UpsertTelegramAlertChannel(r.Context(), s.pool, db.AlertChannel{
		TargetID:        req.TargetID,
		ChannelType:     "telegram",
		BotToken:        protectedToken,
		ChatID:          strings.TrimSpace(req.ChatID),
		NotifyOnFailure: req.NotifyOnFailure,
		NotifyOnSuccess: req.NotifyOnSuccess,
		Enabled:         req.Enabled,
	})
	if err != nil {
		if isPGCode(err, "23503") {
			writeJSONError(w, http.StatusNotFound, "referenced target_id not found")
			return
		}
		if strings.Contains(err.Error(), "bot_token is required") {
			writeJSONError(w, http.StatusBadRequest, "bot_token is required when creating a new telegram alert channel")
			return
		}
		s.internalError(w, "upsert telegram alert", err)
		return
	}
	writeJSON(w, http.StatusOK, toAlertChannelResponse(*saved))
}

// Helpers

func (s *Server) internalError(w http.ResponseWriter, op string, err error) {
	s.logger.Error("api internal error", "op", op, "error", notify.SanitizeMessage(err.Error()))
	writeJSONError(w, http.StatusInternalServerError, "internal server error")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

func parsePathID(r *http.Request, name string) (int64, error) {
	raw := r.PathValue(name)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	return id, nil
}

func parseQueryInt64(r *http.Request, key string) (*int64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return nil, fmt.Errorf("invalid %s query parameter", key)
	}
	return &v, nil
}

func parseQueryInt(r *http.Request, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid %s query parameter", key)
	}
	return v, nil
}

func validateOptionalEndpoint(ep string) error {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return nil
	}
	u, err := url.Parse(ep)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("storage_endpoint must be a valid http or https URL")
	}
	return nil
}

func isPGCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
