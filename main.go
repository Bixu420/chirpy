package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Bixu420/chirpy/internal/auth"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	"github.com/Bixu420/chirpy/internal/database"
	_ "github.com/lib/pq"
)

func main() {

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("secret")
	db, _ := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)
	apiCfg := apiConfig{db: dbQueries, platform: platform, secret: secret}
	mux := http.NewServeMux()
	mux.Handle("/assets", http.FileServer(http.Dir("/assets")))
	fileHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileHandler))
	mux.HandleFunc("GET /api/healthz", healthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.hits)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/chirps", apiCfg.validate)
	mux.HandleFunc("GET /api/chirps", apiCfg.chirps)
	mux.HandleFunc("GET /api/chirps/{id}", apiCfg.getChirp)
	mux.HandleFunc("POST /api/users", apiCfg.addUser)
	mux.HandleFunc("POST /api/login", apiCfg.login)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	server.ListenAndServe()
	err := server.ListenAndServe()
	if err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}

func healthz(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}
func (a *apiConfig) hits(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", a.fileserverHits.Load())))
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Expiry   *int   `json:"expires_in_seconds"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	var expiry int
	if params.Expiry == nil || *params.Expiry > 3600 {
		expiry = 3600
	} else {
		expiry = int(*params.Expiry)
	}
	if err != nil {
		w.WriteHeader(500)
		return
	}
	user, err := cfg.db.GetUser(r.Context(), params.Email)
	hashed_password, _ := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if hashed_password == false {
		respondWithError(w, 401, "Invalid credentials")
		return
	} else {
		token, err := auth.MakeJWT(user.ID, cfg.secret, time.Duration(expiry)*time.Second)
		if err != nil {
			respondWithError(w, 500, "Error with token creation")
		}
		res := User{
			ID:        uuid.UUID(user.ID),
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
			Token:     token,
		}
		respondWithJSON(w, 200, res)
		return
	}
}
func (cfg *apiConfig) validate(w http.ResponseWriter, r *http.Request) {
	fmt.Println("validate handler reached")
	curse := []string{"kerfuffle", "sharbert", "fornax"}
	type parameters struct {
		Check   string    `json:"body"`
		User_Id uuid.UUID `json:"user_id"`
	}
	type succes struct {
		Succes string `json:"cleaned_body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	fmt.Println("decoded body:", params.Check)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	fmt.Println("token:", token)
	fmt.Println("token err:", err)
	valid, err := auth.ValidateJWT(token, cfg.secret)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}
	fmt.Println(len(params.Check))
	if len(params.Check) > 140 {
		respondWithError(w, 400, "Something went wrong")
		return
	} else {
		message := strings.Split(params.Check, " ")
		for idx, word := range message {
			if slices.Contains(curse, strings.ToLower(word)) {
				message[idx] = "****"
			}

		}
		message1 := strings.Join(message, " ")
		chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{Body: message1, UserID: valid})
		if err != nil {
			respondWithError(w, 500, "Operation faileddd")
			return
		}
		res := Chirp{
			ID:        uuid.UUID(chirp.ID),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		respondWithJSON(w, 201, res)
		return
	}
}
func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	fmt.Printf(" platform: %s", cfg.platform)
	if cfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden")
	} else {
		err := cfg.db.DeleteUsers(r.Context())
		if err != nil {
			fmt.Printf("Error creating user: %v\n", err)
			respondWithError(w, 500, "Couldn't create user")
			return
		}
	}
	cfg.fileserverHits.Store(0)
	w.WriteHeader(200)

}
func (cfg *apiConfig) addUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email          string `json:"email"`
		HashedPassword string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	hash, _ := auth.HashPassword(params.HashedPassword)
	params.HashedPassword = hash
	if err != nil {
		w.WriteHeader(500)
		return
	}
	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: params.HashedPassword})
	if err != nil {
		fmt.Printf("Error creating user: %v\n", err)
		respondWithError(w, 500, "Couldn't create user")
		return
	}
	res := User{
		ID:        uuid.UUID(user.ID),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}
	respondWithJSON(w, 201, res)
}
func respondWithError(w http.ResponseWriter, code int, msg string) {

	type returnVals struct {
		Message string `json:"error"`
	}
	respBody := returnVals{
		Message: msg,
	}
	dat, err := json.Marshal(respBody)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}
func (cfg *apiConfig) chirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		fmt.Printf("Error creating user: %v\n", err)
		respondWithError(w, 500, "Error fetching the data")
		return
	}
	chirp := []Chirp{}
	for _, dbChirp := range chirps {
		chirp = append(chirp, Chirp{ID: dbChirp.ID, CreatedAt: dbChirp.CreatedAt, UpdatedAt: dbChirp.UpdatedAt, Body: dbChirp.Body, UserID: dbChirp.UserID})
	}
	respondWithJSON(w, 200, chirp)

}
func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		respondWithError(w, 500, "Invalid ID")
		return
	}
	query, err := cfg.db.GetChirp(r.Context(), id)
	if err != nil {
		respondWithError(w, 404, "Chirp doesnt exist")
		return
	}
	response := Chirp{ID: query.ID, CreatedAt: query.CreatedAt, UpdatedAt: query.UpdatedAt, Body: query.Body, UserID: query.UserID}
	respondWithJSON(w, 200, response)
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
}
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}
