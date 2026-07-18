package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/wnc-replay/replay-tool/analysis"
	"github.com/wnc-replay/replay-tool/dissect"
	docs "github.com/wnc-replay/replay-tool/docs"
)

// APIRound is one entry returned by POST /replay.
type APIRound struct {
	FileName string      `json:"fileName"`
	Error    string      `json:"error,omitempty"`
	Round    *FullOutput `json:"round,omitempty"`
}

// APIError is returned when an API request cannot be processed.
type APIError struct {
	Context string `json:"context"`
	Error   string `json:"error,omitempty"`
}

// @title Replay Tool API
// @version 1.0
// @description Analyze Rainbow Six Siege replay rounds using replay-tool.
// @BasePath /
// @schemes http
func runAPI(port string, swaggerEnabled bool) error {
	address, err := apiAddress(port)
	if err != nil {
		return err
	}

	router := gin.Default()
	router.Use(corsMiddleware())
	router.GET("/test", testHandler)
	router.POST("/round", roundHandler)
	router.POST("/replay", replayHandler)
	if swaggerEnabled {
		docs.SwaggerInfo.Host = "localhost" + address
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		fmt.Printf("Swagger UI available at http://localhost%s/swagger/index.html\n", address)
	}

	fmt.Printf("Replay API listening on http://localhost%s\n", address)
	return router.Run(address)
}

func apiAddress(port string) (string, error) {
	port = strings.TrimPrefix(strings.TrimSpace(port), ":")
	if port == "" {
		return "", fmt.Errorf("--api requires a port")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", fmt.Errorf("invalid API port %q: %w", port, err)
	}
	return ":" + port, nil
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// testHandler godoc
// @Summary Test API availability
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /test [get]
func testHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
}

// roundHandler godoc
// @Summary Analyze one replay round
// @Description Upload a Rainbow Six Siege .rec file and return the full replay-tool analysis.
// @Tags replay
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Replay round (.rec)"
// @Param trim query bool false "Empty player frames, entities, camera frames, library shots, and library ammo updates to reduce response size"
// @Success 200 {object} FullOutput
// @Failure 400 {object} APIError
// @Router /round [post]
func roundHandler(c *gin.Context) {
	header, err := c.FormFile("file")
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error fetching form file", err)
		return
	}
	file, err := header.Open()
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error opening file stream", err)
		return
	}
	defer file.Close()

	output, err := analyzeReplay(file)
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error parsing replay", err)
		return
	}
	if c.Query("trim") == "true" {
		trimAnalysis(&output)
	}
	c.JSON(http.StatusOK, output)
}

// replayHandler godoc
// @Summary Analyze a replay archive
// @Description Upload a ZIP archive containing replay round files and analyze every non-directory entry.
// @Tags replay
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Replay ZIP archive"
// @Param trim query bool false "Empty player frames, entities, camera frames, library shots, and library ammo updates to reduce response size"
// @Success 200 {array} APIRound
// @Failure 400 {object} APIError
// @Router /replay [post]
func replayHandler(c *gin.Context) {
	header, err := c.FormFile("file")
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error fetching form file", err)
		return
	}
	file, err := header.Open()
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error opening file stream", err)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error copying file to buffer", err)
		return
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, "Error creating zip reader", err)
		return
	}

	rounds := make([]APIRound, 0, len(archive.File))
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		item := APIRound{FileName: entry.Name}
		stream, openErr := entry.Open()
		if openErr != nil {
			item.Error = openErr.Error()
			rounds = append(rounds, item)
			continue
		}
		output, parseErr := analyzeReplay(stream)
		stream.Close()
		if parseErr != nil {
			item.Error = parseErr.Error()
		} else {
			if c.Query("trim") == "true" {
				trimAnalysis(&output)
			}
			item.Round = &output
		}
		rounds = append(rounds, item)
	}
	c.JSON(http.StatusOK, rounds)
}

func analyzeReplay(source io.Reader) (FullOutput, error) {
	reader, err := dissect.NewReader(source)
	if err != nil {
		return FullOutput{}, err
	}
	var raw bytes.Buffer
	reader.Write(&raw)
	if err := reader.Read(); err != nil && !dissect.Ok(err) {
		return FullOutput{}, err
	}
	output := buildOutput(reader, raw.Bytes(), false)
	enrichAnalysis(&output, reader)
	return output, nil
}

func trimAnalysis(output *FullOutput) {
	if output.Analysis == nil {
		return
	}
	for i := range output.Analysis.Players {
		output.Analysis.Players[i].Frames = make([]analysis.PosFrame, 0)
	}
	output.Analysis.Entities = make([]analysis.EntityTrack, 0)
	output.Analysis.CameraFrames = make([]analysis.LibraryCameraFrame, 0)
	output.Analysis.LibraryShots = make([]analysis.LibraryShotEntry, 0)
	output.Analysis.LibraryAmmoUpdates = make([]analysis.LibraryAmmoUpdate, 0)
}

func writeAPIError(c *gin.Context, status int, context string, err error) {
	response := gin.H{"context": context}
	if err != nil {
		response["error"] = err.Error()
	}
	c.JSON(status, response)
}
