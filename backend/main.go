package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"

	"attack-surface-monitor/backend/agent"
	"attack-surface-monitor/backend/db"
	"attack-surface-monitor/backend/handlers"
	"attack-surface-monitor/backend/middleware"
)

func main() {
	// Load .env file if exists
	godotenv.Load()
	// Get environment variables
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	openAIKey := os.Getenv("OPENAI_API_KEY")
	if openAIKey == "" {
		log.Fatal("OPENAI_API_KEY is required")
	}

	// Initialize database
	if err := db.InitDB(dataDir); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	log.Println("Database initialized")

	// Initialize OpenAI client
	agent.InitOpenAI(openAIKey)
	log.Println("OpenAI client initialized")

	// Initialize WebSocket hub
	handlers.InitHub()
	log.Println("WebSocket hub initialized")

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} ${latency}\n",
	}))
	app.Use(middleware.Config())

	// Health check
	app.Get("/health", handlers.HealthCheck)

	// API routes
	api := app.Group("/api")
	api.Post("/scan", handlers.StartScan)
	api.Get("/scan/:id", handlers.GetScan)
	api.Get("/scans", handlers.ListScans)

	// WebSocket route
	app.Get("/ws/scan/:id", handlers.WebSocketHandler)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Server starting on port %s", port)
		if err := app.Listen(":" + port); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-quit
	log.Println("Shutting down server...")

	if err := app.Shutdown(); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
