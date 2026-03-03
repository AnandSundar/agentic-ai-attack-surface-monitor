package handlers

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
)

// WSEvent represents a WebSocket event
type WSEvent struct {
	Type      string      `json:"type"`
	Message   string      `json:"message,omitempty"`
	Tool      string      `json:"tool,omitempty"`
	Input     interface{} `json:"input,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Subdomain string      `json:"subdomain,omitempty"`
	Risk      string      `json:"risk,omitempty"`
	Details   interface{} `json:"details,omitempty"`
	Summary   string      `json:"summary,omitempty"`
}

// Client represents a WebSocket client
type Client struct {
	ScanID string
	Conn   *websocket.Conn
	Send   chan []byte
}

// Hub maintains the set of active clients
type Hub struct {
	// ScanID -> map of clients
	clients map[string]map[*Client]bool
	// Broadcast channel
	Broadcast chan BroadcastMessage
	// Register client
	Register chan *Client
	// Unregister client
	Unregister chan *Client
	// Mutex for thread-safe access
	mutex sync.RWMutex
}

// BroadcastMessage represents a message to broadcast
type BroadcastMessage struct {
	ScanID string
	Event  WSEvent
}

// Global hub instance
var globalHub *Hub

// NewHub creates a new hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]map[*Client]bool),
		Broadcast:  make(chan BroadcastMessage, 256),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
	}
}

// Run starts the hub's run loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.mutex.Lock()
			if h.clients[client.ScanID] == nil {
				h.clients[client.ScanID] = make(map[*Client]bool)
			}
			h.clients[client.ScanID][client] = true
			h.mutex.Unlock()
			log.Printf("Client registered for scan %s", client.ScanID)

		case client := <-h.Unregister:
			h.mutex.Lock()
			if clients, ok := h.clients[client.ScanID]; ok {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					close(client.Send)
					if len(clients) == 0 {
						delete(h.clients, client.ScanID)
					}
				}
			}
			h.mutex.Unlock()
			log.Printf("Client unregistered for scan %s", client.ScanID)

		case message := <-h.Broadcast:
			h.mutex.RLock()
			clients := h.clients[message.ScanID]
			h.mutex.RUnlock()

			for client := range clients {
				select {
				case client.Send <- mustMarshal(message.Event):
				default:
					// Buffer full - close send channel and remove client
					close(client.Send)
					h.mutex.Lock()
					delete(clients, client)
					h.mutex.Unlock()
					// Properly unregister the client
					globalHub.Unregister <- client
				}
			}
		}
	}
}

func mustMarshal(event WSEvent) []byte {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Error marshaling event: %v", err)
		return []byte(`{"type":"error","message":"Failed to marshal event"}`)
	}
	return data
}

// InitHub initializes the global hub
func InitHub() {
	globalHub = NewHub()
	go globalHub.Run()
}

// BroadcastToScan broadcasts an event to all clients subscribed to a scan
func BroadcastToScan(scanID string, event WSEvent) {
	if globalHub != nil {
		globalHub.Broadcast <- BroadcastMessage{
			ScanID: scanID,
			Event:  event,
		}
	}
}

// WebSocketHandler handles WebSocket connections using fiber's websocket middleware
func WebSocketHandler(c *fiber.Ctx) error {
	scanID := c.Params("id")
	if scanID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Scan ID required",
		})
	}

	// Use fiber's websocket helper
	return websocket.New(func(conn *websocket.Conn) {
		client := &Client{
			ScanID: scanID,
			Conn:   conn,
			Send:   make(chan []byte, 256),
		}

		globalHub.Register <- client

		go writePump(client)
		go readPump(client)

		// Keep connection alive
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	})(c)
}

// readPump reads messages from the WebSocket connection
func readPump(client *Client) {
	defer func() {
		globalHub.Unregister <- client
		client.Conn.Close()
	}()

	for {
		_, _, err := client.Conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// writePump writes messages to the WebSocket connection
func writePump(client *Client) {
	defer client.Conn.Close()

	for {
		message, ok := <-client.Send
		if !ok {
			client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}

		if err := client.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
			return
		}
	}
}
