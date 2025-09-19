#!/usr/bin/env python3

import pygame
import socket
import threading
import json
import sys
import queue

pygame.init()

# --- Setup ---
WIDTH, HEIGHT = 600, 400
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Pygame Client")

font = pygame.font.Font(None, 32)
clock = pygame.time.Clock()

# --- Networking globals ---
client_socket = None
network_thread = None
running = True
incoming_messages = queue.Queue()

def network_loop(sock):
    """Runs in background thread, listens for server messages."""
    sock.settimeout(0.5)  # avoid blocking forever
    while running:
        try:
            data = sock.recv(1024)
            if not data:
                break
            msg = data.decode("utf-8").strip()
            incoming_messages.put(msg)
        except socket.timeout:
            continue
        except OSError:
            break

# --- Simple InputBox for username/password ---
class InputBox:
    def __init__(self, x, y, w, h, text='', password=False):
        self.rect = pygame.Rect(x, y, w, h)
        self.color_inactive = pygame.Color('lightskyblue3')
        self.color_active = pygame.Color('dodgerblue2')
        self.color = self.color_inactive
        self.text = text
        self.txt_surface = font.render(text, True, self.color)
        self.active = False
        self.password = password

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            self.active = self.rect.collidepoint(event.pos)
            self.color = self.color_active if self.active else self.color_inactive
        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            else:
                self.text += event.unicode
            disp = "*" * len(self.text) if self.password else self.text
            self.txt_surface = font.render(disp, True, self.color)

    def draw(self, screen):
        screen.blit(self.txt_surface, (self.rect.x+5, self.rect.y+5))
        pygame.draw.rect(screen, self.color, self.rect, 2)

# --- UI Elements ---
username_box = InputBox(150, 50, 200, 32)
password_box = InputBox(150, 100, 200, 32, password=True)
button_rect = pygame.Rect(200, 160, 100, 40)

connected = False
status_msg = "Not connected"

# --- Main Loop ---
while True:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
            if client_socket:
                client_socket.close()
            pygame.quit()
            sys.exit()

        username_box.handle_event(event)
        password_box.handle_event(event)

        if event.type == pygame.MOUSEBUTTONDOWN:
            if button_rect.collidepoint(event.pos) and not connected:
                # Try to connect
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect(("127.0.0.1", 5000))

                    # Send login JSON
                    payload = {
                        "username": username_box.text,
                        "password": password_box.text
                    }
                    client_socket.sendall(json.dumps(payload).encode("utf-8"))

                    # Start background thread
                    network_thread = threading.Thread(target=network_loop, args=(client_socket,))
                    network_thread.daemon = True
                    network_thread.start()

                    connected = True
                    status_msg = "Connected!"
                except Exception as e:
                    status_msg = f"Connect failed: {e}"

    # --- Process incoming messages ---
    while not incoming_messages.empty():
        raw = incoming_messages.get()
        try:
            msg = json.loads(raw)
            status_msg = f"Server: {msg.get('status', raw)}"
        except json.JSONDecodeError:
            status_msg = f"Server raw: {raw}"

    # --- Draw ---
    screen.fill((30, 30, 30))
    screen.blit(font.render("Username:", True, pygame.Color("white")), (60, 55))
    screen.blit(font.render("Password:", True, pygame.Color("white")), (60, 105))

    username_box.draw(screen)
    password_box.draw(screen)

    if not connected:
        pygame.draw.rect(screen, pygame.Color("green"), button_rect)
        btn_label = font.render("Connect", True, pygame.Color("white"))
        screen.blit(btn_label, btn_label.get_rect(center=button_rect.center))

    status_surface = font.render(status_msg, True, pygame.Color("yellow"))
    screen.blit(status_surface, (50, 250))

    pygame.display.flip()
    clock.tick(30)

