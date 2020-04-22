#!/usr/bin/env python3

import http.server
import socketserver

from config import PORT


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        input("Received a GET. Server is suspended. Press Enter to continue...")
        http.server.SimpleHTTPRequestHandler.do_GET(self)


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("serving at port:", PORT)
        httpd.serve_forever()
