Chisel server --tls-key key.pem --tls-cert cert.pem -p 4443 -v --socks5
Curl -k https://fdksa



import http.server
import ssl
import socketserver
# Define the port you want the server to listen on
PORT = 4443
# Set up a simple HTTP request handler
Handler = http.server.SimpleHTTPRequestHandler
# Create an HTTP server with the specified handler
httpd = socketserver.TCPServer(("", PORT), Handler)
# Wrap the server socket with SSL for HTTPS
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='cert.pem',
                               keyfile='key.pem',
                               ssl_version=ssl.PROTOCOL_TLS)
print(f"Serving HTTPS on port {PORT}")
# Serve until interrupted
httpd.serve_forever()
