"""Disposable SPA for browser writes; never use production CRM for these tests."""
from http.server import BaseHTTPRequestHandler, HTTPServer

HTML = b'''<!doctype html><html><head><title>DAOOS fixture</title></head><body>
<nav><a href="#home">Home</a> <a href="#dialogs">Dialogs</a></nav>
<h1>Fixture</h1><input id="text" aria-label="Text"><button id="count">Increment</button>
<output id="result">0</output><output id="auth"></output><div id="spa"></div><input type="file" id="file"><a id="download" href="/download" download="fixture.txt">Download</a>
<script>
document.querySelector('#auth').textContent='saved='+localStorage.getItem('count')+' cookie='+document.cookie;let count=0;document.querySelector('#count').onclick=()=>{document.querySelector('#result').textContent=++count;localStorage.setItem('count',count);document.cookie='fixture=authorized; SameSite=Lax'};
setTimeout(()=>{document.querySelector('#spa').textContent='SPA ready'},150);
window.onhashchange=()=>document.querySelector('h1').textContent=location.hash;
</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect-private':
            self.send_response(302); self.send_header('Location','http://169.254.169.254/latest/meta-data/'); self.end_headers(); return
        if self.path == '/download':
            self.send_response(200); self.send_header('Content-Disposition','attachment; filename="fixture.txt"'); self.end_headers(); self.wfile.write(b'fixture download'); return
        self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers(); self.wfile.write(HTML)
    def log_message(self,*args): pass

HTTPServer(('0.0.0.0',80),Handler).serve_forever()
