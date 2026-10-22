HTML documentation of the PKI DevSecOps Agantra project - version 7.8.3
Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com

HOW TO OPEN
  1. Double-click index.html (any modern browser), or
  2. Run  .\Serve-Docs.ps1  (or: python3 -m http.server 1434 --directory html) and open
     http://localhost:1434/index.html

FILES
  *.html   one page per document. Every page has its own HTML5, CSS 3 and JavaScript inside.
           Nothing is shared between pages except the font files.
  fonts\   Roboto, Roboto Mono, Material Symbols and Font Awesome (Free) as local .woff2 files,
           with their licenses (SIL OFL 1.1 and CC BY 4.0). Keep this folder next to the pages.

The pages are made by Build-HtmlDocs.ps1 from the text documents in docs\ . Do not edit them by hand:
change the text document and run the script again (or run it with -Watch).
