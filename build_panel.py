"""Bundle local UI sources/art into one deployable, dependency-free HTML file."""
import base64
from pathlib import Path

ROOT = Path(__file__).parent
template = (ROOT / 'web/panel-shell.html').read_text(encoding='utf-8')
css = (ROOT / 'web/panel.css').read_text(encoding='utf-8')
js = (ROOT / 'web/panel.js').read_text(encoding='utf-8')
art = base64.b64encode((ROOT / 'assets/anime-hero.webp').read_bytes()).decode()
page = template.replace('/* PANEL_CSS */', css).replace('/* PANEL_JS */', js).replace('__HERO_DATA__', art)
for token, filename in [('__MANROPE_FONT__', 'manrope.woff2'), ('__CORMORANT_FONT__', 'cormorant-garamond.woff2'), ('__LORA_FONT__', 'lora.woff2')]:
    page = page.replace(token, base64.b64encode((ROOT / 'assets/fonts' / filename).read_bytes()).decode())
for token, filename in [('__DARK_ART__', 'rose-moon-dark.webp'), ('__LIGHT_ART__', 'rose-moon-light.webp')]:
    page = page.replace(token, base64.b64encode((ROOT / 'assets' / filename).read_bytes()).decode())
(ROOT / 'panel.html').write_text(page, encoding='utf-8')
print('Bundled panel.html with local artwork; no third-party CDN requests.')

# Keep server-side installer bundled so updates from older three-file updaters work.
backend = ROOT / 'panel.py'
source = backend.read_text(encoding='utf-8')
a = source.index('# BEGIN EMBEDDED AWG INSTALLER')
b = source.index('# END EMBEDDED AWG INSTALLER', a)
script = (ROOT / 'awg-install.sh').read_text(encoding='utf-8')
source = source[:a] + '# BEGIN EMBEDDED AWG INSTALLER\nAWG_INSTALL_SCRIPT = ' + repr(script) + '\n' + source[b:]
backend.write_text(source, encoding='utf-8')
