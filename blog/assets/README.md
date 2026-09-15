# Diagram assets

Mermaid source with rendered SVG (for the post) and PNG (for CMSs that want raster).

| Figure | Source | Shows |
|---|---|---|
| 1 | `handshake-sequence.mmd` | Both enforcement points, and that frames bypass the WAF |
| 2 | `edge-topology.mmd` | Upgrade inspected, WebSocket frames never inspected |
| 3 | `trust-boundaries.mmd` | Which attacker capability each layer stops |

## Regenerating

```bash
for f in handshake-sequence edge-topology trust-boundaries; do
  npx -y @mermaid-js/mermaid-cli -i $f.mmd -o $f.svg -b transparent
  npx -y @mermaid-js/mermaid-cli -i $f.mmd -o $f.png -b white -s 2
done
```

## Two Mermaid gotchas hit while authoring these

**Use `#lt;` and `#gt;`, not `&lt;` and `&gt;`.** HTML entities are a parse error inside a sequence-diagram message. Figure 1 needs them to show `<ConversationRelay url="...">`.

**Don't set `primaryTextColor` on flowcharts.** It cascades into edge-label text, which then renders white on a white label background — the labels vanish silently, and they're the whole point of figure 2. Set node text colour via `classDef` instead.

## Palette

Twilio red `#F22F46`, navy `#0D122B`, light grey `#F4F4F6`, amber note `#FEF6E4`, green `#36D576`. Swap for current brand values before publication.
