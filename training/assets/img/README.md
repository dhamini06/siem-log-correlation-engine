# Brand assets

Drop the official **BlueCloud Softech Solutions** logo here as:

```
bluecloud-logo.png
```

The header in every page already references this exact path. Once the file is present, replacing
the `BC` monogram is a one-line change per page (7 pages):

```html
<!-- current placeholder -->
<div class="brand-mark" aria-hidden="true">BC</div>

<!-- official logo -->
<img class="brand-mark" src="assets/img/bluecloud-logo.png" alt="BlueCloud Softech Solutions">
```

Sizing is already handled for both logo shapes — a square icon mark and a wide horizontal
wordmark render correctly without touching the CSS, because `img.brand-mark` uses
`object-fit: contain` with a 44px height and no fixed width. A PNG, JPG, SVG or WebP all work;
SVG is preferred if an SVG is available because it stays sharp at any DPI.

Nothing else needs to change: the header height, the 68px bar, the navigation, and the
BlueCloud Softech Solutions wordmark beside the mark all stay as they are.
