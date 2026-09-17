# Lattice-based keyed-verification credentials

## Run and build

```sh
npm ci
npm run dev
```

`npm run build` produces the distributable presentation at `dist/index.html`.

## Export PDF

```sh
npm run check:setup
npm run pdf
```

The PDF is saved to `dist/lattice-based-keyed-verification-credentials.pdf`, with
one landscape page per slide. The export uses a separate print layout and keeps
the browser presentation unchanged.

## Browser checks

Playwright is a development dependency of this project, pinned in `package.json`
and `package-lock.json`. Install its Chromium browser once, then run the checks:

```sh
npm run check:setup
npm run check
```

The check builds the presentation and verifies slide navigation, math rendering,
readable text sizing, and access to all content at three window sizes. It imports
Playwright from this project's dependencies.
