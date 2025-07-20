# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JailJogger is a standalone web application for logging jail visits. It's a single-file HTML application (`jail-visit-secure-webapp.html`) that runs entirely in the browser with no server-side components or build process.

## Architecture

The entire application is contained in `jail-visit-secure-webapp.html` (943 lines) with:
- Embedded CSS styles in a `<style>` block
- Embedded JavaScript in a `<script>` block
- No external dependencies or frameworks
- Uses browser localStorage for data persistence
- Hardcoded authentication credentials

## Key Features

- User authentication (hardcoded credentials: username='dkarpay', password='Reservedness5050-propjoe')
- Visit logging with date, inmate name, location, and notes
- Speech recognition for voice input
- PDF generation for monthly reports
- Statistics dashboard
- Local data storage only (no server/database)

## Development Commands

This is a simple HTML file with no build process or dependencies:

```bash
# Open in browser directly
open jail-visit-secure-webapp.html

# Or use a simple HTTP server
python3 -m http.server 8000
# Then navigate to http://localhost:8000/jail-visit-secure-webapp.html
```

## Testing

No testing framework is currently implemented. Manual testing in browser is required.

## Important Considerations

1. **Security**: Authentication credentials are hardcoded in the JavaScript code and visible to anyone who views the source
2. **Data Storage**: All data is stored in browser localStorage - clearing browser data will delete all visits
3. **Browser Compatibility**: Uses modern browser APIs (Speech Recognition, localStorage) - may not work in older browsers
4. **No Version Control for Data**: No data backup or sync capabilities

## Code Style

When modifying the application:
- Keep all code in the single HTML file
- Use vanilla JavaScript (no frameworks)
- Follow the existing event-driven architecture
- Maintain the dark theme color scheme defined in CSS variables