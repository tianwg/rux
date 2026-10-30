//! A small VT100/xterm screen model for terminal blocks.
//!
//! This is deliberately not a complete terminal: it covers the control
//! sequences shells, pagers, and full-screen programs use most often, keeps a
//! grid with attributes and scrollback, and can render the result as text,
//! HTML, or a VT redraw. Unknown sequences are ignored rather than fatal.

use std::collections::{BTreeMap, VecDeque};

use base64::Engine;
use chrono::Utc;
use serde_json::{Value, json};

use unicode_width::UnicodeWidthChar;
use vte::{Params, Perform};

const SCROLLBACK_LIMIT: usize = 10_000;
const PROGRAM_STATUS_LIMIT: usize = 256;
const OSC_BUFFER_SIZE: usize = 131_072;

#[derive(Clone)]
struct ProgramStatusRecord {
    id: String,
    state: String,
    kind: Option<String>,
    progress: Option<u8>,
    app: Option<String>,
    title: Option<String>,
    msg: Option<String>,
    updated_at: String,
    touched_at: std::time::Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    Default,
    Palette(u8),
    Rgb(u8, u8, u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pen {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub blink: bool,
    pub inverse: bool,
    pub hidden: bool,
    pub strike: bool,
}

#[derive(Clone, Default)]
struct Theme {
    foreground: Option<(u8, u8, u8)>,
    background: Option<(u8, u8, u8)>,
    cursor: Option<(u8, u8, u8)>,
    palette: BTreeMap<u8, (u8, u8, u8)>,
    scheme: Option<String>,
}

impl Default for Pen {
    fn default() -> Self {
        Self {
            fg: Color::Default,
            bg: Color::Default,
            bold: false,
            dim: false,
            italic: false,
            underline: false,
            blink: false,
            inverse: false,
            hidden: false,
            strike: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub ch: char,
    pub pen: Pen,
    /// True for the second column of a double-width character.
    pub cont: bool,
}

impl Cell {
    fn blank(pen: Pen) -> Self {
        Self {
            ch: ' ',
            pen,
            cont: false,
        }
    }
}

#[derive(Clone, Debug)]
struct Line {
    cells: Vec<Cell>,
    /// True when the terminal wrapped this line onto the next one.
    wrapped: bool,
}

/// Scrollback storage: normally the live cell grid. When a terminal
/// goes idle the grid is packed - serialized into pen-run segments
/// and zlib-compressed - and dropped, then restored transparently on
/// the next access, so a packed scrollback behaves exactly like a
/// live one at a fraction of the memory. Every scrollback touch goes
/// through this wrapper for that reason.
struct Scrollback {
    state: std::cell::RefCell<ScrollbackState>,
}

enum ScrollbackState {
    Live(VecDeque<Line>),
    Packed { bytes: Vec<u8>, lines: usize },
}

/// Below this many lines, packing is not worth the churn.
const SCROLLBACK_PACK_MIN_LINES: usize = 64;

impl Scrollback {
    fn new() -> Self {
        Self {
            state: std::cell::RefCell::new(ScrollbackState::Live(VecDeque::new())),
        }
    }

    fn len(&self) -> usize {
        match &*self.state.borrow() {
            ScrollbackState::Live(lines) => lines.len(),
            ScrollbackState::Packed { lines, .. } => *lines,
        }
    }

    fn clear(&self) {
        *self.state.borrow_mut() = ScrollbackState::Live(VecDeque::new());
    }

    /// Restore the live grid if packed. A corrupt blob restores as an
    /// empty scrollback rather than failing: history is a record of
    /// what scrolled away, never the only copy of live state.
    fn restore(&self) {
        let bytes = {
            let mut state = self.state.borrow_mut();
            if let ScrollbackState::Packed { bytes, .. } = &mut *state {
                std::mem::take(bytes)
            } else {
                return;
            }
        };
        let lines = unpack_scrollback(&bytes);
        *self.state.borrow_mut() = ScrollbackState::Live(lines);
    }

    fn live(&self) -> std::cell::RefMut<'_, VecDeque<Line>> {
        self.restore();
        std::cell::RefMut::map(self.state.borrow_mut(), |state| match state {
            ScrollbackState::Live(lines) => lines,
            ScrollbackState::Packed { .. } => unreachable!("restore leaves the grid live"),
        })
    }

    fn restored(&self) -> std::cell::Ref<'_, VecDeque<Line>> {
        self.restore();
        std::cell::Ref::map(self.state.borrow(), |state| match state {
            ScrollbackState::Live(lines) => lines,
            ScrollbackState::Packed { .. } => unreachable!("restore leaves the grid live"),
        })
    }

    fn push_back(&self, line: Line) {
        self.live().push_back(line);
    }

    fn pop_front(&self) -> Option<Line> {
        self.live().pop_front()
    }

    /// Pack the live grid, returning the packed byte count.
    fn pack(&self) -> Option<usize> {
        let mut state = self.state.borrow_mut();
        let ScrollbackState::Live(lines) = &*state else {
            return None;
        };
        if lines.len() < SCROLLBACK_PACK_MIN_LINES {
            return None;
        }
        let bytes = pack_scrollback(lines);
        let count = lines.len();
        let packed = bytes.len();
        *state = ScrollbackState::Packed {
            bytes,
            lines: count,
        };
        Some(packed)
    }

    fn is_packed(&self) -> bool {
        matches!(&*self.state.borrow(), ScrollbackState::Packed { .. })
    }
}

/// All lines a format renders: scrollback history followed by
/// the visible grid, with trailing empty lines trimmed. Borrowed,
/// never cloned: a format over a deep scrollback reads each line
/// once, and deep-copying every line's cells first cost more than
/// the rendering itself.
fn visible_lines<'a>(scrollback: &'a VecDeque<Line>, screen: &'a [Line]) -> Vec<&'a Line> {
    let mut lines: Vec<&Line> = scrollback.iter().chain(screen.iter()).collect();
    while lines.len() > 1 && line_text(lines.last().unwrap(), true).is_empty() {
        lines.pop();
    }
    lines
}

fn pack_color(out: &mut Vec<u8>, color: Color) {
    match color {
        Color::Default => out.push(0),
        Color::Palette(index) => {
            out.push(1);
            out.push(index);
        }
        Color::Rgb(r, g, b) => out.extend_from_slice(&[2, r, g, b]),
    }
}

fn pen_bits(pen: &Pen) -> u16 {
    let flags = [
        pen.bold,
        pen.dim,
        pen.italic,
        pen.underline,
        pen.blink,
        pen.inverse,
        pen.hidden,
        pen.strike,
    ];
    let mut bits = 0u16;
    for (i, on) in flags.iter().enumerate() {
        if *on {
            bits |= 1 << i;
        }
    }
    bits
}

fn pen_from_bits(bits: u16) -> Pen {
    let on = |i: u16| bits & (1 << i) != 0;
    Pen {
        fg: Color::Default,
        bg: Color::Default,
        bold: on(0),
        dim: on(1),
        italic: on(2),
        underline: on(3),
        blink: on(4),
        inverse: on(5),
        hidden: on(6),
        strike: on(7),
    }
}

/// Serialize the scrollback as maximal runs of cells sharing a pen
/// and width flag, then zlib-compress the whole thing. Typical
/// scrollback is short text runs and long blank tails, so this lands
/// at a small fraction of the live grid's size.
fn pack_scrollback(lines: &VecDeque<Line>) -> Vec<u8> {
    use std::io::Write as _;
    let mut raw = Vec::new();
    raw.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    for line in lines {
        let mut body = Vec::new();
        let mut segments = 0u32;
        let mut i = 0;
        while i < line.cells.len() {
            let first = &line.cells[i];
            let mut j = i + 1;
            while j < line.cells.len()
                && line.cells[j].pen == first.pen
                && line.cells[j].cont == first.cont
            {
                j += 1;
            }
            pack_color(&mut body, first.pen.fg);
            pack_color(&mut body, first.pen.bg);
            body.extend_from_slice(&pen_bits(&first.pen).to_le_bytes());
            body.push(first.cont as u8);
            body.extend_from_slice(&((j - i) as u32).to_le_bytes());
            for cell in &line.cells[i..j] {
                body.extend_from_slice(&(cell.ch as u32).to_le_bytes());
            }
            segments += 1;
            i = j;
        }
        raw.push(line.wrapped as u8);
        raw.extend_from_slice(&segments.to_le_bytes());
        raw.extend_from_slice(&body);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = encoder.write_all(&raw);
    encoder.finish().unwrap_or_default()
}

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn color(&mut self) -> Option<Color> {
        match self.u8()? {
            0 => Some(Color::Default),
            1 => Some(Color::Palette(self.u8()?)),
            2 => {
                let b = self.take(3)?;
                Some(Color::Rgb(b[0], b[1], b[2]))
            }
            _ => None,
        }
    }
}

/// Inverse of pack_scrollback. Any inconsistency yields an empty
/// scrollback (see Scrollback::restore).
fn unpack_scrollback(bytes: &[u8]) -> VecDeque<Line> {
    use std::io::Read as _;
    let mut raw = Vec::new();
    if flate2::read::ZlibDecoder::new(bytes)
        .read_to_end(&mut raw)
        .is_err()
    {
        return VecDeque::new();
    }
    let mut reader = ByteReader { buf: &raw, pos: 0 };
    let Some(count) = reader.u32() else {
        return VecDeque::new();
    };
    if count as usize > SCROLLBACK_LIMIT {
        return VecDeque::new();
    }
    let mut lines = VecDeque::with_capacity(count as usize);
    for _ in 0..count {
        let (Some(wrapped), Some(segments)) = (reader.u8(), reader.u32()) else {
            return VecDeque::new();
        };
        let mut cells: Vec<Cell> = Vec::new();
        for _ in 0..segments {
            let (Some(fg), Some(bg), Some(bits), Some(cont), Some(n)) = (
                reader.color(),
                reader.color(),
                reader.u16(),
                reader.u8(),
                reader.u32(),
            ) else {
                return VecDeque::new();
            };
            if n > 1_000_000 {
                return VecDeque::new();
            }
            let mut pen = pen_from_bits(bits);
            pen.fg = fg;
            pen.bg = bg;
            for _ in 0..n {
                let Some(ch) = reader.u32().and_then(char::from_u32) else {
                    return VecDeque::new();
                };
                cells.push(Cell {
                    ch,
                    pen,
                    cont: cont != 0,
                });
            }
        }
        lines.push_back(Line {
            cells,
            wrapped: wrapped != 0,
        });
    }
    lines
}

#[derive(Clone, Copy, Default, Debug)]
struct Cursor {
    row: usize,
    col: usize,
}

struct AltState {
    lines: Vec<Line>,
    cursor: Cursor,
    saved: Option<(Cursor, Pen, bool)>,
    scroll_top: usize,
    scroll_bottom: usize,
    wrap_pending: bool,
    placements: Vec<Placement>,
}

/// An image held by the terminal: a Kitty transmission (kept in its
/// wire form for replay, decoded when raw) or a decoded sixel.
#[derive(Clone)]
struct StoredImage {
    width: u32,
    height: u32,
    /// Decoded RGBA pixels, row-major. Empty for PNG transmissions,
    /// whose pixels the server never needs.
    rgba: Vec<u8>,
    /// The Kitty wire format of `data` (24, 32, or 100).
    kitty_format: Option<u32>,
    /// Wire-form bytes: raw pixels for formats 24/32, the PNG for 100.
    data: Vec<u8>,
}

/// One on-screen display of an image, anchored to a cell.
#[derive(Clone)]
struct Placement {
    image: u32,
    placement_id: u32,
    row: usize,
    col: usize,
    x_px: u32,
    y_px: u32,
    src_x: u32,
    src_y: u32,
    src_w: u32,
    src_h: u32,
    cell_cols: u32,
    cell_rows: u32,
    z: i32,
    /// A sixel placement's original DCS parameters and payload, which
    /// `format_vt` replays verbatim.
    sixel: Option<(Vec<u16>, Vec<u8>)>,
}

/// A Kitty transmission arriving in chunks (`m=1` on all but the last).
struct KittyPending {
    control: Vec<(String, String)>,
    data: Vec<u8>,
}

/// A DCS sequence being collected between `hook` and `unhook`.
struct DcsState {
    params: Vec<u16>,
    intermediates: Vec<u8>,
    action: char,
    data: Vec<u8>,
}

pub struct Screen {
    cols: usize,
    rows: usize,
    lines: Vec<Line>,
    scrollback: Scrollback,
    cursor: Cursor,
    saved: Option<(Cursor, Pen, bool)>,
    pen: Pen,
    scroll_top: usize,
    scroll_bottom: usize,
    wrap_pending: bool,
    last_char: char,
    alt: Option<AltState>,
    title: String,
    pwd: String,
    cursor_visible: bool,
    bracketed_paste: bool,
    application_cursor: bool,
    mouse_x10: bool,
    mouse_normal: bool,
    mouse_button: bool,
    mouse_any: bool,
    mouse_utf8: bool,
    mouse_sgr: bool,
    mouse_urxvt: bool,
    focus_reporting: bool,
    sync_output: bool,
    sixel_scroll: bool,
    images: std::collections::HashMap<u32, StoredImage>,
    placements: Vec<Placement>,
    next_image_id: u32,
    kitty_pending: Option<KittyPending>,
    apc: Option<Vec<u8>>,
    apc_esc: bool,
    esc_pending: bool,
    dcs: Option<DcsState>,
    kitty_stack: Vec<u16>,
    title_stack: Vec<String>,
    insert_mode: bool,
    auto_wrap: bool,
    responses: Vec<u8>,
    program_status: BTreeMap<String, ProgramStatusRecord>,
    /// Set after a real OSC 7501 report. OSC 9;4 stops updating the root
    /// record once this is true, until a full reset.
    saw_program_status: bool,
    status_events: Vec<(String, Value)>,
    clipboard_copies: BTreeMap<u64, (String, std::time::Instant)>,
    next_clipboard_id: u64,
    theme: Theme,
    parser: Box<vte::Parser<OSC_BUFFER_SIZE>>,
}

/// How much mouse input the application asked to be told about,
/// strongest last: DECSET 9 (X10, press only), 1000 (press/release),
/// 1002 (plus motion while a button is held), 1003 (all motion).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MouseTracking {
    #[default]
    Off,
    X10,
    Normal,
    Button,
    Any,
}

/// The wire format the application asked mouse reports to use:
/// DECSET 1005 (UTF-8), 1006 (SGR), 1015 (urxvt). X10 is the default.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MouseFormat {
    #[default]
    X10,
    Utf8,
    Sgr,
    Urxvt,
}

/// Encode one mouse report the way the application asked for it.
/// `button` is the xterm button number (0/1/2 for left/middle/right,
/// 64/65/66/67 for wheel up/down/left/right), already including the
/// modifier bits (+4 shift, +8 alt, +16 ctrl); `x`/`y` are 1-based
/// cells. Callers gate on the tracking mode: this always encodes.
pub fn encode_mouse_report(
    format: MouseFormat,
    button: u8,
    x: u32,
    y: u32,
    release: bool,
    motion: bool,
) -> Vec<u8> {
    let mut b = button;
    if motion {
        b += 32;
    }
    match format {
        MouseFormat::Sgr => format!("\x1b[<{b};{x};{y}{}", if release { 'm' } else { 'M' })
            .into_bytes(),
        MouseFormat::Urxvt => {
            if release {
                b = 3;
            }
            format!("\x1b[{};{x};{y}M", b + 32).into_bytes()
        }
        MouseFormat::X10 | MouseFormat::Utf8 => {
            if release {
                b = 3;
            }
            let mut out = b"\x1b[M".to_vec();
            for v in [u32::from(b) + 32, x + 32, y + 32] {
                if format == MouseFormat::Utf8 {
                    let mut buf = [0u8; 4];
                    let ch = char::from_u32(v).unwrap_or('\u{fffd}');
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                } else {
                    out.push(v.min(255) as u8);
                }
            }
            out
        }
    }
}

/// Rows per PAGE record when scrollback is shipped in a snapshot.
/// Small enough that a decoder never has to allocate a giant page,
/// large enough that 10,000 rows of history take only ten records.
const HISTORY_PAGE_ROWS: usize = 1_000;

/// Encode one snapshot PAGE payload for a contiguous run of rows,
/// oldest first. The style table is built from these rows alone, as
/// the format scopes styles per page. `wrapped_from_previous` is the
/// wrap flag of the row just before this run, for the first row's
/// continuation bit.
fn encode_snapshot_page(lines: &[Line], cols: u16, wrapped_from_previous: bool) -> Vec<u8> {
    let styles: Vec<Pen> = lines
        .iter()
        .flat_map(|line| line.cells.iter().map(|cell| cell.pen))
        .filter(|pen| *pen != Pen::default())
        .fold(Vec::new(), |mut styles, pen| {
            if !styles.contains(&pen) {
                styles.push(pen);
            }
            styles
        });
    let rows = lines.len().min(u16::MAX as usize);
    let mut page = Vec::new();
    put_u16(&mut page, cols);
    put_u16(&mut page, rows as u16);
    put_u16(&mut page, styles.len().min(u16::MAX as usize) as u16);
    put_u16(&mut page, 0); // No hyperlinks.
    put_u16(&mut page, styles.len().min(u16::MAX as usize) as u16);
    put_u16(&mut page, 0); // Hyperlink allocation hint.
    put_u32(&mut page, 0); // Grapheme allocation hint.
    put_u32(&mut page, 0); // String allocation hint.
    for (index, style) in styles.iter().enumerate() {
        put_u16(&mut page, (index + 1).min(u16::MAX as usize) as u16);
        put_ghostty_style(&mut page, *style);
    }
    for (row, line) in lines.iter().enumerate().take(rows) {
        let last = line
            .cells
            .iter()
            .rposition(|cell| cell.ch != ' ' || cell.cont || cell.pen != Pen::default());
        let Some(last) = last else {
            page.extend_from_slice(&[0, 0, 0]);
            continue;
        };
        let count = (last + 1).min(u16::MAX as usize);
        let wrapped_from_previous = if row > 0 {
            lines[row - 1].wrapped
        } else {
            wrapped_from_previous
        };
        let row_flags =
            u8::from(line.wrapped) | (u8::from(wrapped_from_previous) << 1) | (3 << 4);
        page.push(row_flags);
        put_u16(&mut page, count as u16);
        for col in 0..count {
            let cell = line.cells[col];
            let style_id = if cell.pen == Pen::default() {
                0
            } else {
                styles
                    .iter()
                    .position(|style| *style == cell.pen)
                    .map(|index| index + 1)
                    .unwrap_or(0)
                    .min(u16::MAX as usize) as u16
            };
            let width = if cell.cont {
                2u64 // Spacer tail.
            } else if col + 1 < line.cells.len() && line.cells[col + 1].cont {
                1u64 // Wide character.
            } else {
                0u64
            };
            let codepoint = if cell.cont { 0 } else { cell.ch as u32 };
            let word = ((codepoint as u64 & 0x00ff_ffff) << 2)
                | ((style_id as u64) << 26)
                | (width << 42);
            put_u64(&mut page, word);
        }
    }
    put_u32(&mut page, 0); // No grapheme suffixes.
    page
}

impl Screen {
    pub fn new(cols: u16, rows: u16) -> Self {
        let cols = cols.max(1) as usize;
        let rows = rows.max(1) as usize;
        Self {
            cols,
            rows,
            lines: vec![blank_line(cols); rows],
            scrollback: Scrollback::new(),
            cursor: Cursor::default(),
            saved: None,
            pen: Pen::default(),
            scroll_top: 0,
            scroll_bottom: rows - 1,
            wrap_pending: false,
            last_char: ' ',
            alt: None,
            title: String::new(),
            pwd: String::new(),
            cursor_visible: true,
            bracketed_paste: false,
            application_cursor: false,
            mouse_x10: false,
            mouse_normal: false,
            mouse_button: false,
            mouse_any: false,
            mouse_utf8: false,
            mouse_sgr: false,
            mouse_urxvt: false,
            focus_reporting: false,
            sync_output: false,
            sixel_scroll: true,
            images: std::collections::HashMap::new(),
            placements: Vec::new(),
            next_image_id: 0x8000_0000,
            kitty_pending: None,
            apc: None,
            apc_esc: false,
            esc_pending: false,
            dcs: None,
            kitty_stack: Vec::new(),
            title_stack: Vec::new(),
            insert_mode: false,
            auto_wrap: true,
            responses: Vec::new(),
            program_status: BTreeMap::new(),
            saw_program_status: false,
            status_events: Vec::new(),
            clipboard_copies: BTreeMap::new(),
            next_clipboard_id: 1,
            theme: Theme::default(),
            parser: Box::new(vte::Parser::<OSC_BUFFER_SIZE>::new_with_size()),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        let mut parser = std::mem::take(&mut self.parser);
        for &byte in bytes {
            if self.apc.is_some() {
                if self.apc_esc {
                    self.apc_esc = false;
                    if byte == b'\\' {
                        let body = self.apc.take().unwrap_or_default();
                        self.kitty_apc(&body);
                    } else if let Some(buffer) = &mut self.apc {
                        buffer.extend_from_slice(&[0x1b, byte]);
                    }
                } else if byte == 0x1b {
                    self.apc_esc = true;
                } else if byte == 0x9c {
                    let body = self.apc.take().unwrap_or_default();
                    self.kitty_apc(&body);
                } else if let Some(buffer) = &mut self.apc {
                    if buffer.len() < 36_000_000 {
                        buffer.push(byte);
                    }
                }
            } else if self.esc_pending {
                self.esc_pending = false;
                if byte == b'_' {
                    self.apc = Some(Vec::new());
                } else {
                    parser.advance(self, 0x1b);
                    parser.advance(self, byte);
                }
            } else if byte == 0x1b {
                self.esc_pending = true;
            } else {
                parser.advance(self, byte);
            }
        }
        self.parser = parser;
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn pwd(&self) -> &str {
        &self.pwd
    }

    pub fn take_responses(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.responses)
    }

    pub fn take_status_events(&mut self) -> Vec<(String, Value)> {
        std::mem::take(&mut self.status_events)
    }

    pub fn program_status_records(&self) -> Vec<Value> {
        self.program_status
            .values()
            .map(|record| {
                let mut value = json!({
                    "state": record.state,
                    "updated_at": record.updated_at,
                });
                if !record.id.is_empty() {
                    value["id"] = json!(record.id);
                }
                if let Some(kind) = &record.kind {
                    value["kind"] = json!(kind);
                }
                if let Some(progress) = record.progress {
                    value["progress"] = json!(progress);
                }
                if let Some(app) = &record.app {
                    value["app"] = json!(app);
                }
                if let Some(app) = self.effective_app(&record.id) {
                    value["effective_app"] = json!(app);
                }
                if let Some(title) = &record.title {
                    value["title"] = json!(title);
                }
                if let Some(msg) = &record.msg {
                    value["msg"] = json!(msg);
                }
                value
            })
            .collect()
    }

    pub fn clipboard_copy(&mut self, id: u64) -> Option<(u64, String)> {
        let now = std::time::Instant::now();
        self.clipboard_copies
            .retain(|_, (_, created)| now.duration_since(*created).as_secs() < 60);
        let id = if id == 0 {
            *self.clipboard_copies.keys().max()?
        } else {
            id
        };
        self.clipboard_copies
            .get(&id)
            .map(|(text, _)| (id, text.clone()))
    }

    /// One complete APC string. Only `G` (Kitty graphics) is handled;
    /// other APC users are ignored, as they were when the parser
    /// discarded the string.
    fn kitty_apc(&mut self, body: &[u8]) {
        if body.first() != Some(&b'G') {
            return;
        }
        let body = &body[1..];
        let (control_raw, payload) = match body.iter().position(|byte| *byte == b';') {
            Some(index) => (&body[..index], &body[index + 1..]),
            None => (body, &[][..]),
        };
        let mut control: Vec<(String, String)> = Vec::new();
        for pair in control_raw.split(|byte| *byte == b',') {
            if pair.is_empty() {
                continue;
            }
            let pair = String::from_utf8_lossy(pair);
            match pair.split_once('=') {
                Some((key, value)) => control.push((key.to_string(), value.to_string())),
                None => control.push((pair.into_owned(), String::new())),
            }
        }
        let more = kitty_key(&control, "m") == Some("1");
        if self.kitty_pending.is_some() {
            let mut pending = self.kitty_pending.take().unwrap();
            pending.data.extend_from_slice(payload);
            if pending.data.len() > 48_000_000 {
                self.kitty_pending = None;
                return;
            }
            if more {
                self.kitty_pending = Some(pending);
                return;
            }
            self.kitty_finish(pending.control, &pending.data);
            return;
        }
        if more {
            self.kitty_pending = Some(KittyPending {
                control,
                data: payload.to_vec(),
            });
            return;
        }
        self.kitty_finish(control, payload);
    }

    fn kitty_finish(&mut self, control: Vec<(String, String)>, payload: &[u8]) {
        let action = kitty_key(&control, "a").unwrap_or("T");
        let id = kitty_key(&control, "i").and_then(|value| value.parse::<u32>().ok());
        match action {
            "q" | "t" | "T" => {
                let decoded = self.kitty_decode(&control, payload);
                match decoded {
                    Ok((format, width, height, wire, rgba)) => {
                        self.kitty_respond(id, Ok(()));
                        if action == "q" {
                            return;
                        }
                        let image_id = match id {
                            Some(id) => id,
                            None => {
                                self.next_image_id = self.next_image_id.wrapping_add(1);
                                self.next_image_id
                            }
                        };
                        self.images.insert(
                            image_id,
                            StoredImage {
                                width,
                                height,
                                rgba,
                                kitty_format: Some(format),
                                data: wire,
                            },
                        );
                        if action == "T" {
                            self.kitty_place(&control, image_id);
                        }
                    }
                    Err(error) => self.kitty_respond(id, Err(error)),
                }
            }
            "p" => {
                let Some(image_id) = id else {
                    return;
                };
                if self.images.contains_key(&image_id) {
                    self.kitty_place(&control, image_id);
                    self.kitty_respond(id, Ok(()));
                } else {
                    self.kitty_respond(id, Err("no such image".into()));
                }
            }
            "d" => {
                self.kitty_delete(&control);
                self.kitty_respond(id, Ok(()));
            }
            "f" => {
                self.kitty_respond(id, Err("animation frames are not supported".into()));
            }
            _ => {}
        }
    }

    /// Decode a transmission payload into wire bytes plus RGBA pixels.
    /// PNG (format 100) is kept in wire form; its size comes from the
    /// IHDR header.
    fn kitty_decode(
        &self,
        control: &[(String, String)],
        payload: &[u8],
    ) -> Result<(u32, u32, u32, Vec<u8>, Vec<u8>), String> {
        if let Some(kind) = kitty_key(control, "t")
            && kind != "d"
        {
            return Err("only direct transmissions are supported".into());
        }
        let format: u32 = kitty_key(control, "f")
            .and_then(|value| value.parse().ok())
            .unwrap_or(32);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload))
            .map_err(|_| "the payload is not valid base64".to_string())?;
        if decoded.len() > 32 * 1024 * 1024 {
            return Err("the image is too large".into());
        }
        let data = match kitty_key(control, "o") {
            None => decoded,
            Some("z") => {
                use std::io::Read as _;
                let mut out = Vec::new();
                let mut decoder = flate2::read::ZlibDecoder::new(decoded.as_slice());
                let mut limited = decoder.by_ref().take(64 * 1024 * 1024 + 1);
                limited
                    .read_to_end(&mut out)
                    .map_err(|_| "the compressed payload did not inflate".to_string())?;
                if out.len() > 64 * 1024 * 1024 {
                    return Err("the image is too large".into());
                }
                out
            }
            Some(_) => return Err("unsupported compression".into()),
        };
        match format {
            24 | 32 => {
                let width = kitty_key(control, "s")
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|value| *value > 0)
                    .ok_or("a raw transmission needs s and v")?;
                let height = kitty_key(control, "v")
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|value| *value > 0)
                    .ok_or("a raw transmission needs s and v")?;
                if width > 10_000 || height > 10_000 {
                    return Err("the image dimensions are too large".into());
                }
                let channels = if format == 24 { 3usize } else { 4usize };
                let expected = width as usize * height as usize * channels;
                if data.len() != expected {
                    return Err("the payload size does not match s and v".into());
                }
                let rgba = if format == 32 {
                    data.clone()
                } else {
                    let mut rgba = Vec::with_capacity(width as usize * height as usize * 4);
                    for pixel in data.chunks_exact(3) {
                        rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 255]);
                    }
                    rgba
                };
                Ok((format, width, height, data, rgba))
            }
            100 => {
                if data.len() < 24 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
                    return Err("the payload is not a PNG".into());
                }
                let width = u32::from_be_bytes(data[16..20].try_into().unwrap());
                let height = u32::from_be_bytes(data[20..24].try_into().unwrap());
                if width == 0 || height == 0 || width > 10_000 || height > 10_000 {
                    return Err("the PNG dimensions are invalid".into());
                }
                Ok((format, width, height, data, Vec::new()))
            }
            _ => Err("unsupported image format".into()),
        }
    }

    /// Place an image at the cursor and, unless told not to, move the
    /// cursor below it the way Kitty terminals do.
    fn kitty_place(&mut self, control: &[(String, String)], image_id: u32) {
        if self.placements.len() >= 512 {
            return;
        }
        let parse = |key: &str| {
            kitty_key(control, key)
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0)
        };
        let placement = Placement {
            image: image_id,
            placement_id: parse("p"),
            row: self.cursor.row,
            col: self.cursor.col,
            x_px: parse("x"),
            y_px: parse("y"),
            src_x: parse("X"),
            src_y: parse("Y"),
            src_w: parse("w"),
            src_h: parse("h"),
            cell_cols: parse("c"),
            cell_rows: parse("r"),
            z: kitty_key(control, "z")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            sixel: None,
        };
        let (_, span_rows) = self.placement_span(&placement);
        let anchor_row = placement.row;
        self.placements.push(placement);
        if kitty_key(control, "C") != Some("1") {
            let target = anchor_row.saturating_add(span_rows as usize);
            self.cursor.row = target.min(self.rows.saturating_sub(1));
            self.wrap_pending = false;
        }
    }

    /// A placement's footprint in cells: the explicit `c`/`r` when set,
    /// else the source size converted at a nominal 10x20 cell.
    fn placement_span(&self, placement: &Placement) -> (u32, u32) {
        let Some(image) = self.images.get(&placement.image) else {
            return (0, 0);
        };
        let width_px = if placement.src_w > 0 {
            placement.src_w
        } else {
            image.width
        };
        let height_px = if placement.src_h > 0 {
            placement.src_h
        } else {
            image.height
        };
        let cols = if placement.cell_cols > 0 {
            placement.cell_cols
        } else {
            width_px.div_ceil(10)
        };
        let rows = if placement.cell_rows > 0 {
            placement.cell_rows
        } else {
            height_px.div_ceil(20)
        };
        (cols.max(1), rows.max(1))
    }

    fn kitty_delete(&mut self, control: &[(String, String)]) {
        let what = kitty_key(control, "d").unwrap_or("p");
        let id = kitty_key(control, "i").and_then(|value| value.parse::<u32>().ok());
        let placement_id =
            kitty_key(control, "p").and_then(|value| value.parse::<u32>().ok());
        let cursor_row = self.cursor.row;
        let cursor_col = self.cursor.col;
        let drop_data = what.chars().any(|c| c.is_ascii_uppercase());
        let mut freed: Vec<u32> = Vec::new();
        match what.to_ascii_lowercase().as_str() {
            "a" => {
                freed = self.placements.iter().map(|p| p.image).collect();
                self.placements.clear();
            }
            "c" => {
                self.placements.retain(|p| {
                    let hit = p.row == cursor_row && p.col == cursor_col;
                    if hit {
                        freed.push(p.image);
                    }
                    !hit
                });
            }
            "i" => {
                if let Some(id) = id {
                    self.placements.retain(|p| p.image != id);
                    freed.push(id);
                }
            }
            "p" => {
                if let (Some(id), Some(pid)) = (id, placement_id) {
                    self.placements
                        .retain(|p| !(p.image == id && p.placement_id == pid));
                    freed.push(id);
                }
            }
            "x" => {
                if let Some(x) = kitty_key(control, "x").and_then(|v| v.parse::<usize>().ok()) {
                    let keep: Vec<bool> = self
                        .placements
                        .iter()
                        .map(|p| {
                            let (span, _) = self.placement_span(p);
                            !(p.col <= x && x < p.col + span as usize)
                        })
                        .collect();
                    let mut keep = keep.into_iter();
                    self.placements.retain(|_| keep.next().unwrap_or(true));
                }
            }
            "y" => {
                if let Some(y) = kitty_key(control, "y").and_then(|v| v.parse::<usize>().ok()) {
                    let keep: Vec<bool> = self
                        .placements
                        .iter()
                        .map(|p| {
                            let (_, span) = self.placement_span(p);
                            !(p.row <= y && y < p.row + span as usize)
                        })
                        .collect();
                    let mut keep = keep.into_iter();
                    self.placements.retain(|_| keep.next().unwrap_or(true));
                }
            }
            "z" => {
                if let Some(z) = kitty_key(control, "z").and_then(|v| v.parse::<i32>().ok()) {
                    self.placements.retain(|p| p.z != z);
                }
            }
            _ => {}
        }
        if drop_data {
            for image in freed {
                if !self.placements.iter().any(|p| p.image == image) {
                    self.images.remove(&image);
                }
            }
        }
    }

    /// Kitty answers only transmissions that named an image id.
    fn kitty_respond(&mut self, id: Option<u32>, result: Result<(), String>) {
        let Some(id) = id else {
            return;
        };
        let reply = match result {
            Ok(()) => format!("\x1b_Gi={id};OK\x1b\\"),
            Err(error) => {
                let error = error.replace([';', '\n'], " ");
                format!("\x1b_Gi={id};EINVAL:{error}\x1b\\")
            }
        };
        self.responses.extend_from_slice(reply.as_bytes());
    }

    pub fn set_theme(&mut self, options: &Value) -> Result<(), String> {
        let foreground = parse_theme_color(options, "foreground")?;
        let background = parse_theme_color(options, "background")?;
        let cursor = parse_theme_color(options, "cursor")?;
        let scheme = match options.get("scheme").and_then(Value::as_str) {
            None | Some("") => None,
            Some("light" | "dark") => options
                .get("scheme")
                .and_then(Value::as_str)
                .map(str::to_string),
            Some(_) => return Err("scheme must be light or dark".into()),
        };
        let mut palette = BTreeMap::new();
        if let Some(values) = options.get("palette").and_then(Value::as_array) {
            for value in values {
                let value = value
                    .as_str()
                    .ok_or_else(|| "palette entries must be strings".to_string())?;
                let (index, color) = value
                    .split_once('=')
                    .ok_or_else(|| "palette entries must be index=RRGGBB".to_string())?;
                let index = index
                    .parse::<u8>()
                    .map_err(|_| "palette index must be from 0 to 255".to_string())?;
                let color = parse_hex_color(color)
                    .ok_or_else(|| format!("invalid palette color {color:?}"))?;
                palette.insert(index, color);
            }
        }
        self.theme = Theme {
            foreground,
            background,
            cursor,
            palette,
            scheme,
        };
        Ok(())
    }

    fn effective_app(&self, id: &str) -> Option<&str> {
        let mut parent = id;
        loop {
            if let Some(app) = self
                .program_status
                .get(parent)
                .and_then(|record| record.app.as_deref())
            {
                return Some(app);
            }
            let Some((parent_id, _)) = parent.rsplit_once('/') else {
                return self
                    .program_status
                    .get("")
                    .and_then(|record| record.app.as_deref());
            };
            parent = parent_id;
        }
    }

    fn remove_status_records(&mut self, id: Option<&str>, reason: &str) {
        let ids: Vec<String> = self
            .program_status
            .keys()
            .filter(|candidate| match id {
                None => true,
                Some("") => true,
                Some(id) => *candidate == id || candidate.starts_with(&format!("{id}/")),
            })
            .cloned()
            .collect();
        if ids.is_empty() {
            return;
        }
        for id in &ids {
            self.program_status.remove(id);
        }
        self.status_events.push((
            "program_status_removed".into(),
            json!({ "ids": ids, "reason": reason }),
        ));
    }

    pub fn clear_transient_program_status(&mut self, reason: &str) {
        let ids: Vec<String> = self
            .program_status
            .iter()
            .filter(|(_, record)| matches!(record.state.as_str(), "working" | "blocked"))
            .map(|(id, _)| id.clone())
            .collect();
        if ids.is_empty() {
            return;
        }
        for id in &ids {
            self.program_status.remove(id);
        }
        self.status_events.push((
            "program_status_removed".into(),
            json!({ "ids": ids, "reason": reason }),
        ));
    }

    fn report_program_status(&mut self, body: &str) {
        // ESC ] 7501 ;  plus ST is 9 bytes. The whole sequence must be <= 4096.
        if body.len() + 9 > 4096 {
            return;
        }
        let mut pairs = BTreeMap::<String, String>::new();
        for pair in body.split(':') {
            let Some((raw_key, raw_value)) = pair.split_once('=') else {
                continue;
            };
            let key = raw_key.trim();
            let value = raw_value.trim();
            if key.is_empty()
                || key.len() > 16
                || !key.bytes().all(|byte| byte.is_ascii_lowercase())
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.,+/=-".contains(&byte))
            {
                continue;
            }
            pairs.insert(key.to_string(), value.to_string());
        }
        let Some(state) = pairs.get("state").map(String::as_str) else {
            return;
        };
        if state == "clear" {
            let id = match pairs.get("id") {
                None => None,
                Some(id) if !id.is_empty() && valid_program_status_id(id) => Some(id.as_str()),
                Some(_) => return,
            };
            self.saw_program_status = true;
            self.remove_status_records(id, "clear");
            return;
        }
        if !matches!(state, "idle" | "working" | "done" | "blocked" | "error") {
            return;
        }
        let id = pairs.get("id").cloned().unwrap_or_default();
        if !id.is_empty() && !valid_program_status_id(&id) {
            return;
        }
        let title = match pairs.get("title") {
            Some(encoded) if encoded.len() > 256 => return,
            Some(encoded) => match decode_status_text(encoded, 192) {
                Some(value) => Some(value),
                None => return,
            },
            None => None,
        };
        let msg = match pairs.get("msg") {
            Some(encoded) if encoded.len() > 2732 => return,
            Some(encoded) => match decode_status_text(encoded, 2048) {
                Some(value) => Some(value),
                None => return,
            },
            None => None,
        };
        let app = pairs
            .get("app")
            .filter(|app| {
                !app.is_empty()
                    && app.len() <= 32
                    && app
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
            })
            .cloned();
        let kind = if state == "blocked" {
            pairs.get("kind").and_then(|kind| {
                matches!(kind.as_str(), "permission" | "question" | "auth").then(|| kind.clone())
            })
        } else {
            None
        };
        let progress = if matches!(state, "working" | "blocked") {
            pairs
                .get("progress")
                .and_then(|value| value.parse::<u8>().ok())
                .filter(|value| *value <= 100)
        } else {
            None
        };

        if !self.program_status.contains_key(&id)
            && self.program_status.len() >= PROGRAM_STATUS_LIMIT
        {
            if let Some(oldest) = self
                .program_status
                .iter()
                .min_by_key(|(_, record)| record.touched_at)
                .map(|(id, _)| id.clone())
            {
                self.program_status.remove(&oldest);
                self.status_events.push((
                    "program_status_removed".into(),
                    json!({ "ids": [oldest], "reason": "evicted" }),
                ));
            }
        }
        let record = ProgramStatusRecord {
            id: id.clone(),
            state: state.to_string(),
            kind,
            progress,
            app,
            title,
            msg,
            updated_at: Utc::now().to_rfc3339(),
            touched_at: std::time::Instant::now(),
        };
        self.saw_program_status = true;
        self.program_status.insert(id.clone(), record);
        let record = self
            .program_status_records()
            .into_iter()
            .find(|record| record.get("id").and_then(Value::as_str).unwrap_or("") == id)
            .unwrap_or(Value::Null);
        self.status_events.push((
            "program_status_changed".into(),
            json!({ "id": id, "record": record, "reason": "report" }),
        ));
    }

    pub fn application_cursor(&self) -> bool {
        self.application_cursor
    }

    /// The strongest mouse tracking mode currently set.
    pub fn mouse_tracking(&self) -> MouseTracking {
        if self.mouse_any {
            MouseTracking::Any
        } else if self.mouse_button {
            MouseTracking::Button
        } else if self.mouse_normal {
            MouseTracking::Normal
        } else if self.mouse_x10 {
            MouseTracking::X10
        } else {
            MouseTracking::Off
        }
    }

    /// The mouse report format currently set.
    pub fn mouse_format(&self) -> MouseFormat {
        if self.mouse_sgr {
            MouseFormat::Sgr
        } else if self.mouse_urxvt {
            MouseFormat::Urxvt
        } else if self.mouse_utf8 {
            MouseFormat::Utf8
        } else {
            MouseFormat::X10
        }
    }

    pub fn focus_reporting(&self) -> bool {
        self.focus_reporting
    }

    pub fn alternate_screen(&self) -> bool {
        self.alt.is_some()
    }

    pub fn active_modes(&self) -> Vec<&'static str> {
        let mut modes = Vec::new();
        if self.bracketed_paste {
            modes.push("bracketed_paste");
        }
        if self.application_cursor {
            modes.push("application_cursor");
        }
        if self.insert_mode {
            modes.push("insert");
        }
        if !self.cursor_visible {
            modes.push("hidden_cursor");
        }
        match self.mouse_tracking() {
            MouseTracking::X10 => modes.push("mouse_x10"),
            MouseTracking::Normal => modes.push("mouse_normal"),
            MouseTracking::Button => modes.push("mouse_button"),
            MouseTracking::Any => modes.push("mouse_any"),
            MouseTracking::Off => {}
        }
        match self.mouse_format() {
            MouseFormat::Utf8 => modes.push("mouse_utf8"),
            MouseFormat::Sgr => modes.push("mouse_sgr"),
            MouseFormat::Urxvt => modes.push("mouse_urxvt"),
            MouseFormat::X10 => {}
        }
        if self.focus_reporting {
            modes.push("focus_event");
        }
        modes
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.max(1) as usize;
        let rows = rows.max(1) as usize;
        if cols == self.cols && rows == self.rows {
            return;
        }

        // The primary grid is stored in `alt` while the alternate screen is
        // active, so resize both grids and clamp both cursors.
        if let Some(saved) = self.alt.as_mut() {
            let mut row = saved.cursor.row;
            resize_grid(
                &mut saved.lines,
                cols,
                rows,
                &mut row,
                &mut saved.scroll_top,
                &mut saved.scroll_bottom,
                None,
            );
            saved.cursor.row = row;
            saved.cursor.col = saved.cursor.col.min(cols - 1);
        }

        let mut row = self.cursor.row;
        let mut top = self.scroll_top;
        let mut bottom = self.scroll_bottom;
        let mut live = self.scrollback.live();
        let scrollback = if self.alt.is_some() {
            None
        } else {
            Some(&mut *live)
        };
        resize_grid(
            &mut self.lines,
            cols,
            rows,
            &mut row,
            &mut top,
            &mut bottom,
            scrollback,
        );
        self.cursor.row = row;
        self.cursor.col = self.cursor.col.min(cols - 1);
        self.scroll_top = top;
        self.scroll_bottom = bottom;
        self.cols = cols;
        self.rows = rows;
        self.wrap_pending = false;
    }

    /// Clear the screen and scrollback, keeping terminal modes and title.
    pub fn clear(&mut self) {
        self.scrollback.clear();
        self.lines = vec![blank_line(self.cols); self.rows];
        self.cursor = Cursor::default();
        self.scroll_top = 0;
        self.scroll_bottom = self.rows - 1;
        self.wrap_pending = false;
    }

    /// Pack the scrollback for an idle stretch, returning the packed
    /// byte count. The grid restores itself on the next access.
    pub fn suspend_scrollback(&mut self) -> Option<usize> {
        self.scrollback.pack()
    }

    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }

    pub fn scrollback_packed(&self) -> bool {
        self.scrollback.is_packed()
    }

    /// Full reset, as with `ESC c` or a fresh terminal.
    pub fn reset(&mut self) {
        let removed: Vec<String> = self.program_status.keys().cloned().collect();
        let mut status_events = std::mem::take(&mut self.status_events);
        let theme = self.theme.clone();
        *self = Screen::new(self.cols as u16, self.rows as u16);
        self.theme = theme;
        if !removed.is_empty() {
            status_events.push((
                "program_status_removed".into(),
                json!({ "ids": removed, "reason": "reset" }),
            ));
        }
        self.status_events = status_events;
    }

    /// DECSTR (`CSI ! p`): modes and pen only. Records, text, title, and the
    /// working directory stay.
    pub fn soft_reset(&mut self) {
        self.pen = Pen::default();
        self.saved = None;
        self.cursor_visible = true;
        self.bracketed_paste = false;
        self.application_cursor = false;
        self.mouse_x10 = false;
        self.mouse_normal = false;
        self.mouse_button = false;
        self.mouse_any = false;
        self.mouse_utf8 = false;
        self.mouse_sgr = false;
        self.mouse_urxvt = false;
        self.focus_reporting = false;
        self.sync_output = false;
        self.sixel_scroll = true;
        self.insert_mode = false;
        self.auto_wrap = true;
        self.wrap_pending = false;
        self.scroll_top = 0;
        self.scroll_bottom = self.rows.saturating_sub(1);
    }

    fn map_osc94_to_root(&mut self, state: &str, progress: Option<u8>) {
        match state {
            "remove" => {
                if self.program_status.remove("").is_some() {
                    self.status_events.push((
                        "program_status_removed".into(),
                        json!({ "ids": [""], "reason": "clear" }),
                    ));
                }
            }
            "set" => self.insert_mapped_status("working", progress),
            "error" => self.insert_mapped_status("error", None),
            "indeterminate" | "pause" => self.insert_mapped_status("working", None),
            _ => {}
        }
    }

    fn insert_mapped_status(&mut self, state: &str, progress: Option<u8>) {
        self.program_status.insert(
            String::new(),
            ProgramStatusRecord {
                id: String::new(),
                state: state.to_string(),
                kind: None,
                progress,
                app: None,
                title: None,
                msg: None,
                updated_at: Utc::now().to_rfc3339(),
                touched_at: std::time::Instant::now(),
            },
        );
        let record = self
            .program_status_records()
            .into_iter()
            .find(|record| record.get("id").is_none())
            .unwrap_or(Value::Null);
        self.status_events.push((
            "program_status_changed".into(),
            json!({ "id": "", "record": record, "reason": "report" }),
        ));
    }

    pub fn format_text(&self, trim: bool, unwrap: bool) -> String {
        let scrollback = self.scrollback.restored();
        let lines = visible_lines(&scrollback, &self.lines);
        let mut out = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                let previous_wrapped = lines[i - 1].wrapped;
                if !(unwrap && previous_wrapped) {
                    out.push('\n');
                }
            }
            let mut text = line_text(line, trim);
            if unwrap {
                text.truncate(text.trim_end().len());
            }
            out.push_str(&text);
        }
        out
    }

    pub fn format_vt(&self) -> String {
        let mut out = String::new();
        if let Some(color) = self.theme.foreground {
            out.push_str(&format!("\x1b]10;{}\x1b\\", osc_color(color)));
        }
        if let Some(color) = self.theme.background {
            out.push_str(&format!("\x1b]11;{}\x1b\\", osc_color(color)));
        }
        if let Some(color) = self.theme.cursor {
            out.push_str(&format!("\x1b]12;{}\x1b\\", osc_color(color)));
        }
        for (index, color) in &self.theme.palette {
            out.push_str(&format!("\x1b]4;{index};{}\x1b\\", osc_color(*color)));
        }
        let mut transmitted: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for (row, line) in self.lines.iter().enumerate() {
            let mut anchored: Vec<&Placement> = self
                .placements
                .iter()
                .filter(|placement| placement.row == row)
                .collect();
            anchored.sort_by_key(|placement| placement.z);
            for placement in anchored {
                out.push_str(&format!("\x1b[{}G", placement.col + 1));
                if let Some((params, data)) = &placement.sixel {
                    let params = params
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(";");
                    out.push_str("\x1bP");
                    if !params.is_empty() {
                        out.push_str(&params);
                    }
                    out.push('q');
                    out.push_str(&String::from_utf8_lossy(data));
                    out.push_str("\x1b\\");
                    continue;
                }
                let Some(image) = self.images.get(&placement.image) else {
                    continue;
                };
                if transmitted.insert(placement.image) {
                    let format = image.kitty_format.unwrap_or(32);
                    let payload = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &image.data,
                    );
                    out.push_str(&format!(
                        "\x1b_Ga=t,f={format},s={},v={},i={};{payload}\x1b\\",
                        image.width, image.height, placement.image
                    ));
                }
                let mut control = format!("a=p,i={}", placement.image);
                if placement.placement_id > 0 {
                    control.push_str(&format!(",p={}", placement.placement_id));
                }
                if placement.x_px > 0 {
                    control.push_str(&format!(",x={}", placement.x_px));
                }
                if placement.y_px > 0 {
                    control.push_str(&format!(",y={}", placement.y_px));
                }
                if placement.src_x > 0 {
                    control.push_str(&format!(",X={}", placement.src_x));
                }
                if placement.src_y > 0 {
                    control.push_str(&format!(",Y={}", placement.src_y));
                }
                if placement.src_w > 0 {
                    control.push_str(&format!(",w={}", placement.src_w));
                }
                if placement.src_h > 0 {
                    control.push_str(&format!(",h={}", placement.src_h));
                }
                if placement.cell_cols > 0 {
                    control.push_str(&format!(",c={}", placement.cell_cols));
                }
                if placement.cell_rows > 0 {
                    control.push_str(&format!(",r={}", placement.cell_rows));
                }
                if placement.z != 0 {
                    control.push_str(&format!(",z={}", placement.z));
                }
                control.push_str(",C=1");
                out.push_str(&format!("\x1b_G{control}\x1b\\"));
            }
            out.push_str("\x1b[0m");
            let mut current: Option<Pen> = None;
            for cell in &line.cells {
                if cell.cont {
                    continue;
                }
                if current != Some(cell.pen) {
                    out.push_str(&sgr(cell.pen));
                    current = Some(cell.pen);
                }
                out.push(cell.ch);
            }
            out.push_str("\r\n");
        }
        out
    }

    /// Encode the terminal state in the Ghostty `GHOSTSNP` v1 format used by
    /// Rex terminal data streams. This snapshot intentionally omits scrollback
    /// pages and Kitty graphics, but preserves the visible grid and styles.
    pub fn ghostty_snapshot(&self) -> Vec<u8> {
        let cols = self.cols.min(u16::MAX as usize) as u16;
        let rows = self.rows.min(u16::MAX as usize) as u16;
        let mut snapshot = b"GHOSTSNP\x01\x00".to_vec();

        let mut terminal = Vec::new();
        put_u16(&mut terminal, cols);
        put_u16(&mut terminal, rows);
        put_u32(&mut terminal, 0); // Pixel width, unknown.
        put_u32(&mut terminal, 0); // Pixel height, unknown.
        put_u16(&mut terminal, 0);
        put_u16(&mut terminal, rows.saturating_sub(1));
        put_u16(&mut terminal, 0);
        put_u16(&mut terminal, cols.saturating_sub(1));
        terminal.push(0); // Main status display.
        put_u16(&mut terminal, 0); // Primary active screen.
        put_u16(&mut terminal, 1); // One screen.
        put_u32(&mut terminal, u32::MAX); // No previous codepoint.
        terminal.push(1); // Default cursor style.
        terminal.push(1); // Block cursor.
        terminal.push(0); // Default blink policy.
        terminal.push(0); // No shell redraw policy.
        terminal.push(0); // Modify-other-keys disabled.
        terminal.push(match self.mouse_tracking() {
            MouseTracking::Off => 0,
            MouseTracking::X10 => 1,
            MouseTracking::Normal => 2,
            MouseTracking::Button => 3,
            MouseTracking::Any => 4,
        }); // Mouse event mode.
        terminal.push(match self.mouse_format() {
            MouseFormat::X10 => 0,
            MouseFormat::Utf8 => 1,
            MouseFormat::Sgr => 2,
            MouseFormat::Urxvt => 3,
        }); // Mouse format.
        terminal.push(0); // Mouse shift-capture unspecified.
        terminal.push(0); // Text mouse cursor.
        terminal.push(0); // Not password input.
        let mut modes = 0u64;
        if self.insert_mode {
            modes |= 1 << 1;
        }
        if self.application_cursor {
            modes |= 1 << 4;
        }
        if self.auto_wrap {
            modes |= 1 << 9;
        }
        if self.cursor_visible {
            modes |= 1 << 13;
        }
        if self.bracketed_paste {
            modes |= 1 << 36;
        }
        put_u64(&mut terminal, modes); // Current modes.
        put_u64(&mut terminal, 0); // Saved modes.
        put_u64(&mut terminal, (1 << 9) | (1 << 10) | (1 << 13)); // Defaults.
        put_dynamic_rgb(&mut terminal, self.theme.background);
        put_dynamic_rgb(&mut terminal, self.theme.foreground);
        put_dynamic_rgb(&mut terminal, self.theme.cursor);
        put_u64(&mut terminal, u64::MAX); // Unlimited byte scrollback.
        put_u64(&mut terminal, SCROLLBACK_LIMIT as u64);

        for byte_index in 0..(cols as usize + 7) / 8 {
            let mut tabs = 0u8;
            for bit in 0..8 {
                let column = byte_index * 8 + bit;
                if column > 0 && column < cols as usize && column % 8 == 0 {
                    tabs |= 1 << bit;
                }
            }
            terminal.push(tabs);
        }
        let palette = std::array::from_fn::<_, 256, _>(xterm_color);
        for color in palette {
            terminal.extend_from_slice(&[color.0, color.1, color.2]);
        }
        let mut palette_mask = [0u8; 32];
        for index in self.theme.palette.keys() {
            palette_mask[*index as usize / 8] |= 1 << (*index as usize % 8);
        }
        terminal.extend_from_slice(&palette_mask);
        for color in self.theme.palette.values() {
            terminal.extend_from_slice(&[color.0, color.1, color.2]);
        }
        put_string(&mut terminal, &self.pwd);
        put_string(&mut terminal, &self.title);
        debug_assert_eq!(
            terminal.len(),
            103 + (cols as usize + 7) / 8
                + 768
                + 32
                + self.theme.palette.len() * 3
                + 8
                + self.pwd.len()
                + self.title.len()
        );
        put_snapshot_record(&mut snapshot, 1, &terminal);

        let mut screen = Vec::new();
        put_u16(&mut screen, 0); // Primary screen key.
        put_u16(&mut screen, 1); // One page follows.
        // The complete logical history extent for this screen. The
        // rows themselves follow READY as HISTORY pages. The alternate
        // screen has no scrollback of its own in this model, and the
        // primary grid's history is not part of an alternate snapshot.
        let history_rows = if self.alt.is_none() {
            self.scrollback.len()
        } else {
            0
        };
        put_u64(&mut screen, history_rows as u64);
        put_u16(
            &mut screen,
            self.cursor.col.min(cols.saturating_sub(1) as usize) as u16,
        );
        put_u16(
            &mut screen,
            self.cursor.row.min(rows.saturating_sub(1) as usize) as u16,
        );
        screen.push(1); // Block cursor.
        screen.push(u8::from(self.wrap_pending));
        put_ghostty_style(&mut screen, self.pen);
        put_u32(&mut screen, 0); // Implicit hyperlink counter.
        put_u16(&mut screen, 0); // Default charset state.
        screen.push(0); // Protected mode off.
        screen.push(self.kitty_stack.len().saturating_sub(1) as u8); // Kitty keyboard stack index.
        let mut kitty_bytes = [0u8; 8]; // Kitty keyboard stack flags.
        for (i, flags) in self.kitty_stack.iter().take(4).enumerate() {
            kitty_bytes[i * 2..i * 2 + 2].copy_from_slice(&flags.to_le_bytes());
        }
        screen.extend_from_slice(&kitty_bytes);
        screen.push(0); // No semantic-click mode.
        screen.push(0);
        screen.push(0); // No saved cursor.
        screen.push(0); // No cursor hyperlink.
        debug_assert_eq!(screen.len(), 54);
        put_snapshot_record(&mut snapshot, 2, &screen);

        let active_wrapped_prev = if self.alt.is_none() {
            self.scrollback
                .restored()
                .back()
                .map(|line| line.wrapped)
                .unwrap_or(false)
        } else {
            false
        };
        let page = encode_snapshot_page(&self.lines, cols, active_wrapped_prev);
        put_snapshot_record(&mut snapshot, 3, &page);
        put_snapshot_record(&mut snapshot, 7, &[]); // Ground continuation.
        put_snapshot_record(&mut snapshot, 5, &[]); // READY.
        // History pages follow READY, newest chunk first, so a client
        // can prepend them as they arrive. Each page holds at most
        // HISTORY_PAGE_ROWS rows of the primary screen's scrollback.
        let scrollback = self.scrollback.restored();
        let history_lines: Vec<&Line> = if self.alt.is_none() {
            scrollback.iter().collect()
        } else {
            Vec::new()
        };
        let page_count = history_lines.len().div_ceil(HISTORY_PAGE_ROWS);
        let mut history = Vec::with_capacity(6);
        put_u16(&mut history, 0); // Primary screen.
        put_u32(&mut history, page_count as u32);
        put_snapshot_record(&mut snapshot, 4, &history);
        let mut chunk_end = history_lines.len();
        while chunk_end > 0 {
            let chunk_start = chunk_end.saturating_sub(HISTORY_PAGE_ROWS);
            let wrapped_prev = if chunk_start > 0 {
                history_lines[chunk_start - 1].wrapped
            } else {
                false
            };
            let chunk: Vec<Line> = history_lines[chunk_start..chunk_end]
                .iter()
                .map(|line| (*line).clone())
                .collect();
            put_snapshot_record(
                &mut snapshot,
                3,
                &encode_snapshot_page(&chunk, cols, wrapped_prev),
            );
            chunk_end = chunk_start;
        }
        put_snapshot_record(&mut snapshot, 6, &[]); // FINISH.
        snapshot
    }

    pub fn initial_resize_message(&self, nonce: u64, owner: Option<&str>) -> Vec<u8> {
        let payload = json!({
            "type": "resize",
            "cols": self.cols,
            "rows": self.rows,
            "cell_width_px": 0,
            "cell_height_px": 0,
            "owner": owner,
        });
        apc_message(nonce, &payload)
    }

    pub fn initial_theme_message(&self, nonce: u64) -> Option<Vec<u8>> {
        if self.theme.foreground.is_none()
            && self.theme.background.is_none()
            && self.theme.cursor.is_none()
            && self.theme.palette.is_empty()
            && self.theme.scheme.is_none()
        {
            return None;
        }
        let mut payload = json!({ "type": "theme" });
        for (name, color) in [
            ("foreground", self.theme.foreground),
            ("background", self.theme.background),
            ("cursor", self.theme.cursor),
        ] {
            if let Some((r, g, b)) = color {
                payload[name] = json!(format!("{r:02x}{g:02x}{b:02x}"));
            }
        }
        if !self.theme.palette.is_empty() {
            payload["palette"] = json!(
                self.theme
                    .palette
                    .iter()
                    .map(|(index, (r, g, b))| format!("{index}={r:02x}{g:02x}{b:02x}"))
                    .collect::<Vec<_>>()
            );
        }
        if let Some(scheme) = &self.theme.scheme {
            payload["scheme"] = json!(scheme);
        }
        Some(apc_message(nonce, &payload))
    }

    pub fn format_html(&self, trim: bool, unwrap: bool) -> String {
        let scrollback = self.scrollback.restored();
        let lines = visible_lines(&scrollback, &self.lines);
        let mut outer_style = String::from("font-family: monospace; white-space: pre;");
        if let Some(color) = self.theme.foreground {
            outer_style.push_str(&format!("color: {};", rgb_css(color)));
        }
        if let Some(color) = self.theme.background {
            outer_style.push_str(&format!("background-color: {};", rgb_css(color)));
        }
        if let Some(scheme) = &self.theme.scheme {
            outer_style.push_str(&format!("color-scheme: {scheme};"));
        }
        let mut out = format!("<div style=\"{outer_style}\">");
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                let previous_wrapped = lines[i - 1].wrapped;
                if !(unwrap && previous_wrapped) {
                    out.push('\n');
                }
            }
            let limit = if trim {
                line.cells
                    .iter()
                    .rposition(|c| !c.cont && c.ch != ' ')
                    .map(|i| i + 1)
                    .unwrap_or(0)
            } else {
                line.cells.len()
            };
            let mut current: Option<Pen> = None;
            let mut run = String::new();
            for cell in line.cells.iter().take(limit) {
                if cell.cont {
                    continue;
                }
                if current != Some(cell.pen) {
                    if !run.is_empty() {
                        out.push_str(&html_span(current.unwrap_or_default(), &run, &self.theme));
                        run.clear();
                    }
                    current = Some(cell.pen);
                }
                run.push(cell.ch);
            }
            if !run.is_empty() {
                out.push_str(&html_span(current.unwrap_or_default(), &run, &self.theme));
            }
        }
        out.push_str("</div>");
        out
    }

    fn blank(&self) -> Line {
        blank_line(self.cols)
    }

    fn line_mut(&mut self) -> &mut Line {
        &mut self.lines[self.cursor.row]
    }

    fn save_cursor(&mut self) {
        self.saved = Some((self.cursor, self.pen, self.wrap_pending));
    }

    fn restore_cursor(&mut self) {
        if let Some((cursor, pen, wrap_pending)) = self.saved {
            self.cursor = cursor;
            self.pen = pen;
            self.wrap_pending = wrap_pending;
        }
    }

    fn carriage_return(&mut self) {
        self.cursor.col = 0;
        self.wrap_pending = false;
    }

    fn linefeed(&mut self) {
        if self.cursor.row == self.scroll_bottom {
            self.scroll_up(1);
        } else if self.cursor.row + 1 < self.rows {
            self.cursor.row += 1;
        }
        self.wrap_pending = false;
    }

    fn reverse_index(&mut self) {
        if self.cursor.row == self.scroll_top {
            self.scroll_down(1);
        } else if self.cursor.row > 0 {
            self.cursor.row -= 1;
        }
        self.wrap_pending = false;
    }

    fn mark_wrapped(&mut self) {
        if let Some(line) = self.lines.get_mut(self.cursor.row) {
            line.wrapped = true;
        }
    }

    /// Move placements with content shifting inside [top, bottom];
    /// placements pushed out of the region are dropped (a client
    /// scrolling them into scrollback keeps its own copies from the
    /// live stream, but the snapshot format has no image records).
    fn shift_placements(&mut self, top: usize, bottom: usize, delta: isize) {
        self.placements.retain(|placement| {
            if placement.row < top || placement.row > bottom {
                return true;
            }
            let moved = placement.row as isize + delta;
            (top as isize..=bottom as isize).contains(&moved)
        });
        for placement in &mut self.placements {
            if placement.row >= top && placement.row <= bottom {
                placement.row = (placement.row as isize + delta) as usize;
            }
        }
    }

    fn scroll_up(&mut self, n: usize) {
        let top = self.scroll_top;
        let bottom = self.scroll_bottom;
        if top > bottom || bottom >= self.lines.len() {
            return;
        }
        let n = n.min(bottom - top + 1);
        self.shift_placements(top, bottom, -(n as isize));
        for _ in 0..n {
            if top == 0 && self.alt.is_none() {
                let line = self.lines.remove(top);
                self.scrollback.push_back(line);
                while self.scrollback.len() > SCROLLBACK_LIMIT {
                    self.scrollback.pop_front();
                }
            } else {
                self.lines.remove(top);
            }
            self.lines.insert(bottom, self.blank());
        }
    }

    fn scroll_down(&mut self, n: usize) {
        let top = self.scroll_top;
        let bottom = self.scroll_bottom;
        if top > bottom || bottom >= self.lines.len() {
            return;
        }
        let n = n.min(bottom - top + 1);
        self.shift_placements(top, bottom, n as isize);
        for _ in 0..n {
            self.lines.remove(bottom);
            self.lines.insert(top, self.blank());
        }
    }

    fn erase_cells(&mut self, row: usize, start: usize, end: usize) {
        if let Some(line) = self.lines.get_mut(row) {
            let end = end.min(line.cells.len());
            for cell in line.cells.iter_mut().take(end).skip(start) {
                *cell = Cell::blank(self.pen);
            }
        }
    }

    fn erase_display(&mut self, mode: usize) {
        match mode {
            0 => {
                let row = self.cursor.row;
                self.erase_cells(row, self.cursor.col, self.cols);
                for r in row + 1..self.rows {
                    self.erase_cells(r, 0, self.cols);
                }
            }
            1 => {
                let row = self.cursor.row;
                for r in 0..row {
                    self.erase_cells(r, 0, self.cols);
                }
                self.erase_cells(row, 0, self.cursor.col + 1);
            }
            2 => {
                for r in 0..self.rows {
                    self.erase_cells(r, 0, self.cols);
                }
                self.placements.clear();
            }
            3 => {
                self.scrollback.clear();
                self.erase_display(2);
            }
            _ => {}
        }
    }

    fn erase_line(&mut self, mode: usize) {
        let row = self.cursor.row;
        match mode {
            0 => self.erase_cells(row, self.cursor.col, self.cols),
            1 => self.erase_cells(row, 0, self.cursor.col + 1),
            2 => self.erase_cells(row, 0, self.cols),
            _ => {}
        }
    }

    fn insert_chars(&mut self, n: usize) {
        let n = n.max(1);
        let col = self.cursor.col;
        let pen = self.pen;
        let cols = self.cols;
        let line = self.line_mut();
        for _ in 0..n {
            if col < line.cells.len() {
                line.cells.insert(col, Cell::blank(pen));
                line.cells.truncate(cols);
            }
        }
    }

    fn delete_chars(&mut self, n: usize) {
        let n = n.max(1);
        let col = self.cursor.col;
        let pen = self.pen;
        let cols = self.cols;
        let line = self.line_mut();
        for _ in 0..n {
            if col < line.cells.len() {
                line.cells.remove(col);
                line.cells.push(Cell::blank(pen));
            }
        }
        line.cells.truncate(cols);
    }

    fn insert_lines(&mut self, n: usize) {
        let n = n.max(1);
        let top = self.scroll_top;
        let bottom = self.scroll_bottom;
        if self.cursor.row < top || self.cursor.row > bottom {
            return;
        }
        self.shift_placements(self.cursor.row, bottom, n as isize);
        for _ in 0..n {
            self.lines.remove(bottom);
            self.lines.insert(self.cursor.row, self.blank());
        }
    }

    fn delete_lines(&mut self, n: usize) {
        let n = n.max(1);
        let top = self.scroll_top;
        let bottom = self.scroll_bottom;
        if self.cursor.row < top || self.cursor.row > bottom {
            return;
        }
        self.shift_placements(self.cursor.row, bottom, -(n as isize));
        for _ in 0..n {
            self.lines.remove(self.cursor.row);
            self.lines.insert(bottom, self.blank());
        }
    }

    fn set_scroll_region(&mut self, top: usize, bottom: usize) {
        let top = top.min(self.rows - 1);
        let bottom = bottom.min(self.rows - 1);
        if top < bottom {
            self.scroll_top = top;
            self.scroll_bottom = bottom;
            self.cursor = Cursor { row: top, col: 0 };
            self.wrap_pending = false;
        }
    }

    fn enter_alt(&mut self) {
        if self.alt.is_some() {
            return;
        }
        let blank = self.blank();
        let saved = AltState {
            lines: std::mem::replace(&mut self.lines, vec![blank; self.rows]),
            cursor: self.cursor,
            saved: self.saved,
            scroll_top: self.scroll_top,
            scroll_bottom: self.scroll_bottom,
            wrap_pending: self.wrap_pending,
            placements: std::mem::take(&mut self.placements),
        };
        self.alt = Some(saved);
        self.cursor = Cursor::default();
        self.saved = None;
        self.scroll_top = 0;
        self.scroll_bottom = self.rows - 1;
        self.wrap_pending = false;
    }

    fn leave_alt(&mut self) {
        if let Some(saved) = self.alt.take() {
            self.lines = saved.lines;
            self.cursor = saved.cursor;
            self.saved = saved.saved;
            self.scroll_top = saved.scroll_top;
            self.scroll_bottom = saved.scroll_bottom;
            self.wrap_pending = saved.wrap_pending;
            self.placements = saved.placements;
        }
    }

    fn sgr(&mut self, params: &Params) {
        let values: Vec<u16> = params.iter().flat_map(|p| p.iter().copied()).collect();
        if values.is_empty() {
            self.pen = Pen::default();
            return;
        }
        let mut i = 0;
        while i < values.len() {
            let value = values[i];
            match value {
                0 => self.pen = Pen::default(),
                1 => self.pen.bold = true,
                2 => self.pen.dim = true,
                3 => self.pen.italic = true,
                4 => self.pen.underline = true,
                5 => self.pen.blink = true,
                7 => self.pen.inverse = true,
                8 => self.pen.hidden = true,
                9 => self.pen.strike = true,
                21 | 22 => {
                    self.pen.bold = false;
                    self.pen.dim = false;
                }
                23 => self.pen.italic = false,
                24 => self.pen.underline = false,
                25 => self.pen.blink = false,
                27 => self.pen.inverse = false,
                28 => self.pen.hidden = false,
                29 => self.pen.strike = false,
                30..=37 => self.pen.fg = Color::Palette((value - 30) as u8),
                38 | 48 => {
                    let foreground = value == 38;
                    if i + 1 < values.len() {
                        match values[i + 1] {
                            5 if i + 2 < values.len() => {
                                let color = Color::Palette(values[i + 2] as u8);
                                if foreground {
                                    self.pen.fg = color;
                                } else {
                                    self.pen.bg = color;
                                }
                                i += 2;
                            }
                            2 if i + 4 < values.len() => {
                                let color = Color::Rgb(
                                    values[i + 2] as u8,
                                    values[i + 3] as u8,
                                    values[i + 4] as u8,
                                );
                                if foreground {
                                    self.pen.fg = color;
                                } else {
                                    self.pen.bg = color;
                                }
                                i += 4;
                            }
                            _ => {}
                        }
                    }
                }
                39 => self.pen.fg = Color::Default,
                40..=47 => self.pen.bg = Color::Palette((value - 40) as u8),
                49 => self.pen.bg = Color::Default,
                90..=97 => self.pen.fg = Color::Palette((value - 90 + 8) as u8),
                100..=107 => self.pen.bg = Color::Palette((value - 100 + 8) as u8),
                _ => {}
            }
            i += 1;
        }
    }

    fn set_modes(&mut self, params: &Params, intermediates: &[u8], enable: bool) {
        let private = intermediates.contains(&b'?');
        let values: Vec<u16> = params
            .iter()
            .map(|p| p.first().copied().unwrap_or(0))
            .collect();
        for value in values {
            if private {
                match value {
                    1 => self.application_cursor = enable,
                    7 => self.auto_wrap = enable,
                    25 => self.cursor_visible = enable,
                    47 | 1047 | 1049 => {
                        if enable {
                            self.enter_alt();
                        } else {
                            self.leave_alt();
                        }
                    }
                    2004 => self.bracketed_paste = enable,
                    2026 => self.sync_output = enable,
                    80 => self.sixel_scroll = enable,
                    9 => self.mouse_x10 = enable,
                    1000 => self.mouse_normal = enable,
                    1002 => self.mouse_button = enable,
                    1003 => self.mouse_any = enable,
                    1004 => self.focus_reporting = enable,
                    1005 => self.mouse_utf8 = enable,
                    1006 => self.mouse_sgr = enable,
                    1015 => self.mouse_urxvt = enable,
                    _ => {}
                }
            } else if value == 4 {
                self.insert_mode = enable;
            }
        }
    }

    fn csi(&mut self, params: &Params, intermediates: &[u8], action: char) {
        let first = |default: usize| param(params, 0, default);
        let second = |default: usize| param(params, 1, default);
        let count = first(1);

        match action {
            'A' => {
                let floor = if self.cursor.row >= self.scroll_top {
                    self.scroll_top
                } else {
                    0
                };
                self.cursor.row = self.cursor.row.saturating_sub(count).max(floor);
                self.wrap_pending = false;
            }
            'B' => {
                let ceiling = if self.cursor.row <= self.scroll_bottom {
                    self.scroll_bottom
                } else {
                    self.rows - 1
                };
                self.cursor.row = (self.cursor.row + count).min(ceiling);
                self.wrap_pending = false;
            }
            'C' => {
                self.cursor.col = (self.cursor.col + count).min(self.cols - 1);
                self.wrap_pending = false;
            }
            'D' => {
                self.cursor.col = self.cursor.col.saturating_sub(count);
                self.wrap_pending = false;
            }
            'E' => {
                self.cursor.row = (self.cursor.row + count).min(self.rows - 1);
                self.cursor.col = 0;
                self.wrap_pending = false;
            }
            'F' => {
                self.cursor.row = self.cursor.row.saturating_sub(count);
                self.cursor.col = 0;
                self.wrap_pending = false;
            }
            'G' | '`' => {
                self.cursor.col = count.saturating_sub(1).min(self.cols - 1);
                self.wrap_pending = false;
            }
            'H' | 'f' => {
                self.cursor.row = first(1).saturating_sub(1).min(self.rows - 1);
                self.cursor.col = second(1).saturating_sub(1).min(self.cols - 1);
                self.wrap_pending = false;
            }
            'd' => {
                self.cursor.row = first(1).saturating_sub(1).min(self.rows - 1);
                self.wrap_pending = false;
            }
            'e' => {
                self.cursor.row = (self.cursor.row + count).min(self.rows - 1);
                self.wrap_pending = false;
            }
            'a' => {
                self.cursor.col = (self.cursor.col + count).min(self.cols - 1);
                self.wrap_pending = false;
            }
            'J' => self.erase_display(param(params, 0, 0)),
            'K' => self.erase_line(param(params, 0, 0)),
            'L' => self.insert_lines(count),
            'M' => self.delete_lines(count),
            'P' => self.delete_chars(count),
            '@' => self.insert_chars(count),
            'X' => {
                let col = self.cursor.col;
                self.erase_cells(self.cursor.row, col, col + count);
            }
            'S' => self.scroll_up(count),
            'T' => self.scroll_down(count),
            'm' => self.sgr(params),
            'h' => self.set_modes(params, intermediates, true),
            'l' => self.set_modes(params, intermediates, false),
            'r' => {
                let top = first(1).saturating_sub(1);
                let bottom = second(self.rows).saturating_sub(1);
                self.set_scroll_region(top, bottom);
            }
            's' => self.save_cursor(),
            'u' => self.csi_u(params, intermediates),
            'b' => {
                for _ in 0..count {
                    self.print(self.last_char);
                }
            }
            'Z' => {
                for _ in 0..count {
                    self.cursor.col = self.previous_tab_stop();
                }
                self.wrap_pending = false;
            }
            'I' => {
                for _ in 0..count {
                    self.cursor.col = self.next_tab_stop();
                }
                self.wrap_pending = false;
            }
            'n' => match param(params, 0, 0) {
                5 => self.responses.extend_from_slice(b"\x1b[0n"),
                6 => {
                    let response = format!("\x1b[{};{}R", self.cursor.row + 1, self.cursor.col + 1);
                    self.responses.extend_from_slice(response.as_bytes());
                }
                _ => {}
            },
            'c' => {
                if intermediates.contains(&b'>') {
                    self.responses.extend_from_slice(b"\x1b[>41;1;0c");
                } else {
                    self.responses.extend_from_slice(b"\x1b[?62;4;22c");
                }
            }
            'p' if intermediates.contains(&b'!') => self.soft_reset(),
            'p' if intermediates.contains(&b'$') => self.decrqm(params, intermediates),
            'q' if intermediates.contains(&b'>') => {
                let version = format!("\x1bP>|rux {}\x1b\\", env!("CARGO_PKG_VERSION"));
                self.responses.extend_from_slice(version.as_bytes());
            }
            't' => match param(params, 0, 0) {
                11 => self.responses.extend_from_slice(b"\x1b[1t"),
                13 => self.responses.extend_from_slice(b"\x1b[3;0;0t"),
                18 => {
                    let response = format!("\x1b[8;{};{}t", self.rows, self.cols);
                    self.responses.extend_from_slice(response.as_bytes());
                }
                19 => {
                    let response = format!("\x1b[9;{};{}t", self.rows, self.cols);
                    self.responses.extend_from_slice(response.as_bytes());
                }
                22 => {
                    if self.title_stack.len() < 10 {
                        self.title_stack.push(self.title.clone());
                    }
                }
                23 => {
                    if let Some(title) = self.title_stack.pop() {
                        if self.title != title {
                            self.title = title;
                            self.status_events.push((
                                "title_changed".into(),
                                json!({ "title": self.title }),
                            ));
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// OSC 10/11/12: set the terminal's dynamic foreground, background,
    /// or cursor color, or answer a `?` query with the color in force.
    /// A query for a color nobody set goes unanswered: the effective
    /// default belongs to the client, and the server cannot know it.
    fn dynamic_color(&mut self, which: &[u8], spec: &[u8], bell_terminated: bool) {
        if spec == b"?" {
            let color = match which {
                b"10" => self.theme.foreground,
                b"11" => self.theme.background,
                _ => self.theme.cursor,
            };
            if let Some(color) = color {
                let prefix = format!("{};", String::from_utf8_lossy(which));
                let reply = osc_color_reply(&prefix, color, bell_terminated);
                self.responses.extend_from_slice(&reply);
            }
            return;
        }
        if let Some(color) = parse_osc_color(spec) {
            match which {
                b"10" => self.theme.foreground = Some(color),
                b"11" => self.theme.background = Some(color),
                _ => self.theme.cursor = Some(color),
            }
        }
    }

    fn dcs_dispatch(&mut self, dcs: DcsState) {
        match (dcs.action, dcs.intermediates.as_slice()) {
            ('q', []) => self.place_sixel(dcs.params, dcs.data),
            ('q', [b'$']) => self.decrqss(&dcs.data),
            ('q', [b'+']) => self.xtgettcap(&dcs.data),
            _ => {}
        }
    }

    /// Decode a sixel image and place it at the cursor.
    fn place_sixel(&mut self, params: Vec<u16>, data: Vec<u8>) {
        let opaque = params.get(1) == Some(&1);
        let Some((width, height, rgba)) = decode_sixel(&data, opaque) else {
            return;
        };
        if width == 0 || height == 0 || self.placements.len() >= 512 {
            return;
        }
        self.next_image_id = self.next_image_id.wrapping_add(1);
        let image_id = self.next_image_id;
        self.images.insert(
            image_id,
            StoredImage {
                width,
                height,
                rgba,
                kitty_format: None,
                data: Vec::new(),
            },
        );
        let mut placement = Placement {
            image: image_id,
            placement_id: 0,
            row: self.cursor.row,
            col: self.cursor.col,
            x_px: 0,
            y_px: 0,
            src_x: 0,
            src_y: 0,
            src_w: 0,
            src_h: 0,
            cell_cols: 0,
            cell_rows: 0,
            z: 0,
            sixel: Some((params, data)),
        };
        let (cols, rows) = self.placement_span(&placement);
        placement.cell_cols = cols;
        placement.cell_rows = rows;
        let anchor_row = placement.row;
        self.placements.push(placement);
        if self.sixel_scroll {
            self.cursor.row = anchor_row
                .saturating_add(rows as usize)
                .min(self.scroll_bottom);
            self.wrap_pending = false;
        }
    }

    /// DECRQSS (`DCS $ q <query> ST`): answer queries about the current
    /// settings. Only the scroll region and the SGR rendition are
    /// reported; anything else gets the "invalid query" reply.
    fn decrqss(&mut self, query: &[u8]) {
        let body: Option<String> = match query {
            b"r" => Some(format!("{};{}r", self.scroll_top + 1, self.scroll_bottom + 1)),
            b"m" => Some(self.sgr_report()),
            _ => None,
        };
        let reply = match body {
            Some(body) => format!("\x1bP1$r{body}\x1b\\"),
            None => "\x1bP0$r\x1b\\".to_string(),
        };
        self.responses.extend_from_slice(reply.as_bytes());
    }

    /// The current pen as an SGR parameter string, for DECRQSS.
    fn sgr_report(&self) -> String {
        let pen = self.pen;
        let mut parts: Vec<String> = vec!["0".into()];
        if pen.bold {
            parts.push("1".into());
        }
        if pen.dim {
            parts.push("2".into());
        }
        if pen.italic {
            parts.push("3".into());
        }
        if pen.underline {
            parts.push("4".into());
        }
        if pen.blink {
            parts.push("5".into());
        }
        if pen.inverse {
            parts.push("7".into());
        }
        if pen.hidden {
            parts.push("8".into());
        }
        if pen.strike {
            parts.push("9".into());
        }
        let mut color = |color: Color, base: u8| match color {
            Color::Default => {}
            Color::Palette(index) => parts.push(format!("{};5;{index}", base + 30)),
            Color::Rgb(r, g, b) => parts.push(format!("{};2;{r};{g};{b}", base + 30)),
        };
        color(pen.fg, 8);
        color(pen.bg, 18);
        format!("{}m", parts.join(";"))
    }

    /// XTGETTCAP (`DCS + q <hex> ST`): only the terminal-name query is
    /// answered; `TERM` in spawned shells is `xterm-256color`.
    fn xtgettcap(&mut self, data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        let hex_value = |bytes: &[u8]| -> String {
            bytes.iter().map(|byte| format!("{byte:02X}")).collect()
        };
        let reply = if text.eq_ignore_ascii_case("544E") {
            format!(
                "\x1bP1+r{}={}\x1b\\",
                hex_value(b"TN"),
                hex_value(b"xterm-256color")
            )
        } else {
            "\x1bP0+r\x1b\\".to_string()
        };
        self.responses.extend_from_slice(reply.as_bytes());
    }

    /// DECRQM (`CSI ? Ps $ p` / `CSI Ps $ p`): report whether a mode is
    /// set (1), reset (2), or not recognized (0).
    fn decrqm(&mut self, params: &Params, intermediates: &[u8]) {
        let mode = param(params, 0, 0);
        let private = intermediates.contains(&b'?');
        let state: Option<bool> = if private {
            match mode {
                1 => Some(self.application_cursor),
                7 => Some(self.auto_wrap),
                25 => Some(self.cursor_visible),
                47 | 1047 | 1049 => Some(self.alt.is_some()),
                9 => Some(self.mouse_x10),
                1000 => Some(self.mouse_normal),
                1002 => Some(self.mouse_button),
                1003 => Some(self.mouse_any),
                1004 => Some(self.focus_reporting),
                1005 => Some(self.mouse_utf8),
                1006 => Some(self.mouse_sgr),
                1015 => Some(self.mouse_urxvt),
                2004 => Some(self.bracketed_paste),
                2026 => Some(self.sync_output),
                80 => Some(self.sixel_scroll),
                _ => None,
            }
        } else {
            match mode {
                4 => Some(self.insert_mode),
                20 => Some(false),
                _ => None,
            }
        };
        let value = match state {
            Some(true) => 1,
            Some(false) => 2,
            None => 0,
        };
        let response = format!(
            "\x1b[{}{};{}$y",
            if private { "?" } else { "" },
            mode,
            value
        );
        self.responses.extend_from_slice(response.as_bytes());
    }

    /// The Kitty keyboard flags currently in force: the top of the
    /// keyboard enhancement stack, or 0 when the stack is empty.
    pub fn kitty_flags(&self) -> u16 {
        self.kitty_stack.last().copied().unwrap_or(0)
    }

    /// `CSI u` family: a bare `CSI u` is SCORST (restore cursor); with a
    /// Kitty intermediate it negotiates keyboard enhancement flags:
    /// `?` queries, `>` pushes, `<` pops, `=` sets the current flags.
    fn csi_u(&mut self, params: &Params, intermediates: &[u8]) {
        if intermediates.is_empty() {
            self.restore_cursor();
            return;
        }
        if intermediates.contains(&b'?') {
            let response = format!("\x1b[?{}u", self.kitty_flags());
            self.responses.extend_from_slice(response.as_bytes());
        } else if intermediates.contains(&b'>') {
            if self.kitty_stack.len() < 4 {
                self.kitty_stack.push(param(params, 0, 0) as u16);
            }
        } else if intermediates.contains(&b'<') {
            for _ in 0..param(params, 0, 1).max(1) {
                self.kitty_stack.pop();
            }
        } else if intermediates.contains(&b'=') {
            let flags = param(params, 0, 0) as u16;
            let current = self.kitty_flags();
            let new = match param(params, 1, 1) {
                1 => current | flags,
                2 => current & !flags,
                _ => flags,
            };
            if let Some(top) = self.kitty_stack.last_mut() {
                *top = new;
            } else {
                self.kitty_stack.push(new);
            }
        }
    }

    fn next_tab_stop(&self) -> usize {
        ((self.cursor.col / 8) + 1) * 8
    }

    fn previous_tab_stop(&self) -> usize {
        if self.cursor.col == 0 {
            0
        } else {
            ((self.cursor.col - 1) / 8) * 8
        }
    }
}

impl Perform for Screen {
    fn print(&mut self, c: char) {
        let width = UnicodeWidthChar::width(c).unwrap_or(0);
        if width == 0 {
            return;
        }
        self.last_char = c;

        if self.wrap_pending {
            self.mark_wrapped();
            self.carriage_return();
            self.linefeed();
        }
        if self.insert_mode {
            self.insert_chars(width);
        }
        if self.cursor.col + width > self.cols {
            if self.auto_wrap {
                self.mark_wrapped();
                self.carriage_return();
                self.linefeed();
            } else {
                self.cursor.col = self.cols.saturating_sub(width);
            }
        }

        let row = self.cursor.row;
        let col = self.cursor.col;
        let pen = self.pen;
        if let Some(line) = self.lines.get_mut(row) {
            if col < line.cells.len() {
                line.cells[col] = Cell {
                    ch: c,
                    pen,
                    cont: false,
                };
                if width == 2 && col + 1 < line.cells.len() {
                    line.cells[col + 1] = Cell {
                        ch: ' ',
                        pen,
                        cont: true,
                    };
                }
            }
        }
        if col + width >= self.cols {
            self.cursor.col = self.cols.saturating_sub(1);
            self.wrap_pending = self.auto_wrap;
        } else {
            self.cursor.col += width;
        }
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            0x07 => self.status_events.push(("bell".into(), json!({}))),
            0x08 => {
                self.cursor.col = self.cursor.col.saturating_sub(1);
                self.wrap_pending = false;
            }
            0x09 => {
                self.cursor.col = self.next_tab_stop().min(self.cols - 1);
                self.wrap_pending = false;
            }
            0x0a | 0x0b | 0x0c => self.linefeed(),
            0x0d => self.carriage_return(),
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: char) {
        self.csi(params, intermediates, action);
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, byte: u8) {
        match byte {
            b'7' => self.save_cursor(),
            b'8' => self.restore_cursor(),
            b'D' => self.linefeed(),
            b'E' => {
                self.carriage_return();
                self.linefeed();
            }
            b'M' => self.reverse_index(),
            b'c' => self.reset(),
            _ => {}
        }
    }

    fn hook(&mut self, params: &Params, intermediates: &[u8], ignore: bool, action: char) {
        self.dcs = Some(DcsState {
            params: if ignore {
                Vec::new()
            } else {
                params
                    .iter()
                    .map(|param| param.first().copied().unwrap_or(0))
                    .collect()
            },
            intermediates: if ignore {
                Vec::new()
            } else {
                intermediates.to_vec()
            },
            action: if ignore { '\0' } else { action },
            data: Vec::new(),
        });
    }

    fn put(&mut self, byte: u8) {
        if let Some(dcs) = &mut self.dcs
            && dcs.data.len() < 36_000_000
        {
            dcs.data.push(byte);
        }
    }

    fn unhook(&mut self) {
        if let Some(dcs) = self.dcs.take() {
            self.dcs_dispatch(dcs);
        }
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], bell_terminated: bool) {
        let Some(code) = params.first() else {
            return;
        };
        match *code {
            b"0" | b"2" => {
                let title = params[1..]
                    .iter()
                    .map(|p| String::from_utf8_lossy(p))
                    .collect::<Vec<_>>()
                    .join(";");
                if self.title != title {
                    self.title = title.clone();
                    self.status_events
                        .push(("title_changed".into(), json!({ "title": title })));
                }
            }
            b"7" => {
                if let Some(uri) = params.get(1) {
                    let uri = String::from_utf8_lossy(uri);
                    if let Some(pwd) = file_url_from_osc7(&uri) {
                        if self.pwd != pwd {
                            self.pwd = pwd.clone();
                            self.status_events
                                .push(("pwd_changed".into(), json!({ "pwd": pwd })));
                        }
                    }
                }
            }
            b"52" => {
                let Some(encoded) = params.get(2) else { return };
                if *encoded == b"?" {
                    // A clipboard read query: answer with the newest copy
                    // the server still holds.
                    if let Some((_, text)) = self.clipboard_copy(0) {
                        let selection = params.get(1).copied().unwrap_or(b"");
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
                        let mut reply = b"\x1b]52;".to_vec();
                        reply.extend_from_slice(selection);
                        reply.push(b';');
                        reply.extend_from_slice(encoded.as_bytes());
                        if bell_terminated {
                            reply.push(0x07);
                        } else {
                            reply.extend_from_slice(b"\x1b\\");
                        }
                        self.responses.extend_from_slice(&reply);
                    }
                    return;
                }
                if encoded.len() > 1_398_104 {
                    return;
                }
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded));
                let Ok(decoded) = decoded else { return };
                if decoded.len() > 1_048_576 {
                    return;
                }
                let Ok(text) = String::from_utf8(decoded) else {
                    return;
                };
                if text.is_empty() {
                    // Clearing the clipboard is the newest copy state: it
                    // supersedes any clipboard_written still waiting.
                    self.status_events
                        .retain(|(name, _)| name.as_str() != "clipboard_written");
                    self.status_events
                        .push(("clipboard_written".into(), json!({})));
                    return;
                }
                let bytes = text.len();
                let id = self.next_clipboard_id;
                self.next_clipboard_id = self.next_clipboard_id.wrapping_add(1).max(1);
                let mut payload = json!({ "id": id, "bytes": bytes });
                if bytes <= 48 * 1024 {
                    payload["text"] = json!(text.clone());
                }
                let now = std::time::Instant::now();
                self.clipboard_copies
                    .retain(|_, (_, created)| now.duration_since(*created).as_secs() < 60);
                while self.clipboard_copies.len() >= 64 {
                    if let Some(oldest) = self
                        .clipboard_copies
                        .iter()
                        .min_by_key(|(_, (_, created))| *created)
                        .map(|(id, _)| *id)
                    {
                        self.clipboard_copies.remove(&oldest);
                    } else {
                        break;
                    }
                }
                self.clipboard_copies.insert(id, (text, now));
                // Copies in quick succession are coalesced: a copy that has
                // not been delivered yet is skipped, and the newest copy is
                // always sent.
                self.status_events
                    .retain(|(name, _)| name.as_str() != "clipboard_written");
                self.status_events
                    .push(("clipboard_written".into(), payload));
            }
            b"9" => {
                if params.get(1).is_some_and(|value| *value == b"4") {
                    if let Some(state_value) = params.get(2).and_then(|value| value.first()) {
                        let (state, progress) = match state_value {
                            b'0' => ("remove", None),
                            b'1' => (
                                "set",
                                params
                                    .get(3)
                                    .and_then(|value| std::str::from_utf8(value).ok())
                                    .and_then(|value| value.parse::<u8>().ok())
                                    .filter(|value| *value <= 100),
                            ),
                            b'2' => ("error", None),
                            b'3' => ("indeterminate", None),
                            b'4' => ("pause", None),
                            _ => return,
                        };
                        let mut payload = json!({ "state": state });
                        if let Some(progress) = progress {
                            payload["progress"] = json!(progress);
                        }
                        self.status_events
                            .push(("progress_report".into(), payload.clone()));
                        if !self.saw_program_status {
                            self.map_osc94_to_root(state, progress);
                        }
                    }
                } else {
                    let body = params[1..]
                        .iter()
                        .map(|part| String::from_utf8_lossy(part))
                        .collect::<Vec<_>>()
                        .join(";");
                    self.status_events.push((
                        "desktop_notification".into(),
                        json!({ "title": "", "body": body }),
                    ));
                }
            }
            b"777" => {
                if params.get(1).is_some_and(|value| *value == b"notify") {
                    let title = params
                        .get(2)
                        .map(|value| String::from_utf8_lossy(value).into_owned())
                        .unwrap_or_default();
                    let body = params
                        .get(3..)
                        .unwrap_or(&[])
                        .iter()
                        .map(|part| String::from_utf8_lossy(part))
                        .collect::<Vec<_>>()
                        .join(";");
                    self.status_events.push((
                        "desktop_notification".into(),
                        json!({ "title": title, "body": body }),
                    ));
                }
            }
            b"10" | b"11" | b"12" => {
                if let Some(spec) = params.get(1) {
                    let which = code.to_vec();
                    let spec = spec.to_vec();
                    self.dynamic_color(&which, &spec, bell_terminated);
                }
            }
            b"4" => {
                // Pairs of index;spec. A spec of "?" asks for the color
                // currently in force at that index.
                let mut i = 1;
                while let (Some(index_raw), Some(spec)) = (params.get(i), params.get(i + 1)) {
                    let index = std::str::from_utf8(index_raw)
                        .ok()
                        .and_then(|text| text.parse::<usize>().ok())
                        .filter(|index| *index < 256);
                    if let Some(index) = index {
                        if *spec == b"?" {
                            let color = self
                                .theme
                                .palette
                                .get(&(index as u8))
                                .copied()
                                .unwrap_or_else(|| xterm_color(index));
                            let reply = osc_color_reply(&format!("4;{index};"), color, bell_terminated);
                            self.responses.extend_from_slice(&reply);
                        } else if let Some(color) = parse_osc_color(spec) {
                            self.theme.palette.insert(index as u8, color);
                        }
                    }
                    i += 2;
                }
            }
            b"104" => {
                match params
                    .get(1)
                    .and_then(|raw| std::str::from_utf8(raw).ok())
                    .and_then(|text| text.parse::<u8>().ok())
                {
                    Some(index) => {
                        self.theme.palette.remove(&index);
                    }
                    None => self.theme.palette.clear(),
                }
            }
            b"110" => self.theme.foreground = None,
            b"111" => self.theme.background = None,
            b"112" => self.theme.cursor = None,
            b"7501" => {
                if let Some(body) = params.get(1) {
                    if *body == b"?" {
                        self.responses.extend_from_slice(
                            b"\x1b]7501;?:states=idle,working,done,blocked,error:kinds=permission,question,auth\x1b\\",
                        );
                    } else if let Ok(body) = std::str::from_utf8(body) {
                        self.report_program_status(body);
                    }
                }
            }
            b"133" => {
                if params.get(1).is_some_and(|value| *value == b"A") {
                    self.clear_transient_program_status("prompt");
                }
            }
            _ => {}
        }
    }
}

fn valid_program_status_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    let segments: Vec<&str> = id.split('/').collect();
    !segments.is_empty()
        && segments.len() <= 8
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= 32
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
        })
}

fn decode_status_text(encoded: &str, max_decoded_bytes: usize) -> Option<String> {
    if encoded.len() > max_decoded_bytes.saturating_mul(4) / 3 + 8 {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    if decoded.len() > max_decoded_bytes {
        return None;
    }
    let text = String::from_utf8(decoded).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(text)
}

fn blank_line(cols: usize) -> Line {
    Line {
        cells: vec![Cell::blank(Pen::default()); cols],
        wrapped: false,
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_u32(out, value.len().min(u32::MAX as usize) as u32);
    out.extend_from_slice(&value.as_bytes()[..value.len().min(u32::MAX as usize)]);
}

fn put_snapshot_record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
    let mut checksum_input = Vec::with_capacity(6 + payload.len());
    checksum_input.extend_from_slice(&tag.to_le_bytes());
    checksum_input.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    checksum_input.extend_from_slice(payload);
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32c(&checksum_input).to_le_bytes());
    out.extend_from_slice(payload);
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f63b78 & mask);
        }
    }
    !crc
}

fn put_dynamic_rgb(out: &mut Vec<u8>, color: Option<(u8, u8, u8)>) {
    if let Some((r, g, b)) = color {
        out.extend_from_slice(&[1, r, g, b, 0, 0, 0, 0]);
    } else {
        out.extend_from_slice(&[0; 8]);
    }
}

fn put_snapshot_color(out: &mut Vec<u8>, color: Color) {
    match color {
        Color::Default => out.extend_from_slice(&[0, 0, 0, 0]),
        Color::Palette(index) => out.extend_from_slice(&[1, index, 0, 0]),
        Color::Rgb(r, g, b) => out.extend_from_slice(&[2, r, g, b]),
    }
}

fn put_ghostty_style(out: &mut Vec<u8>, pen: Pen) {
    put_snapshot_color(out, pen.fg);
    put_snapshot_color(out, pen.bg);
    put_snapshot_color(out, Color::Default); // Underline color.
    let mut flags = 0u16;
    flags |= u16::from(pen.bold) << 0;
    flags |= u16::from(pen.italic) << 1;
    flags |= u16::from(pen.dim) << 2;
    flags |= u16::from(pen.blink) << 3;
    flags |= u16::from(pen.inverse) << 4;
    flags |= u16::from(pen.hidden) << 5;
    flags |= u16::from(pen.strike) << 6;
    flags |= u16::from(pen.underline) << 8;
    put_u16(out, flags);
    put_u16(out, 0); // Reserved.
}

fn apc_message(nonce: u64, payload: &Value) -> Vec<u8> {
    let json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
    format!("\x1b_rex1;{nonce};{json}\x1b\\").into_bytes()
}

/// Parse an X11 color specification as used by OSC 4/10/11/12:
/// `rgb:R/G/B` with 1-4 hex digits per component, or `#RGB`,
/// `#RRGGBB`, `#RRRGGGBBB`, `#RRRRGGGGBBBB`.
fn parse_osc_color(spec: &[u8]) -> Option<(u8, u8, u8)> {
    let spec = std::str::from_utf8(spec).ok()?.trim();
    fn scale(value: u32, digits: usize) -> u8 {
        let max = (1u32 << (4 * digits)) - 1;
        (value * 255 / max) as u8
    }
    if let Some(hex) = spec.strip_prefix('#') {
        if hex.is_empty() || hex.len() > 12 || hex.len() % 3 != 0 {
            return None;
        }
        let n = hex.len() / 3;
        let part = |i: usize| u32::from_str_radix(&hex[i * n..(i + 1) * n], 16).ok().map(|v| scale(v, n));
        return Some((part(0)?, part(1)?, part(2)?));
    }
    let rest = spec.strip_prefix("rgb:")?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 {
        return None;
    }
    let part = |text: &str| -> Option<u8> {
        if text.is_empty() || text.len() > 4 {
            return None;
        }
        u32::from_str_radix(text, 16).ok().map(|v| scale(v, text.len()))
    };
    Some((part(parts[0])?, part(parts[1])?, part(parts[2])?))
}

/// Build an OSC color report: `OSC <prefix>rgb:RRRR/GGGG/BBBB` with
/// 16-bit components, terminated the way the query was terminated.
fn osc_color_reply(prefix: &str, (r, g, b): (u8, u8, u8), bell_terminated: bool) -> Vec<u8> {
    let mut out = format!(
        "\x1b]{prefix}rgb:{:04x}/{:04x}/{:04x}",
        r as u32 * 0x101,
        g as u32 * 0x101,
        b as u32 * 0x101
    )
    .into_bytes();
    if bell_terminated {
        out.push(0x07);
    } else {
        out.extend_from_slice(b"\x1b\\");
    }
    out
}

/// Convert an HLS color (hue degrees, lightness %, saturation %) to
/// RGB bytes, for sixel color definitions that use `;1;` coordinates.
fn hls_to_rgb(h: f64, l: f64, s: f64) -> (u8, u8, u8) {
    let h = (h % 360.0) / 60.0;
    let l = l / 100.0;
    let s = s / 100.0;
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h % 2.0) - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = match h {
        v if v < 1.0 => (c, x, 0.0),
        v if v < 2.0 => (x, c, 0.0),
        v if v < 3.0 => (0.0, c, x),
        v if v < 4.0 => (0.0, x, c),
        v if v < 5.0 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    (
        ((r + m) * 255.0).round() as u8,
        ((g + m) * 255.0).round() as u8,
        ((b + m) * 255.0).round() as u8,
    )
}

/// Decode a sixel payload into (width, height, RGBA). Colors defined
/// with `;2;` are RGB percentages, `;1;` is HLS; a register the program
/// never defined keeps the default palette color of the same index.
/// Unpainted pixels are transparent unless the image asked for an
/// opaque background.
fn decode_sixel(data: &[u8], opaque: bool) -> Option<(u32, u32, Vec<u8>)> {
    fn numbers(data: &[u8], start: usize) -> (Vec<u32>, usize) {
        let mut values = Vec::new();
        let mut i = start;
        let mut current: Option<u32> = None;
        while i < data.len() {
            match data[i] {
                b'0'..=b'9' => {
                    current = Some(current.unwrap_or(0) * 10 + (data[i] - b'0') as u32);
                    i += 1;
                }
                b';' => {
                    values.push(current.take().unwrap_or(0));
                    i += 1;
                }
                _ => break,
            }
        }
        if let Some(value) = current {
            values.push(value);
        }
        (values, i)
    }

    let mut colors: std::collections::HashMap<u32, (u8, u8, u8)> =
        std::collections::HashMap::new();
    let mut current_color: u32 = 0;
    let mut painted: std::collections::HashMap<(u32, u32), (u8, u8, u8)> =
        std::collections::HashMap::new();
    let (mut hint_w, mut hint_h) = (0u32, 0u32);
    let (mut x, mut band) = (0u32, 0u32);
    let mut max_x = 0u32;
    let mut max_y = 0u32;
    let mut i = 0usize;
    while i < data.len() {
        match data[i] {
            b'"' => {
                let (values, next) = numbers(data, i + 1);
                if values.len() >= 4 {
                    hint_w = values[2];
                    hint_h = values[3];
                }
                i = next;
            }
            b'#' => {
                let (values, next) = numbers(data, i + 1);
                if let Some(register) = values.first() {
                    current_color = *register;
                    if values.len() >= 5 {
                        let color = match values[1] {
                            1 => hls_to_rgb(
                                values[2] as f64,
                                values[3] as f64,
                                values[4] as f64,
                            ),
                            _ => (
                                (values[2].min(100) * 255 / 100) as u8,
                                (values[3].min(100) * 255 / 100) as u8,
                                (values[4].min(100) * 255 / 100) as u8,
                            ),
                        };
                        colors.insert(*register, color);
                    }
                }
                i = next;
            }
            b'!' => {
                let (values, next) = numbers(data, i + 1);
                let repeat = values.first().copied().unwrap_or(1).max(1);
                if next < data.len() && (0x3f..=0x7e).contains(&data[next]) {
                    let bits = data[next] - 0x3f;
                    let color = colors
                        .get(&current_color)
                        .copied()
                        .unwrap_or_else(|| {
                            let (r, g, b) = xterm_color(current_color as usize % 256);
                            (r, g, b)
                        });
                    for _ in 0..repeat {
                        for bit in 0..6u32 {
                            if bits & (1 << bit) != 0 {
                                painted.insert((x, band + bit), color);
                                max_y = max_y.max(band + bit + 1);
                            }
                        }
                        x += 1;
                    }
                    max_x = max_x.max(x);
                    i = next + 1;
                } else {
                    i = next;
                }
            }
            b'$' => {
                x = 0;
                i += 1;
            }
            b'-' => {
                x = 0;
                band += 6;
                i += 1;
            }
            byte @ 0x3f..=0x7e => {
                let bits = byte - 0x3f;
                let color = colors
                    .get(&current_color)
                    .copied()
                    .unwrap_or_else(|| {
                        let (r, g, b) = xterm_color(current_color as usize % 256);
                        (r, g, b)
                    });
                for bit in 0..6u32 {
                    if bits & (1 << bit) != 0 {
                        painted.insert((x, band + bit), color);
                        max_y = max_y.max(band + bit + 1);
                    }
                }
                x += 1;
                max_x = max_x.max(x);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    let width = hint_w.max(max_x);
    let height = hint_h.max(max_y);
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return None;
    }
    let background: [u8; 4] = if opaque { [0, 0, 0, 255] } else { [0, 0, 0, 0] };
    let mut rgba = vec![0u8; width as usize * height as usize * 4];
    for (index, pixel) in rgba.chunks_exact_mut(4).enumerate() {
        let px = index as u32 % width;
        let py = index as u32 / width;
        match painted.get(&(px, py)) {
            Some((r, g, b)) => pixel.copy_from_slice(&[*r, *g, *b, 255]),
            None => pixel.copy_from_slice(&background),
        }
    }
    Some((width, height, rgba))
}

fn kitty_key<'a>(control: &'a [(String, String)], key: &str) -> Option<&'a str> {
    control
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn xterm_color(index: usize) -> (u8, u8, u8) {
    const BASIC: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (205, 0, 0),
        (0, 205, 0),
        (205, 205, 0),
        (0, 0, 238),
        (205, 0, 205),
        (0, 205, 205),
        (229, 229, 229),
        (127, 127, 127),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (92, 92, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ];
    if index < BASIC.len() {
        return BASIC[index];
    }
    if index < 232 {
        const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
        let value = index - 16;
        return (
            LEVELS[value / 36],
            LEVELS[(value / 6) % 6],
            LEVELS[value % 6],
        );
    }
    let gray = (8 + (index - 232) * 10) as u8;
    (gray, gray, gray)
}

fn resize_grid(
    lines: &mut Vec<Line>,
    cols: usize,
    rows: usize,
    cursor_row: &mut usize,
    scroll_top: &mut usize,
    scroll_bottom: &mut usize,
    mut scrollback: Option<&mut VecDeque<Line>>,
) {
    for line in lines.iter_mut() {
        line.cells.resize(cols, Cell::blank(Pen::default()));
    }
    while lines.len() > rows {
        if *cursor_row >= rows {
            let line = lines.remove(0);
            if let Some(scrollback) = scrollback.as_deref_mut() {
                scrollback.push_back(line);
                while scrollback.len() > SCROLLBACK_LIMIT {
                    scrollback.pop_front();
                }
            }
            *cursor_row -= 1;
        } else {
            lines.pop();
        }
    }
    while lines.len() < rows {
        // Growing the viewport pulls the most recent scrollback lines back
        // into the active area (what xterm/Ghostty do), instead of padding
        // the bottom with blanks and leaving the content stranded at the
        // top of a half-empty screen. Only the primary screen passes a
        // scrollback; the cursor follows its content down.
        let pulled = match scrollback.as_deref_mut() {
            Some(scrollback) => scrollback.pop_back(),
            None => None,
        };
        match pulled {
            Some(mut line) => {
                line.cells.resize(cols, Cell::blank(Pen::default()));
                lines.insert(0, line);
                *cursor_row += 1;
            }
            None => lines.push(blank_line(cols)),
        }
    }
    *cursor_row = (*cursor_row).min(rows - 1);
    *scroll_top = 0;
    *scroll_bottom = rows - 1;
}

fn param(params: &Params, index: usize, default: usize) -> usize {
    params
        .iter()
        .nth(index)
        .and_then(|p| p.first().copied())
        .map(|v| v as usize)
        .filter(|v| *v != 0)
        .unwrap_or(default)
}

fn line_text(line: &Line, trim: bool) -> String {
    let mut text: String = line
        .cells
        .iter()
        .filter(|c| !c.cont)
        .map(|c| c.ch)
        .collect();
    if trim {
        text.truncate(text.trim_end().len());
    }
    text
}

fn sgr(pen: Pen) -> String {
    let mut codes: Vec<String> = vec!["0".into()];
    if pen.bold {
        codes.push("1".into());
    }
    if pen.dim {
        codes.push("2".into());
    }
    if pen.italic {
        codes.push("3".into());
    }
    if pen.underline {
        codes.push("4".into());
    }
    if pen.blink {
        codes.push("5".into());
    }
    if pen.inverse {
        codes.push("7".into());
    }
    if pen.hidden {
        codes.push("8".into());
    }
    if pen.strike {
        codes.push("9".into());
    }
    match pen.fg {
        Color::Default => {}
        Color::Palette(n) if n < 8 => codes.push((30 + n).to_string()),
        Color::Palette(n) if n < 16 => codes.push((90 + n - 8).to_string()),
        Color::Palette(n) => codes.push(format!("38;5;{n}")),
        Color::Rgb(r, g, b) => codes.push(format!("38;2;{r};{g};{b}")),
    }
    match pen.bg {
        Color::Default => {}
        Color::Palette(n) if n < 8 => codes.push((40 + n).to_string()),
        Color::Palette(n) if n < 16 => codes.push((100 + n - 8).to_string()),
        Color::Palette(n) => codes.push(format!("48;5;{n}")),
        Color::Rgb(r, g, b) => codes.push(format!("48;2;{r};{g};{b}")),
    }
    format!("\x1b[{}m", codes.join(";"))
}

fn html_span(pen: Pen, text: &str, theme: &Theme) -> String {
    let style = html_style(pen, theme);
    let escaped = escape_html(text);
    if style.is_empty() {
        escaped
    } else {
        format!("<span style=\"{style}\">{escaped}</span>")
    }
}

fn html_style(pen: Pen, theme: &Theme) -> String {
    let mut style = String::new();
    if pen.bold {
        style.push_str("font-weight: bold;");
    }
    if pen.dim {
        style.push_str("opacity: 0.5;");
    }
    if pen.italic {
        style.push_str("font-style: italic;");
    }
    if pen.underline {
        style.push_str("text-decoration: underline;");
    }
    if pen.strike {
        style.push_str("text-decoration: line-through;");
    }
    if pen.blink {
        style.push_str("text-decoration: blink;");
    }
    if pen.inverse {
        style.push_str("filter: invert(100%);");
    }
    if pen.hidden {
        style.push_str("visibility: hidden;");
    }
    match color_css(pen.fg, theme, true) {
        Some(color) => style.push_str(&format!("color: {color};")),
        None => {}
    }
    match color_css(pen.bg, theme, false) {
        Some(color) => style.push_str(&format!("background-color: {color};")),
        None => {}
    }
    style
}

fn color_css(color: Color, theme: &Theme, foreground: bool) -> Option<String> {
    match color {
        Color::Default => (if foreground {
            theme.foreground
        } else {
            theme.background
        })
        .map(rgb_css),
        Color::Palette(index) => theme
            .palette
            .get(&index)
            .copied()
            .map(rgb_css)
            .or_else(|| Some(format!("var(--vt-palette-{index})"))),
        Color::Rgb(r, g, b) => Some(rgb_css((r, g, b))),
    }
}

fn rgb_css((r, g, b): (u8, u8, u8)) -> String {
    format!("rgb({r}, {g}, {b})")
}

fn osc_color((r, g, b): (u8, u8, u8)) -> String {
    format!("rgb:{r:02x}/{g:02x}/{b:02x}")
}

fn parse_theme_color(options: &Value, field: &str) -> Result<Option<(u8, u8, u8)>, String> {
    match options.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => parse_hex_color(value)
            .map(Some)
            .ok_or_else(|| format!("{field} must be RRGGBB or #RRGGBB")),
        Some(_) => Err(format!("{field} must be a string")),
    }
}

fn parse_hex_color(value: &str) -> Option<(u8, u8, u8)> {
    let value = value.strip_prefix('#').unwrap_or(value);
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((
        u8::from_str_radix(&value[0..2], 16).ok()?,
        u8::from_str_radix(&value[2..4], 16).ok()?,
        u8::from_str_radix(&value[4..6], 16).ok()?,
    ))
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn file_url_from_osc7(uri: &str) -> Option<String> {
    if let Some(rest) = uri.strip_prefix("file://") {
        let (host, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let host = if host.is_empty() {
            local_hostname()
        } else {
            host.to_string()
        };
        return Some(format!("file://{host}{}", percent_decode(path)));
    }
    if uri.starts_with('/') {
        return Some(format!(
            "file://{}{}",
            local_hostname(),
            percent_decode(uri)
        ));
    }
    None
}

fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push(high * 16 + low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    fn snapshot_records(bytes: &[u8]) -> Vec<(u16, &[u8])> {
        assert_eq!(&bytes[..8], b"GHOSTSNP");
        let mut offset = 10;
        let mut out = Vec::new();
        while offset + 10 <= bytes.len() {
            let tag = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
            let len =
                u32::from_le_bytes(bytes[offset + 2..offset + 6].try_into().unwrap()) as usize;
            out.push((tag, &bytes[offset + 10..offset + 10 + len]));
            offset += 10 + len;
            if tag == 6 {
                break;
            }
        }
        out
    }

    /// Decode the row texts of a PAGE payload whose rows all use the
    /// default pen (so the style table is empty).
    fn snapshot_page_texts(page: &[u8]) -> Vec<String> {
        let rows = u16::from_le_bytes(page[2..4].try_into().unwrap()) as usize;
        let styles = u16::from_le_bytes(page[4..6].try_into().unwrap()) as usize;
        assert_eq!(styles, 0, "test pages use the default pen only");
        let mut offset = 20;
        let mut texts = Vec::new();
        for _ in 0..rows {
            if page[offset..offset + 3] == [0, 0, 0] {
                texts.push(String::new());
                offset += 3;
                continue;
            }
            let count =
                u16::from_le_bytes(page[offset + 1..offset + 3].try_into().unwrap()) as usize;
            offset += 3;
            let mut text = String::new();
            for _ in 0..count {
                let word = u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let codepoint = ((word >> 2) & 0x00ff_ffff) as u32;
                if codepoint != 0 {
                    text.push(char::from_u32(codepoint).unwrap_or('\u{fffd}'));
                }
            }
            texts.push(text);
        }
        texts
    }

    #[test]
    #[test]
    fn scrollback_pack_round_trips_through_a_snapshot() {
        let mut screen = Screen::new(40, 5);
        // Styled, wide, and plain lines, enough to fill scrollback
        // past the pack threshold.
        for i in 0..80 {
            screen.feed(
                format!("\x1b[1;38;5;{}mline {} \x1b[0m\u{4e16}\u{754c} tail {}\r\n", 30 + i % 200, i, i)
                    .as_bytes(),
            );
        }
        screen.feed(b"final");
        let before = screen.ghostty_snapshot();
        let text_before = screen.format_text(true, false);
        assert!(screen.scrollback_len() >= SCROLLBACK_PACK_MIN_LINES);
        let packed = screen.suspend_scrollback().expect("scrollback packs");
        assert!(screen.scrollback_packed());
        assert!(
            packed < 4096,
            "packed scrollback should be tiny next to the live grid, got {packed}"
        );
        // Access restores transparently and byte-identically.
        let after = screen.ghostty_snapshot();
        assert_eq!(before, after);
        assert!(!screen.scrollback_packed());
        assert_eq!(text_before, screen.format_text(true, false));
        // A corrupt blob restores as empty rather than failing.
        let mut empty = Screen::new(20, 3);
        let restored = unpack_scrollback(&[9, 9, 9, 9]);
        assert!(restored.is_empty());
        assert_eq!(empty.scrollback_len(), 0);
        empty.feed(b"still alive\r\n");
        assert_eq!(empty.format_text(true, false), "still alive");
    }

    #[test]
    fn snapshot_carries_scrollback_history() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"AAA\r\nBBB\r\nCCC\r\nDDD\r\nEEE");
        assert_eq!(screen.scrollback.len(), 2);
        let snapshot = screen.ghostty_snapshot();
        let records = snapshot_records(&snapshot);
        let tags: Vec<u16> = records.iter().map(|(tag, _)| *tag).collect();
        assert_eq!(tags, [1, 2, 3, 7, 5, 4, 3, 6]);
        // SCREEN declares the logical history extent (rows).
        let screen_rec = records[1].1;
        let history_rows =
            u64::from_le_bytes(screen_rec[4..12].try_into().unwrap());
        assert_eq!(history_rows, 2);
        // HISTORY header: primary key, one page follows.
        let history = records[5].1;
        assert_eq!(
            u16::from_le_bytes(history[0..2].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(history[2..6].try_into().unwrap()),
            1
        );
        // The history page holds the scrolled-off rows, oldest first.
        assert_eq!(snapshot_page_texts(records[6].1), ["AAA", "BBB"]);
        // The active page still holds the visible rows.
        assert_eq!(snapshot_page_texts(records[2].1), ["CCC", "DDD", "EEE"]);
    }

    #[test]
    fn snapshot_history_pages_newest_first() {
        let mut screen = Screen::new(10, 2);
        let mut input = String::new();
        for i in 0..2500 {
            if i > 0 {
                input.push_str("\r\n");
            }
            input.push_str(&format!("L{i:04}"));
        }
        screen.feed(input.as_bytes());
        assert_eq!(screen.scrollback.len(), 2498);
        let snapshot = screen.ghostty_snapshot();
        let records = snapshot_records(&snapshot);
        let history = records.iter().find(|(tag, _)| *tag == 4).unwrap().1;
        assert_eq!(
            u32::from_le_bytes(history[2..6].try_into().unwrap()),
            3,
            "2498 rows chunk into three pages"
        );
        let pages: Vec<&[u8]> = records
            .iter()
            .skip_while(|(tag, _)| *tag != 4)
            .skip(1)
            .take(3)
            .map(|(_, payload)| *payload)
            .collect();
        // Newest page first: it starts at the 1498th scrolled-off line.
        assert_eq!(snapshot_page_texts(pages[0])[0], "L1498");
        // Oldest page last: it ends at the 498th scrolled-off line.
        let oldest = snapshot_page_texts(pages[2]);
        assert_eq!(oldest.len(), 498);
        assert_eq!(oldest[497], "L0497");
    }

    #[test]
    fn snapshot_alt_screen_has_no_history() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"AAA\r\nBBB\r\nCCC\r\nDDD");
        assert_eq!(screen.scrollback.len(), 1);
        screen.feed(b"\x1b[?1049h");
        let snapshot = screen.ghostty_snapshot();
        let records = snapshot_records(&snapshot);
        let tags: Vec<u16> = records.iter().map(|(tag, _)| *tag).collect();
        assert_eq!(tags, [1, 2, 3, 7, 5, 4, 6]);
        let screen_rec = records[1].1;
        assert_eq!(
            u64::from_le_bytes(screen_rec[4..12].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn mouse_modes_track_and_reset() {
        let mut screen = Screen::new(80, 24);
        assert_eq!(screen.mouse_tracking(), MouseTracking::Off);
        screen.feed(b"\x1b[?1000h");
        assert_eq!(screen.mouse_tracking(), MouseTracking::Normal);
        screen.feed(b"\x1b[?1002h\x1b[?1006h");
        assert_eq!(screen.mouse_tracking(), MouseTracking::Button);
        assert_eq!(screen.mouse_format(), MouseFormat::Sgr);
        screen.feed(b"\x1b[?1003h");
        assert_eq!(screen.mouse_tracking(), MouseTracking::Any);
        screen.feed(b"\x1b[?1003l");
        assert_eq!(screen.mouse_tracking(), MouseTracking::Button);
        screen.feed(b"\x1b[?1006l\x1b[?1015h");
        assert_eq!(screen.mouse_format(), MouseFormat::Urxvt);
        assert!(screen.active_modes().contains(&"mouse_button"));
        assert!(screen.active_modes().contains(&"mouse_urxvt"));
        screen.soft_reset();
        assert_eq!(screen.mouse_tracking(), MouseTracking::Off);
        assert_eq!(screen.mouse_format(), MouseFormat::X10);
    }

    #[test]
    fn mouse_report_encoding() {
        // SGR wheel down at cell (10, 5).
        assert_eq!(
            encode_mouse_report(MouseFormat::Sgr, 65, 10, 5, false, false),
            b"\x1b[<65;10;5M"
        );
        // SGR left-button release uses the m terminator.
        assert_eq!(
            encode_mouse_report(MouseFormat::Sgr, 0, 3, 2, true, false),
            b"\x1b[<0;3;2m"
        );
        // SGR motion adds 32 to the button.
        assert_eq!(
            encode_mouse_report(MouseFormat::Sgr, 0, 3, 2, false, true),
            b"\x1b[<32;3;2M"
        );
        // X10 press is ESC [ M followed by button+32, x+32, y+32.
        assert_eq!(
            encode_mouse_report(MouseFormat::X10, 0, 10, 5, false, false),
            b"\x1b[M\x20\x2a\x25"
        );
        // X10 release reports button 3.
        assert_eq!(
            encode_mouse_report(MouseFormat::X10, 0, 10, 5, true, false),
            b"\x1b[M\x23\x2a\x25"
        );
        // urxvt is decimal: ESC [ button+32 ; x ; y M.
        assert_eq!(
            encode_mouse_report(MouseFormat::Urxvt, 64, 7, 9, false, false),
            b"\x1b[96;7;9M"
        );
    }

    use super::*;

    #[test]
    fn osc_title_changes_emit_client_events_only_on_change() {
        let mut screen = Screen::new(20, 2);
        screen.feed(b"\x1b]0;Build task\x07");
        screen.feed(b"\x1b]2;Build task\x07");
        let events = screen.take_status_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "title_changed");
        assert_eq!(events[0].1, json!({ "title": "Build task" }));
    }

    #[test]
    fn renders_plain_text() {
        let mut screen = Screen::new(20, 4);
        screen.feed(b"hello\r\nworld");
        assert_eq!(screen.format_text(true, false), "hello\nworld");
    }

    #[test]
    fn handles_cursor_positioning_and_erase() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"abc\x1b[2J\x1b[Hxyz");
        assert_eq!(screen.format_text(true, false), "xyz");
    }

    #[test]
    fn tracks_styles_and_wide_characters() {
        let mut screen = Screen::new(10, 2);
        screen.feed("\x1b[31mred\x1b[0m \u{4e16}\u{754c}".as_bytes());
        let vt = screen.format_vt();
        assert!(vt.contains("\x1b[0;31m"), "vt was {vt:?}");
        assert!(vt.contains('\u{4e16}'));
        assert!(vt.contains('\u{754c}'));
    }

    #[test]
    fn scrolls_into_scrollback() {
        let mut screen = Screen::new(10, 2);
        screen.feed(b"one\r\ntwo\r\nthree");
        assert_eq!(screen.format_text(true, false), "one\ntwo\nthree");
    }

    #[test]
    fn alternate_screen_round_trips() {
        let mut screen = Screen::new(10, 2);
        screen.feed(b"primary");
        screen.feed(b"\x1b[?1049h");
        screen.feed(b"alt");
        assert_eq!(screen.format_text(true, false), "alt");
        screen.feed(b"\x1b[?1049l");
        assert_eq!(screen.format_text(true, false), "primary");
    }

    #[test]
    fn resize_grow_pulls_scrollback_back() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"1\r\n2\r\n3\r\n4\r\n5");
        assert_eq!(screen.scrollback.len(), 2);
        screen.resize(10, 5);
        assert_eq!(screen.scrollback.len(), 0);
        assert_eq!(screen.format_text(true, false), "1\n2\n3\n4\n5");
        screen.resize(10, 3);
        assert_eq!(screen.scrollback.len(), 2);
        assert_eq!(screen.format_text(true, false), "1\n2\n3\n4\n5");
    }

    #[test]
    fn resize_keeps_content() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"abc\r\ndef");
        screen.resize(5, 3);
        assert_eq!(screen.format_text(true, false), "abc\ndef");
        screen.resize(10, 4);
        assert_eq!(screen.format_text(true, false), "abc\ndef");
    }

    #[test]
    fn trims_trailing_spaces() {
        let mut screen = Screen::new(4, 2);
        screen.feed(b"a   \r\nb");
        assert_eq!(screen.format_text(false, false), "a   \nb   ");
        assert_eq!(screen.format_text(true, false), "a\nb");
    }

    #[test]
    fn program_status_records_parse_inherit_and_clear() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]7501;state=working:app=deploy:msg=RGVwbG95aW5n\x1b\\");
        screen.feed(b"\x1b]7501;state=blocked:id=eu-west:kind=permission:progress=40:title=RVUgV2VzdA==:msg=QXBwcm92ZQ==\x1b\\");
        let records = screen.program_status_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["state"], "working");
        assert_eq!(records[0]["app"], "deploy");
        assert_eq!(records[1]["id"], "eu-west");
        assert_eq!(records[1]["kind"], "permission");
        assert_eq!(records[1]["progress"], 40);
        assert_eq!(records[1]["title"], "EU West");
        assert_eq!(records[1]["msg"], "Approve");
        assert_eq!(records[1]["effective_app"], "deploy");

        screen.feed(b"\x1b]7501;state=clear:id=eu-west\x1b\\");
        assert_eq!(screen.program_status_records().len(), 1);
        let events = screen.take_status_events();
        assert!(events.iter().any(|(name, payload)| {
            name == "program_status_removed"
                && payload["ids"] == json!(["eu-west"])
                && payload["reason"] == "clear"
        }));
    }

    #[test]
    fn program_status_rejects_invalid_text_and_clears_transient_on_prompt() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]7501;state=working:app=claude:msg=V29ya2luZw==\x1b\\");
        screen.feed(b"\x1b]7501;state=done:app=claude:msg=SGVsbG8K\x1b\\");
        assert_eq!(screen.program_status_records().len(), 1);
        screen.feed(b"\x1b]133;A\x1b\\");
        assert!(screen.program_status_records().is_empty());
        assert!(screen.take_status_events().iter().any(|(name, payload)| {
            name == "program_status_removed" && payload["reason"] == "prompt"
        }));
    }

    #[test]
    fn program_status_feature_query_returns_supported_values() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]7501;?\x1b\\");
        assert_eq!(
            screen.take_responses(),
            b"\x1b]7501;?:states=idle,working,done,blocked,error:kinds=permission,question,auth\x1b\\"
        );
    }

    #[test]
    fn osc52_stores_text_and_emits_clipboard_event() {
        let mut screen = Screen::new(80, 24);
        let text = "A".repeat(50_000);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&text);
        let sequence = format!("\x1b]52;c;{encoded}\x07");
        screen.feed(sequence.as_bytes());
        let events = screen.take_status_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "clipboard_written");
        assert_eq!(events[0].1["bytes"], text.len());
        let id = events[0].1["id"].as_u64().unwrap();
        assert_eq!(screen.clipboard_copy(id).unwrap().1, text);
    }

    #[test]
    #[test]
    fn osc52_small_copy_carries_text_id_and_bytes_and_is_readable() {
        let mut screen = Screen::new(80, 24);
        let encoded = base64::engine::general_purpose::STANDARD.encode("hello");
        let sequence = format!("\x1b]52;c;{encoded}\x07");
        screen.feed(sequence.as_bytes());
        let events = screen.take_status_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1["text"], "hello");
        assert_eq!(events[0].1["bytes"], 5);
        let id = events[0].1["id"].as_u64().unwrap();
        assert_eq!(screen.clipboard_copy(id).unwrap().1, "hello");
        assert_eq!(screen.clipboard_copy(0).unwrap().1, "hello");
    }

    #[test]
    fn osc52_rapid_copies_coalesce_to_the_newest() {
        let mut screen = Screen::new(80, 24);
        for text in ["one", "two", "three"] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(text);
            screen.feed(format!("\x1b]52;c;{encoded}\x07").as_bytes());
        }
        let events = screen.take_status_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1["text"], "three");
    }

    #[test]
    fn secondary_da_and_xtversion_are_answered() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b[>c");
        assert_eq!(screen.take_responses(), b"\x1b[>41;1;0c");
        screen.feed(b"\x1b[>0q");
        let reply = screen.take_responses();
        assert!(reply.starts_with(b"\x1bP>|rux "), "{reply:?}");
        assert!(reply.ends_with(b"\x1b\\"), "{reply:?}");
    }

    #[test]
    fn decrqm_reports_tracked_mode_state() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b[?25$p");
        assert_eq!(screen.take_responses(), b"\x1b[?25;1$y");
        screen.feed(b"\x1b[?25l");
        screen.feed(b"\x1b[?25$p");
        assert_eq!(screen.take_responses(), b"\x1b[?25;2$y");
        screen.feed(b"\x1b[?9999$p");
        assert_eq!(screen.take_responses(), b"\x1b[?9999;0$y");
        screen.feed(b"\x1b[4$p");
        assert_eq!(screen.take_responses(), b"\x1b[4;2$y");
        screen.feed(b"\x1b[?2026h");
        screen.feed(b"\x1b[?2026$p");
        assert_eq!(screen.take_responses(), b"\x1b[?2026;1$y");
    }

    #[test]
    fn window_reports_and_title_stack() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b[11t");
        assert_eq!(screen.take_responses(), b"\x1b[1t");
        screen.feed(b"\x1b[19t");
        assert_eq!(screen.take_responses(), b"\x1b[9;24;80t");
        screen.feed(b"\x1b]2;one\x07");
        screen.feed(b"\x1b[22t");
        screen.feed(b"\x1b]2;two\x07");
        assert_eq!(screen.title(), "two");
        screen.feed(b"\x1b[23t");
        assert_eq!(screen.title(), "one");
    }

    #[test]
    fn kitty_keyboard_stack_negotiates_and_answers_queries() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b[?u");
        assert_eq!(screen.take_responses(), b"\x1b[?0u");
        screen.feed(b"\x1b[>15u");
        screen.feed(b"\x1b[?u");
        assert_eq!(screen.take_responses(), b"\x1b[?15u");
        screen.feed(b"\x1b[=8;2u");
        screen.feed(b"\x1b[?u");
        assert_eq!(screen.take_responses(), b"\x1b[?7u");
        screen.feed(b"\x1b[<u");
        screen.feed(b"\x1b[?u");
        assert_eq!(screen.take_responses(), b"\x1b[?0u");
    }

    #[test]
    fn osc52_query_replies_with_the_newest_copy() {
        let mut screen = Screen::new(80, 24);
        let encoded = base64::engine::general_purpose::STANDARD.encode("hi");
        screen.feed(format!("\x1b]52;c;{encoded}\x07").as_bytes());
        screen.take_status_events();
        screen.feed(b"\x1b]52;c;?\x07");
        assert_eq!(screen.take_responses(), b"\x1b]52;c;aGk=\x07");
    }

    #[test]
    fn dynamic_color_queries_answer_once_a_color_is_set() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]11;?\x1b\\");
        assert!(screen.take_responses().is_empty());
        screen.feed(b"\x1b]11;rgb:12/34/56\x1b\\");
        screen.feed(b"\x1b]11;?\x1b\\");
        assert_eq!(screen.take_responses(), b"\x1b]11;rgb:1212/3434/5656\x1b\\");
        screen.feed(b"\x1b]10;#00ff00\x07");
        screen.feed(b"\x1b]10;?\x07");
        assert_eq!(screen.take_responses(), b"\x1b]10;rgb:0000/ffff/0000\x07");
    }

    #[test]
    fn osc4_palette_query_and_set() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]4;1;?\x07");
        assert_eq!(screen.take_responses(), b"\x1b]4;1;rgb:cdcd/0000/0000\x07");
        screen.feed(b"\x1b]4;1;#00ff00\x07");
        screen.feed(b"\x1b]4;1;?\x07");
        assert_eq!(screen.take_responses(), b"\x1b]4;1;rgb:0000/ffff/0000\x07");
    }

    fn desktop_notifications_and_osc94_progress_are_forwarded() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]9;Build finished\x07");
        screen.feed(b"\x1b]777;notify;Title;Body\x1b\\");
        screen.feed(b"\x1b]9;4;1;75\x07");
        let events = screen.take_status_events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].0, "desktop_notification");
        assert_eq!(events[0].1["body"], "Build finished");
        assert_eq!(events[1].1["title"], "Title");
        assert_eq!(events[1].1["body"], "Body");
        assert_eq!(events[2].0, "progress_report");
        assert_eq!(events[2].1, json!({ "state": "set", "progress": 75 }));
        assert_eq!(events[3].0, "program_status_changed");
        assert_eq!(events[3].1["record"]["state"], "working");
        assert_eq!(events[3].1["record"]["progress"], 75);
    }

    #[test]
    fn osc7_emits_a_file_url_and_bell_is_an_event() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]7;file://build.example/tmp/my%20work\x1b\\");
        screen.feed(b"\x07");
        let events = screen.take_status_events();
        assert_eq!(events[0].0, "pwd_changed");
        assert_eq!(events[0].1["pwd"], "file://build.example/tmp/my work");
        assert_eq!(screen.pwd(), "file://build.example/tmp/my work");
        assert_eq!(events[1].0, "bell");
        assert_eq!(events[1].1, json!({}));

        screen.feed(b"\x1b]7;/var/log\x1b\\");
        let pwd = screen.pwd().to_string();
        assert!(pwd.starts_with("file://"), "{pwd}");
        assert!(pwd.ends_with("/var/log"), "{pwd}");
    }

    #[test]
    fn osc94_stops_mapping_after_a_real_program_status_report() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]7501;state=blocked:kind=question:id=ask\x1b\\");
        screen.take_status_events();
        screen.feed(b"\x1b]9;4;1;10\x07");
        let events = screen.take_status_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "progress_report");
        assert_eq!(screen.program_status_records().len(), 1);
        assert_eq!(screen.program_status_records()[0]["state"], "blocked");
    }

    #[test]
    fn overlong_program_status_sequences_are_dropped() {
        let mut screen = Screen::new(80, 24);
        let body = "x".repeat(4088);
        let sequence = format!("\x1b]7501;{body}\x1b\\");
        screen.feed(sequence.as_bytes());
        assert!(screen.program_status_records().is_empty());
        assert!(screen.take_status_events().is_empty());
    }

    #[test]
    fn decstr_resets_modes_without_clearing_program_status_or_text() {
        let mut screen = Screen::new(80, 24);
        screen.feed(b"\x1b]7501;state=working:id=job\x1b\\");
        screen.feed(b"hello");
        screen.feed(b"\x1b[?1h");
        assert!(screen.application_cursor());
        screen.feed(b"\x1b[!p");
        assert!(!screen.application_cursor());
        assert_eq!(screen.program_status_records().len(), 1);
        assert!(screen.format_text(true, false).contains("hello"));
        assert_eq!(screen.title(), "");
    }

    #[test]
    fn terminal_theme_changes_html_defaults_and_vt_redraw() {
        let mut screen = Screen::new(10, 1);
        screen.feed(b"text");
        screen
            .set_theme(&json!({
                "foreground": "#010203",
                "background": "040506",
                "cursor": "#aabbcc",
                "palette": ["1=#112233"],
                "scheme": "dark",
            }))
            .unwrap();
        let html = screen.format_html(true, false);
        assert!(html.contains("color: rgb(1, 2, 3)"), "{html}");
        assert!(html.contains("background-color: rgb(4, 5, 6)"), "{html}");
        assert!(html.contains("color-scheme: dark"), "{html}");
        let vt = screen.format_vt();
        assert!(vt.starts_with("\x1b]10;rgb:01/02/03\x1b\\"), "{vt:?}");
        assert!(vt.contains("\x1b]4;1;rgb:11/22/33\x1b\\"), "{vt:?}");
        assert!(
            screen
                .set_theme(&json!({ "foreground": "not-hex" }))
                .is_err()
        );
    }

    #[test]
    fn unwraps_wrapped_lines() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"abcdefghijk");
        assert_eq!(screen.format_text(false, false), "abcdefghij\nk         ");
        assert_eq!(screen.format_text(false, true), "abcdefghijk");
    }

    fn kitty_payload(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }

    #[test]
    fn kitty_transmit_and_display_stores_places_and_replies() {
        let mut screen = Screen::new(10, 3);
        let pixels: [u8; 8] = [255, 0, 0, 255, 0, 255, 0, 255];
        screen.feed(
            format!("\x1b_Ga=T,i=7,f=32,s=2,v=1;{}\x1b\\", kitty_payload(&pixels))
                .as_bytes(),
        );
        let image = screen.images.get(&7).expect("image stored");
        assert_eq!((image.width, image.height), (2, 1));
        assert_eq!(image.rgba, pixels);
        assert_eq!(screen.placements.len(), 1);
        assert_eq!(
            (screen.placements[0].row, screen.placements[0].col),
            (0, 0)
        );
        assert_eq!(screen.cursor.row, 1);
        assert_eq!(screen.take_responses(), b"\x1b_Gi=7;OK\x1b\\".to_vec());
        let replay = screen.format_vt();
        assert!(replay.contains("a=t,f=32,s=2,v=1,i=7"), "{replay:?}");
        assert!(replay.contains("a=p,i=7"), "{replay:?}");
    }

    #[test]
    fn kitty_query_replies_without_storing() {
        let mut screen = Screen::new(10, 3);
        screen.feed(
            format!(
                "\x1b_Ga=q,i=9,f=32,s=1,v=1;{}\x1b\\",
                kitty_payload(&[1, 2, 3, 4])
            )
            .as_bytes(),
        );
        assert!(screen.images.is_empty());
        assert!(screen.placements.is_empty());
        assert_eq!(screen.take_responses(), b"\x1b_Gi=9;OK\x1b\\".to_vec());
    }

    #[test]
    fn kitty_chunked_transmission_assembles() {
        let mut screen = Screen::new(10, 3);
        let payload = kitty_payload(&[9, 8, 7, 6]);
        let (first, rest) = payload.split_at(4);
        screen.feed(format!("\x1b_Ga=t,i=5,f=32,s=1,v=1,m=1;{first}\x1b\\").as_bytes());
        assert!(screen.images.is_empty());
        screen.feed(format!("\x1b_Gm=0;{rest}\x1b\\").as_bytes());
        assert!(screen.images.contains_key(&5));
        assert_eq!(screen.take_responses(), b"\x1b_Gi=5;OK\x1b\\".to_vec());
    }

    #[test]
    fn kitty_delete_by_image_removes_placement_and_data() {
        let mut screen = Screen::new(10, 3);
        screen.feed(
            format!(
                "\x1b_Ga=T,i=7,f=32,s=1,v=1;{}\x1b\\",
                kitty_payload(&[0, 0, 0, 255])
            )
            .as_bytes(),
        );
        assert_eq!(screen.placements.len(), 1);
        screen.feed(b"\x1b_Ga=d,d=I,i=7\x1b\\");
        assert!(screen.placements.is_empty());
        assert!(screen.images.is_empty());
    }

    #[test]
    fn kitty_unsupported_format_replies_einval() {
        let mut screen = Screen::new(10, 3);
        screen.feed(
            format!("\x1b_Ga=T,i=3,f=99;{}\x1b\\", kitty_payload(&[0, 0, 0, 0])).as_bytes(),
        );
        let responses = String::from_utf8(screen.take_responses()).unwrap();
        assert!(responses.contains("i=3;EINVAL"), "{responses:?}");
        assert!(screen.images.is_empty());
    }

    #[test]
    fn sixel_image_is_decoded_and_placed() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"\x1bP0;0;0q\"1;1;1;6#0;2;100;0;0#0~\x1b\\");
        assert_eq!(screen.images.len(), 1);
        let image = screen.images.values().next().unwrap();
        assert_eq!((image.width, image.height), (1, 6));
        assert_eq!(&image.rgba[0..4], &[255, 0, 0, 255]);
        assert_eq!(&image.rgba[20..24], &[255, 0, 0, 255]);
        assert_eq!(screen.placements.len(), 1);
        assert!(screen.placements[0].sixel.is_some());
        assert_eq!(screen.cursor.row, 1);
        assert!(screen.format_vt().contains("\x1bP0;0;0q"));
    }

    #[test]
    fn decrqss_and_xtgettcap_replies() {
        let mut screen = Screen::new(10, 3);
        screen.feed(b"\x1bP$qr\x1b\\");
        assert_eq!(
            screen.take_responses(),
            b"\x1bP1$r1;3r\x1b\\".to_vec()
        );
        screen.feed(b"\x1bP+q544E\x1b\\");
        assert_eq!(
            screen.take_responses(),
            b"\x1bP1+r544E=787465726D2D323536636F6C6F72\x1b\\".to_vec()
        );
        screen.feed(b"\x1b[c");
        assert_eq!(screen.take_responses(), b"\x1b[?62;4;22c".to_vec());
    }
}
